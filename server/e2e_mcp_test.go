// e2e_mcp_test.go exercises funcbox's MCP surface end to end: the OAuth
// 2.1 authorization server (server/internal/oauth) issuing an MCP-scoped
// access token through a real DCR -> authorize/consent -> token round
// trip, and the Streamable HTTP /mcp endpoint (server/internal/mcpserver)
// itself -- role-filtered tools/list, the users tool group actually
// mutating state through the exact same use case the REST API uses, the
// RFC 9728 401 challenge, access-token audience scoping, and the
// organization's mcp_enabled gate. All against real sqlite + filesystem
// blob backends, exactly like e2e_test.go's own suite (newTestEnvWithVisibility,
// extended in that file to also wire oauth.Handler/mcpserver.Handler).
package funcbox_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// mcpPKCEPair returns a random PKCE verifier and its S256 challenge, for
// driving server/internal/oauth's /oauth/authorize + /oauth/token over
// real HTTP -- deliberately duplicated from that package's own
// oauth_test.go (an internal test file this external package can't
// import), mirroring e2e_test.go's own cliPKCEPair for the analogous CLI
// login flow.
func mcpPKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// registerMCPClient drives POST /oauth/register (RFC 7591 DCR) and
// returns the issued client_id.
func registerMCPClient(t *testing.T, env *testEnv, redirectURI string) string {
	t.Helper()
	body := fmt.Sprintf(`{"client_name":"e2e mcp client","redirect_uris":[%q]}`, redirectURI)
	resp, err := http.Post(env.baseURL+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /oauth/register status = %d, body = %s", resp.StatusCode, raw)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode /oauth/register response: %v (body: %s)", err, raw)
	}
	if out.ClientID == "" {
		t.Fatalf("/oauth/register did not return a client_id (body: %s)", raw)
	}
	return out.ClientID
}

// extractConsentStateToken extracts the consent page's hidden
// "state_token" field value -- the same marker+substring technique
// server/internal/oauth/authorize_test.go's extractFieldValue uses,
// duplicated here for the same "internal test file, can't import" reason
// as mcpPKCEPair above.
func extractConsentStateToken(t *testing.T, body string) string {
	t.Helper()
	marker := `name="state_token" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("state_token field not found in consent page body:\n%s", body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("malformed state_token field in consent page body:\n%s", body)
	}
	return rest[:end]
}

// mintMCPAccessToken drives the FULL OAuth 2.1 round trip a real MCP
// client goes through: DCR, the consent page's Approve decision (using
// client, an already browser-session-authenticated *http.Client -- see
// env.loginViaHTTP), and the PKCE code+verifier token exchange --
// returning the minted access_token (aud="mcp") and refresh_token.
func mintMCPAccessToken(t *testing.T, env *testEnv, client *http.Client) (accessToken, refreshToken, clientID string) {
	t.Helper()
	const redirectURI = "http://127.0.0.1:54123/callback"
	clientID = registerMCPClient(t, env, redirectURI)
	verifier, challenge := mcpPKCEPair(t)

	authorizeURL := env.baseURL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"e2e-state"},
	}.Encode()
	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth/authorize status = %d, body = %s", resp.StatusCode, body)
	}
	stateToken := extractConsentStateToken(t, string(body))

	approveResp, err := client.PostForm(env.baseURL+"/oauth/authorize", url.Values{"state_token": {stateToken}})
	if err != nil {
		t.Fatalf("POST /oauth/authorize (approve): %v", err)
	}
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusFound {
		t.Fatalf("POST /oauth/authorize (approve) status = %d, want 302", approveResp.StatusCode)
	}
	loc, err := url.Parse(approveResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse consent approval Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("consent approval redirect carried no code: %s", approveResp.Header.Get("Location"))
	}

	tokenResp, err := http.PostForm(env.baseURL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
	})
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	defer tokenResp.Body.Close()
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/token status = %d, body = %s", tokenResp.StatusCode, tokenBody)
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(tokenBody, &out); err != nil {
		t.Fatalf("decode /oauth/token response: %v (body: %s)", err, tokenBody)
	}
	if out.TokenType != "Bearer" || !strings.HasPrefix(out.AccessToken, "fbxa_") || out.RefreshToken == "" {
		t.Fatalf("/oauth/token response = %+v, want a Bearer fbxa_... access token and a refresh token", out)
	}
	return out.AccessToken, out.RefreshToken, clientID
}

// bearerRoundTripper attaches "Authorization: Bearer <token>" to every
// request -- how mcpConnect authenticates the go-sdk's Streamable HTTP
// client transport, which has no built-in notion of funcbox's own
// fbxa_ access tokens.
type bearerRoundTripper struct {
	token string
}

func (rt *bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+rt.token)
	return http.DefaultTransport.RoundTrip(req)
}

// mcpConnect connects a fresh MCP client to env's /mcp endpoint using
// token as the bearer credential, performing the protocol's "initialize"
// handshake. The caller must Close() the returned session.
func mcpConnect(t *testing.T, env *testEnv, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "funcbox-e2e-test-client", Version: "0.0.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   env.baseURL + "/mcp",
		HTTPClient: &http.Client{Transport: &bearerRoundTripper{token: token}},
	}
	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("mcp client Connect: %v", err)
	}
	return session
}

// toolNames extracts every tool's Name from a ListToolsResult, for a
// simple membership check against the expected users tool group.
func toolNames(res *mcp.ListToolsResult) []string {
	names := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// toolResultText concatenates every TextContent block in res.Content --
// where a ToolHandlerFor's returned Go error ends up (see tools_users.go's
// toolError doc comment: a plain error is packed into an IsError
// CallToolResult, not a protocol-level error), used below to assert on a
// refused tool call's message.
func toolResultText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// callTool calls name on session with args, failing the test on any
// protocol-level error or IsError result, and returns the structured
// JSON-object result every functions/workspaces/org/audit/devices tool in
// this package returns.
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if res.IsError {
		t.Fatalf("CallTool(%s) IsError = true: %s", name, toolResultText(res))
	}
	structured, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("CallTool(%s) StructuredContent = %#v, want a JSON object", name, res.StructuredContent)
	}
	return structured
}

// callToolExpectIsError calls name on session with args, failing the test
// if the call does NOT come back as an IsError result (a protocol-level
// error, e.g. "unknown tool" for an unregistered name, also fails the
// test -- callers expecting THAT specific refusal shape check err
// themselves instead), and returns the error message text.
func callToolExpectIsError(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): unexpected protocol-level error: %v", name, err)
	}
	if !res.IsError {
		t.Fatalf("CallTool(%s) unexpectedly succeeded: %+v", name, res.StructuredContent)
	}
	return toolResultText(res)
}

// promoteToAdmin loads the user with email by store lookup and sets their
// role to admin, mirroring every other MCP e2e test's own promotion
// shortcut (see TestE2E_MCPUsersToolsFullFlow's doc comment: there is no
// "invite as admin" API, so tests promote directly against the store).
func promoteToAdmin(t *testing.T, env *testEnv, email string) *store.User {
	t.Helper()
	u, err := env.store.Users().ByEmail(context.Background(), email)
	if err != nil {
		t.Fatalf("Users().ByEmail(%s): %v", email, err)
	}
	u.Role = store.RoleAdmin
	if err := env.store.Users().Update(context.Background(), u); err != nil {
		t.Fatalf("Users().Update(%s, promote to admin): %v", email, err)
	}
	return u
}

// TestE2E_MCPUsersToolsFullFlow drives the complete MCP happy path: DCR ->
// authorize (dev login + consent approve) -> PKCE token exchange -> MCP
// "initialize" over Streamable HTTP with the minted Bearer token ->
// tools/list shows the full users tool group for an admin actor -> calling
// approve_user through MCP actually flips a pending user to active and
// writes the audit entry -- the exact same effect PATCH
// /api/v1/org/users/{id} has, because both go through api.Handler.PatchUser.
// Two subtests reuse this env: a plain member's tools/list must NOT
// include any users tool, and a non-admin calling one directly (bypassing
// tools/list) must be refused with no state change.
func TestE2E_MCPUsersToolsFullFlow(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")

	// A pending user for approve_user to act on, created directly against
	// the store (mirroring TestE2E_ApprovalModeFullFlow's own shortcut) --
	// this test is about the MCP tool's effect, not about driving the
	// pending-signup flow itself.
	ctx := context.Background()
	pending := &store.User{
		Provider: store.ProviderGoogle, ProviderSubject: "sub-mcp-pending",
		Email: "mcp-pending@example.com", Name: "MCP Pending", Role: store.RoleMember, Status: store.UserStatusPending,
	}
	if err := env.store.Users().Create(ctx, pending); err != nil {
		t.Fatalf("Users().Create(pending): %v", err)
	}

	// mcp-admin@example.com is this org's SECOND-ever login (bootstrap()
	// already created admin@example.com directly against the store as the
	// first, in newTestEnvWithVisibility) -- BootstrapFirstUser only
	// promotes the very first user, so this one lands as an ordinary
	// member. Log in once (establishing the browser session
	// mintMCPAccessToken's consent step needs), then promote directly
	// against the store -- mirroring how every other e2e test grants a
	// non-bootstrap user admin rights (there is no "invite as admin" API).
	// Role is re-read from the store on every request (loadActiveUser), so
	// the ALREADY-established session picks up the promotion immediately,
	// with no need to log in again.
	client := env.loginViaHTTP(t, "mcp-admin@example.com")
	adminUser, err := env.store.Users().ByEmail(ctx, "mcp-admin@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(mcp-admin): %v", err)
	}
	adminUser.Role = store.RoleAdmin
	if err := env.store.Users().Update(ctx, adminUser); err != nil {
		t.Fatalf("Users().Update(mcp-admin, promote to admin): %v", err)
	}

	accessToken, _, _ := mintMCPAccessToken(t, env, client)

	session := mcpConnect(t, env, accessToken)
	defer session.Close()

	listResult, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := toolNames(listResult)
	for _, want := range []string{
		"list_users", "approve_user", "reject_user", "set_user_role", "set_user_status",
		"get_org_settings", "update_org_settings", "list_login_rules", "replace_login_rules",
		"list_audit_logs",
	} {
		if !containsString(names, want) {
			t.Errorf("admin tools/list = %v, missing %q", names, want)
		}
	}

	callResult, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "approve_user",
		Arguments: map[string]any{"user_id": pending.ID},
	})
	if err != nil {
		t.Fatalf("CallTool(approve_user): %v", err)
	}
	if callResult.IsError {
		t.Fatalf("CallTool(approve_user) IsError = true, content = %+v", callResult.Content)
	}
	structured, ok := callResult.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("approve_user StructuredContent = %#v, want a JSON object", callResult.StructuredContent)
	}
	if structured["status"] != "active" {
		t.Errorf("approve_user result status = %v, want %q", structured["status"], "active")
	}
	if structured["id"] != pending.ID {
		t.Errorf("approve_user result id = %v, want %q", structured["id"], pending.ID)
	}

	reloaded, err := env.store.Users().ByID(ctx, pending.ID)
	if err != nil {
		t.Fatalf("Users().ByID(pending) after approve_user: %v", err)
	}
	if reloaded.Status != store.UserStatusActive {
		t.Fatalf("pending user's stored status after MCP approve_user = %q, want %q", reloaded.Status, store.UserStatusActive)
	}

	// The MCP tool call goes through the exact same api.Handler.PatchUser
	// use case PATCH /api/v1/org/users/{id} does, so it must write the
	// identical org.user.update audit entry (§ REST parity requirement).
	logs, err := env.store.Audit().List(ctx, "", 5)
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	found := false
	for _, l := range logs {
		if l.Action != "org.user.update" || l.Target != "user:"+pending.ID {
			continue
		}
		var detail map[string]any
		if err := json.Unmarshal(l.Detail, &detail); err != nil {
			t.Fatalf("decode audit detail: %v", err)
		}
		if detail["approval_action"] == "approved" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no org.user.update audit entry with approval_action=approved for user %s found in %+v", pending.ID, logs)
	}

	t.Run("member's tools/list excludes the users/org/audit tool groups but includes functions/workspaces/devices", func(t *testing.T) {
		memberToken := env.tokenForOwner(t, "mcp-member") // aud-less, general-purpose -- also valid at /mcp
		memberSession := mcpConnect(t, env, memberToken)
		defer memberSession.Close()

		res, err := memberSession.ListTools(context.Background(), &mcp.ListToolsParams{})
		if err != nil {
			t.Fatalf("ListTools (member): %v", err)
		}
		names := toolNames(res)
		for _, adminOnly := range []string{
			"list_users", "approve_user", "reject_user", "set_user_role", "set_user_status",
			"get_org_settings", "update_org_settings", "list_login_rules", "replace_login_rules",
			"list_audit_logs",
		} {
			if containsString(names, adminOnly) {
				t.Errorf("member tools/list = %v, must NOT include admin-only tool %q", names, adminOnly)
			}
		}
		// functions/workspaces/devices are per-resource authorized (not
		// role-gated at registration), so every authenticated actor --
		// admin or not -- sees them in tools/list.
		for _, everyone := range []string{
			"list_functions", "get_function", "deploy_function", "get_function_files",
			"invoke_function", "get_function_logs", "rollback_function", "delete_function",
			"list_workspaces", "get_workspace", "add_workspace_member", "remove_workspace_member", "set_workspace_member_role",
			"list_connected_devices", "revoke_device",
		} {
			if !containsString(names, everyone) {
				t.Errorf("member tools/list = %v, missing %q (registered for every authenticated actor)", names, everyone)
			}
		}
	})

	t.Run("non-admin calling an admin tool directly is refused with no state change", func(t *testing.T) {
		memberToken := env.tokenForOwner(t, "mcp-member2")
		memberSession := mcpConnect(t, env, memberToken)
		defer memberSession.Close()

		target, err := env.store.Users().ByEmail(ctx, "mcp-admin@example.com")
		if err != nil {
			t.Fatalf("Users().ByEmail(mcp-admin): %v", err)
		}
		beforeRole := target.Role

		_, err = memberSession.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "set_user_role",
			Arguments: map[string]any{"user_id": target.ID, "role": "member"},
		})
		if err == nil {
			t.Fatalf("CallTool(set_user_role) by a non-admin unexpectedly succeeded")
		}
		if !strings.Contains(err.Error(), "unknown tool") {
			t.Errorf("CallTool(set_user_role) by a non-admin error = %q, want it to mention \"unknown tool\" (the tool was never registered for this session)", err.Error())
		}

		after, err := env.store.Users().ByID(ctx, target.ID)
		if err != nil {
			t.Fatalf("Users().ByID(target) after refused call: %v", err)
		}
		if after.Role != beforeRole {
			t.Fatalf("target's role changed from %q to %q despite the refused non-admin tool call -- state must NOT change", beforeRole, after.Role)
		}
	})
}

// TestE2E_MCPUnauthorized covers the 401 shape every unauthenticated or
// invalid /mcp request must get: RFC 9728 §5.1's exact
// `WWW-Authenticate: Bearer resource_metadata="..."` header, pointing at
// this deployment's own protected-resource metadata document, which is
// how an MCP client auto-discovers the OAuth flow.
func TestE2E_MCPUnauthorized(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	wantHeader := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, env.baseURL)

	t.Run("no Authorization header", func(t *testing.T) {
		resp, err := http.Get(env.baseURL + "/mcp")
		if err != nil {
			t.Fatalf("GET /mcp: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != wantHeader {
			t.Errorf("WWW-Authenticate = %q, want %q", got, wantHeader)
		}
	})

	t.Run("garbage bearer token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/mcp", nil)
		req.Header.Set("Authorization", "Bearer fbxa_not-a-real-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /mcp: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != wantHeader {
			t.Errorf("WWW-Authenticate = %q, want %q", got, wantHeader)
		}
	})
}

// TestE2E_MCPAudienceScoping proves the aud claim's acceptance scoping
// (bd91d87/806003d + this step's own additions): an aud=mcp access token
// (minted the same way server/internal/oauth's /oauth/token does) works at
// /mcp but is REJECTED at /api/v1, while a general-purpose, aud-less token
// (the print-access-token/tokenForOwner shape) keeps working at BOTH --
// the regression coverage for "existing aud-less tokens keep working
// everywhere".
func TestE2E_MCPAudienceScoping(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	ctx := context.Background()

	u := &store.User{
		Provider: store.ProviderGoogle, ProviderSubject: "sub-aud-scope",
		Email: "aud-scope@example.com", Name: "Aud Scope", Role: store.RoleMember, Status: store.UserStatusActive,
	}
	if err := env.store.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	mcpToken, _, err := env.auth.IssueAccessTokenForAudience(ctx, u.ID, time.Hour, auth.AudienceMCP)
	if err != nil {
		t.Fatalf("IssueAccessTokenForAudience: %v", err)
	}

	t.Run("aud=mcp token works at /mcp", func(t *testing.T) {
		session := mcpConnect(t, env, mcpToken)
		defer session.Close()
		if _, err := session.ListTools(context.Background(), &mcp.ListToolsParams{}); err != nil {
			t.Fatalf("ListTools with an aud=mcp token: %v", err)
		}
	})

	t.Run("aud=mcp token rejected at /api/v1", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+mcpToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /api/v1/me: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("GET /api/v1/me with an aud=mcp token status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("aud-less token works at both /mcp and /api/v1", func(t *testing.T) {
		genericToken, _, err := env.auth.IssueAccessToken(ctx, u.ID, time.Hour)
		if err != nil {
			t.Fatalf("IssueAccessToken: %v", err)
		}

		session := mcpConnect(t, env, genericToken)
		defer session.Close()
		if _, err := session.ListTools(context.Background(), &mcp.ListToolsParams{}); err != nil {
			t.Fatalf("ListTools with an aud-less token: %v", err)
		}

		req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/api/v1/me", nil)
		req.Header.Set("Authorization", "Bearer "+genericToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /api/v1/me: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("GET /api/v1/me with an aud-less token status = %d, body = %s, want 200", resp.StatusCode, body)
		}
	})
}

// TestE2E_MCPGating covers the organization's mcp_enabled setting (default
// true, per settings.Org.McpEnabled): turning it off must 404 -- not 501,
// not a JSON error body -- /mcp and all four OAuth/metadata endpoints, and
// turning it back on must restore them, all resolved fresh per request
// (no stale caching across the toggle).
func TestE2E_MCPGating(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	adminToken := env.tokenForOwner(t, "admin-user")

	setMCPEnabled := func(t *testing.T, enabled bool) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org",
			strings.NewReader(fmt.Sprintf(`{"mcp_enabled":%v}`, enabled)))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PATCH /api/v1/org (mcp_enabled=%v): %v", enabled, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("PATCH /api/v1/org (mcp_enabled=%v) status = %d, body = %s", enabled, resp.StatusCode, body)
		}
	}

	gatedGET := func(t *testing.T, path string) int {
		t.Helper()
		resp, err := http.Get(env.baseURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	setMCPEnabled(t, false)
	for _, path := range []string{
		"/mcp",
		"/.well-known/oauth-authorization-server",
		"/.well-known/oauth-protected-resource",
		"/oauth/authorize",
	} {
		if got := gatedGET(t, path); got != http.StatusNotFound {
			t.Errorf("GET %s with mcp_enabled=false status = %d, want 404", path, got)
		}
	}
	// /oauth/register only accepts POST, but the gate must still 404 it
	// before the method even matters.
	regResp, err := http.Post(env.baseURL+"/oauth/register", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /oauth/register: %v", err)
	}
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /oauth/register with mcp_enabled=false status = %d, want 404", regResp.StatusCode)
	}

	setMCPEnabled(t, true)
	// /mcp, unauthenticated, now reaches the real handler again -> 401 (not
	// 404): the clearest proof the gate itself, not just the route dispatch,
	// re-opened.
	if got := gatedGET(t, "/mcp"); got != http.StatusUnauthorized {
		t.Errorf("GET /mcp with mcp_enabled=true (restored) status = %d, want 401 (unauthenticated, but no longer gated)", got)
	}
	if got := gatedGET(t, "/.well-known/oauth-protected-resource"); got != http.StatusOK {
		t.Errorf("GET /.well-known/oauth-protected-resource with mcp_enabled=true status = %d, want 200", got)
	}
	if got := gatedGET(t, "/.well-known/oauth-authorization-server"); got != http.StatusOK {
		t.Errorf("GET /.well-known/oauth-authorization-server with mcp_enabled=true status = %d, want 200", got)
	}
	// /oauth/authorize with no query params reaches the real handler and
	// fails validation (missing client_id) -> 400, proving it's no longer
	// gated (a still-gated route would be 404 here instead).
	if got := gatedGET(t, "/oauth/authorize"); got != http.StatusBadRequest {
		t.Errorf("GET /oauth/authorize (no params) with mcp_enabled=true status = %d, want 400", got)
	}
}

// deployFile builds one deploy_function "files" entry (utf8, the default
// encoding).
func deployFile(path, content string) map[string]any {
	return map[string]any{"path": path, "content": content}
}

// deployFileBase64 builds one deploy_function "files" entry carrying
// binary content, base64-encoded.
func deployFileBase64(path string, data []byte) map[string]any {
	return map[string]any{"path": path, "content": base64.StdEncoding.EncodeToString(data), "encoding": "base64"}
}

// TestE2E_MCPFunctionsDeployInvokeEditLoop drives the AI-agent loop
// deploy_function → invoke_function → deploy_function itself is the
// centerpiece; §16.4.1). It deploys a small multi-file fetch-handler
// (utf8 source + one base64 binary asset), invokes it, checks the
// invocation shows up in get_function_logs, round-trips the exact
// uploaded bytes back through get_function_files (both listing and
// single-file mode, and both the active and an older version_id),
// redeploys modified source, invokes again to see the new behavior, rolls
// back, invokes again to see the old behavior restored, then deletes the
// function and confirms it's gone.
func TestE2E_MCPFunctionsDeployInvokeEditLoop(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	const owner = "mcp-loop-owner"
	token := env.tokenForOwner(t, owner)
	session := mcpConnect(t, env, token)
	defer session.Close()

	binaryAsset := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0xff, 0xfe}
	msgV1 := "export const MSG = \"hello-v1\";\n"
	indexJS := "import { MSG } from \"./lib/msg.js\";\nexport default { async fetch(req) { return new Response(MSG); } };\n"

	deployOut := callTool(t, session, "deploy_function", map[string]any{
		"owner": owner,
		"note":  "initial version",
		"files": []any{
			deployFile("funcbox.yaml", "name: mcp-loop-app\nvisibility: org\n"),
			deployFile("lib/msg.js", msgV1),
			deployFile("index.js", indexJS),
			deployFileBase64("assets/logo.png", binaryAsset),
		},
	})
	if deployOut["dry_run"] != false {
		t.Fatalf("deploy_function dry_run = %v, want false", deployOut["dry_run"])
	}
	v1ID, _ := deployOut["version_id"].(string)
	if v1ID == "" {
		t.Fatalf("deploy_function did not return a version_id: %v", deployOut)
	}

	invokeOut := callTool(t, session, "invoke_function", map[string]any{"owner": owner, "name": "mcp-loop-app"})
	if status, _ := invokeOut["status"].(float64); status != http.StatusOK {
		t.Fatalf("invoke_function status = %v, want 200 (out=%v)", invokeOut["status"], invokeOut)
	}
	if body, _ := invokeOut["body"].(string); body != "hello-v1" {
		t.Fatalf("invoke_function body = %q, want %q", body, "hello-v1")
	}

	logsOut := callTool(t, session, "get_function_logs", map[string]any{"owner": owner, "name": "mcp-loop-app"})
	logs, _ := logsOut["logs"].([]any)
	if len(logs) == 0 {
		t.Fatalf("get_function_logs returned no entries after invoke_function")
	}
	if first, ok := logs[0].(map[string]any); !ok || first["status"].(float64) != http.StatusOK {
		t.Errorf("get_function_logs[0] = %v, want status 200", logs[0])
	}

	// get_function_files: listing mode round-trips every uploaded file
	// exactly, including the base64 binary asset.
	filesOut := callTool(t, session, "get_function_files", map[string]any{"owner": owner, "name": "mcp-loop-app"})
	filesList, _ := filesOut["files"].([]any)
	contentByPath := map[string]string{}
	encodingByPath := map[string]string{}
	for _, f := range filesList {
		fm, ok := f.(map[string]any)
		if !ok {
			t.Fatalf("get_function_files entry = %#v, want an object", f)
		}
		contentByPath[fm["path"].(string)] = fmt.Sprint(fm["content"])
		encodingByPath[fm["path"].(string)] = fmt.Sprint(fm["encoding"])
	}
	if contentByPath["lib/msg.js"] != msgV1 {
		t.Errorf("get_function_files lib/msg.js content = %q, want %q", contentByPath["lib/msg.js"], msgV1)
	}
	if encodingByPath["assets/logo.png"] != "base64" {
		t.Errorf("get_function_files assets/logo.png encoding = %q, want base64", encodingByPath["assets/logo.png"])
	}
	decodedAsset, err := base64.StdEncoding.DecodeString(contentByPath["assets/logo.png"])
	if err != nil || !bytes.Equal(decodedAsset, binaryAsset) {
		t.Errorf("get_function_files assets/logo.png round-trip mismatch (err=%v): got %x, want %x", err, decodedAsset, binaryAsset)
	}

	// get_function_files: single-file mode returns exactly one entry.
	singleOut := callTool(t, session, "get_function_files", map[string]any{"owner": owner, "name": "mcp-loop-app", "file": "index.js"})
	singleFiles, _ := singleOut["files"].([]any)
	if len(singleFiles) != 1 {
		t.Fatalf("get_function_files single-file mode returned %d entries, want 1: %v", len(singleFiles), singleFiles)
	}
	if sf, ok := singleFiles[0].(map[string]any); !ok || sf["content"] != indexJS {
		t.Errorf("get_function_files single-file mode content = %v, want %q", singleFiles[0], indexJS)
	}

	// Redeploy with modified source, under a new note.
	msgV2 := "export const MSG = \"hello-v2\";\n"
	deployOut2 := callTool(t, session, "deploy_function", map[string]any{
		"owner": owner,
		"name":  "mcp-loop-app",
		"note":  "v2: change the message",
		"files": []any{
			deployFile("funcbox.yaml", "name: mcp-loop-app\nvisibility: org\n"),
			deployFile("lib/msg.js", msgV2),
			deployFile("index.js", indexJS),
		},
	})
	v2ID, _ := deployOut2["version_id"].(string)
	if v2ID == "" || v2ID == v1ID {
		t.Fatalf("second deploy_function version_id = %q, want a new id distinct from %q", v2ID, v1ID)
	}

	invokeOut2 := callTool(t, session, "invoke_function", map[string]any{"owner": owner, "name": "mcp-loop-app"})
	if body, _ := invokeOut2["body"].(string); body != "hello-v2" {
		t.Fatalf("invoke_function (after v2 deploy) body = %q, want %q", body, "hello-v2")
	}

	// get_function_files with an explicit OLDER version_id still returns
	// that version's content, distinct from the now-active v2.
	oldFilesOut := callTool(t, session, "get_function_files", map[string]any{"owner": owner, "name": "mcp-loop-app", "version_id": v1ID})
	oldFiles, _ := oldFilesOut["files"].([]any)
	foundOldMsg := false
	for _, f := range oldFiles {
		fm, _ := f.(map[string]any)
		if fm["path"] == "lib/msg.js" && fm["content"] == msgV1 {
			foundOldMsg = true
		}
	}
	if !foundOldMsg {
		t.Errorf("get_function_files(version_id=%s) did not return v1's lib/msg.js content: %v", v1ID, oldFiles)
	}

	// Roll back to v1, and see the old behavior restored.
	callTool(t, session, "rollback_function", map[string]any{"owner": owner, "name": "mcp-loop-app", "version_id": v1ID})
	invokeOut3 := callTool(t, session, "invoke_function", map[string]any{"owner": owner, "name": "mcp-loop-app"})
	if body, _ := invokeOut3["body"].(string); body != "hello-v1" {
		t.Fatalf("invoke_function (after rollback_function) body = %q, want %q", body, "hello-v1")
	}

	// Delete, and see the function is gone.
	delOut := callTool(t, session, "delete_function", map[string]any{"owner": owner, "name": "mcp-loop-app"})
	if delOut["deleted"] != true {
		t.Fatalf("delete_function.deleted = %v, want true", delOut["deleted"])
	}
	invokeOut4 := callTool(t, session, "invoke_function", map[string]any{"owner": owner, "name": "mcp-loop-app"})
	if status, _ := invokeOut4["status"].(float64); status != http.StatusNotFound {
		t.Fatalf("invoke_function (after delete_function) status = %v, want 404", invokeOut4["status"])
	}
}

// TestE2E_MCPDeployFunctionValidation covers deploy_function's edge cases:
// dry_run never persists, invalid base64 is rejected cleanly, deploy
// authorization denies a non-owning actor, and the existing
// max_functions_per_user limit is enforced identically to a REST deploy
// (reusing TestE2E_FunctionLimitBlocksNewFunctionButNotUpdates' own setup
// shape).
func TestE2E_MCPDeployFunctionValidation(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")

	t.Run("dry_run does not persist", func(t *testing.T) {
		const owner = "mcp-dryrun-owner"
		token := env.tokenForOwner(t, owner)
		session := mcpConnect(t, env, token)
		defer session.Close()

		out := callTool(t, session, "deploy_function", map[string]any{
			"owner":   owner,
			"dry_run": true,
			"files": []any{
				deployFile("funcbox.yaml", "name: mcp-dryrun-app\n"),
				deployFile("index.js", `export default { fetch() { return new Response("ok"); } };`),
			},
		})
		if out["dry_run"] != true {
			t.Fatalf("deploy_function(dry_run) dry_run = %v, want true", out["dry_run"])
		}
		if out["version_id"] != nil && out["version_id"] != "" {
			t.Errorf("deploy_function(dry_run) version_id = %v, want empty/absent", out["version_id"])
		}

		getOut := callToolExpectIsError(t, session, "get_function", map[string]any{"owner": owner, "name": "mcp-dryrun-app"})
		if !strings.Contains(getOut, "not found") {
			t.Errorf("get_function after a dry run = %q, want a not-found error (nothing was persisted)", getOut)
		}
	})

	t.Run("invalid base64 content is rejected", func(t *testing.T) {
		const owner = "mcp-badb64-owner"
		token := env.tokenForOwner(t, owner)
		session := mcpConnect(t, env, token)
		defer session.Close()

		msg := callToolExpectIsError(t, session, "deploy_function", map[string]any{
			"owner": owner,
			"files": []any{
				deployFile("funcbox.yaml", "name: mcp-badb64-app\n"),
				deployFile("index.js", `export default { fetch() { return new Response("ok"); } };`),
				map[string]any{"path": "assets/x.bin", "content": "!!!not-valid-base64!!!", "encoding": "base64"},
			},
		})
		if !strings.Contains(msg, "base64") {
			t.Errorf("deploy_function with invalid base64 error = %q, want it to mention base64", msg)
		}
	})

	t.Run("deploy authorization denies a non-owning actor", func(t *testing.T) {
		env.tokenForOwner(t, "mcp-authz-victim") // provisions the target owner's public User ID
		attackerToken := env.tokenForOwner(t, "mcp-authz-attacker")
		session := mcpConnect(t, env, attackerToken)
		defer session.Close()

		msg := callToolExpectIsError(t, session, "deploy_function", map[string]any{
			"owner": "mcp-authz-victim",
			"files": []any{
				deployFile("funcbox.yaml", "name: mcp-authz-app\n"),
				deployFile("index.js", `export default { fetch() { return new Response("ok"); } };`),
			},
		})
		if !strings.Contains(msg, "permitted") {
			t.Errorf("deploy_function as a non-owning actor error = %q, want a permission refusal", msg)
		}
	})

	t.Run("function-count limit is enforced", func(t *testing.T) {
		const owner = "mcp-quota-owner"
		env.tokenForOwner(t, owner)

		adminToken := env.tokenForOwner(t, "mcp-quota-admin")
		promoteToAdmin(t, env, "mcp-quota-admin@example.com")
		patchReq, _ := http.NewRequest(http.MethodPatch, env.baseURL+"/api/v1/org", strings.NewReader(`{"max_functions_per_user":1}`))
		patchReq.Header.Set("Authorization", "Bearer "+adminToken)
		patchReq.Header.Set("Content-Type", "application/json")
		patchResp, err := http.DefaultClient.Do(patchReq)
		if err != nil {
			t.Fatalf("PATCH /api/v1/org: %v", err)
		}
		patchResp.Body.Close()
		if patchResp.StatusCode != http.StatusOK {
			t.Fatalf("PATCH /api/v1/org (max_functions_per_user) status = %d", patchResp.StatusCode)
		}

		token := env.tokenForOwner(t, owner)
		session := mcpConnect(t, env, token)
		defer session.Close()

		appFiles := func(name string) []any {
			return []any{
				deployFile("funcbox.yaml", "name: "+name+"\n"),
				deployFile("index.js", `export default { fetch() { return new Response("ok"); } };`),
			}
		}
		out := callTool(t, session, "deploy_function", map[string]any{"owner": owner, "files": appFiles("mcp-quota-app-0")})
		if out["dry_run"] != false || out["version_id"] == "" {
			t.Fatalf("first deploy_function (at the limit) = %v, want a persisted deploy", out)
		}

		msg := callToolExpectIsError(t, session, "deploy_function", map[string]any{"owner": owner, "files": appFiles("mcp-quota-app-1")})
		if !strings.Contains(msg, "limit") {
			t.Errorf("second (new) deploy_function over the limit error = %q, want it to mention the limit", msg)
		}
	})
}

// TestE2E_MCPInvokeFunctionAuthzAndCap covers invoke_function's non-happy
// paths: a visibility denial surfaces as a normal (non-error) tool result
// carrying the function's own 403 status -- not a tool-level error -- an
// oversized response body is truncated to the ~1MB cap with truncated=true,
// and every invocation (denied or not) still appends an execution log
// entry, exactly like a real HTTP invocation would.
func TestE2E_MCPInvokeFunctionAuthzAndCap(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")

	t.Run("visibility denial for another user's private function", func(t *testing.T) {
		const owner = "mcp-private-owner"
		ownerToken := env.tokenForOwner(t, owner)
		ownerSession := mcpConnect(t, env, ownerToken)
		defer ownerSession.Close()

		// visibility: workspace on a personal (user-owned) function narrows
		// it to the owner alone -- see internal/invoke's isWorkspaceMember
		// doc comment ("for a user-owned function, workspace visibility
		// narrows down to just the owner themselves").
		deployOut := callTool(t, ownerSession, "deploy_function", map[string]any{
			"owner": owner,
			"files": []any{
				deployFile("funcbox.yaml", "name: mcp-private-app\nvisibility: workspace\n"),
				deployFile("index.js", `export default { fetch() { return new Response("owner-only"); } };`),
			},
		})
		if deployOut["version_id"] == "" {
			t.Fatalf("deploy_function (private) did not persist: %v", deployOut)
		}

		strangerToken := env.tokenForOwner(t, "mcp-private-stranger")
		strangerSession := mcpConnect(t, env, strangerToken)
		defer strangerSession.Close()

		out := callTool(t, strangerSession, "invoke_function", map[string]any{"owner": owner, "name": "mcp-private-app"})
		status, _ := out["status"].(float64)
		if status != http.StatusUnauthorized && status != http.StatusForbidden {
			t.Fatalf("invoke_function (stranger, private function) status = %v, want 401 or 403 -- and NOT a tool-level error, out=%v", out["status"], out)
		}
		// A denied invocation never reaches the runtime, so it does NOT
		// append an execution log entry -- Invoker.Serve itself returns
		// right after authorize() fails, before ever calling
		// appendInvocationLog (see invoke.go's serveFunction). Confirmed by
		// the owner's OWN invocation below actually showing up.
		deniedLogsOut := callTool(t, ownerSession, "get_function_logs", map[string]any{"owner": owner, "name": "mcp-private-app"})
		if logs, _ := deniedLogsOut["logs"].([]any); len(logs) != 0 {
			t.Errorf("get_function_logs after only a DENIED invocation = %v, want empty", logs)
		}

		// The owner invoking their own private function succeeds and DOES
		// show up in get_function_logs -- the invocation MUST appear in
		// execution logs, per this tool's own design.
		ownerOut := callTool(t, ownerSession, "invoke_function", map[string]any{"owner": owner, "name": "mcp-private-app"})
		if ownerStatus, _ := ownerOut["status"].(float64); ownerStatus != http.StatusOK {
			t.Fatalf("invoke_function (owner, own private function) status = %v, want 200", ownerOut["status"])
		}
		logsOut := callTool(t, ownerSession, "get_function_logs", map[string]any{"owner": owner, "name": "mcp-private-app"})
		logs, _ := logsOut["logs"].([]any)
		if len(logs) == 0 {
			t.Errorf("get_function_logs shows no entry for the owner's successful invocation")
		}
	})

	t.Run("response body is capped and flagged truncated", func(t *testing.T) {
		const owner = "mcp-bigbody-owner"
		token := env.tokenForOwner(t, owner)
		session := mcpConnect(t, env, token)
		defer session.Close()

		deployOut := callTool(t, session, "deploy_function", map[string]any{
			"owner": owner,
			"files": []any{
				deployFile("funcbox.yaml", "name: mcp-bigbody-app\nvisibility: org\n"),
				deployFile("index.js", `export default { fetch() { return new Response("x".repeat(1300000)); } };`),
			},
		})
		if deployOut["version_id"] == "" {
			t.Fatalf("deploy_function (bigbody) did not persist: %v", deployOut)
		}

		out := callTool(t, session, "invoke_function", map[string]any{"owner": owner, "name": "mcp-bigbody-app"})
		if out["truncated"] != true {
			t.Fatalf("invoke_function (1.3MB body) truncated = %v, want true", out["truncated"])
		}
		// Content is plain ASCII ("x" repeated), so body_encoding is utf8 and
		// the returned string's byte length equals the RAW body length the
		// bounded response writer retained -- must be EXACTLY the cap, not
		// merely "under" it: this is the Finding-3 regression guard that the
		// writer itself (not a post-hoc slice of an unboundedly-buffered
		// response) is what enforces the limit.
		if got := out["body_encoding"]; got != "utf8" {
			t.Fatalf("invoke_function (1.3MB body) body_encoding = %v, want utf8", got)
		}
		body, _ := out["body"].(string)
		if len(body) != 1<<20 {
			t.Fatalf("invoke_function (1.3MB body) returned body length %d, want exactly %d (the cap)", len(body), 1<<20)
		}
	})
}

// TestE2E_MCPWorkspaceMembersAddRemove drives add_workspace_member,
// set_workspace_member_role, and remove_workspace_member through MCP,
// including a non-admin member's denied attempt to manage membership.
func TestE2E_MCPWorkspaceMembersAddRemove(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	ctx := context.Background()

	wsAdminToken := env.tokenForOwner(t, "mcp-ws-admin")
	wsAdminUser, err := env.store.Users().ByEmail(ctx, "mcp-ws-admin@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(mcp-ws-admin): %v", err)
	}

	ws := &store.Workspace{Name: "MCP Team", Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
	if err := env.store.CreateWorkspace(ctx, ws, wsAdminUser.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}

	env.tokenForOwner(t, "mcp-ws-member")
	memberUser, err := env.store.Users().ByEmail(ctx, "mcp-ws-member@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(mcp-ws-member): %v", err)
	}

	adminSession := mcpConnect(t, env, wsAdminToken)
	defer adminSession.Close()

	addOut := callTool(t, adminSession, "add_workspace_member", map[string]any{
		"workspace_id": ws.ID, "user_id": memberUser.ID, "role": "member",
	})
	if addOut["role"] != "member" {
		t.Fatalf("add_workspace_member result = %v, want role=member", addOut)
	}

	getOut := callTool(t, adminSession, "get_workspace", map[string]any{"workspace_id": ws.ID})
	if !workspaceHasMember(getOut, memberUser.ID) {
		t.Fatalf("get_workspace after add_workspace_member = %v, missing member %s", getOut, memberUser.ID)
	}

	// A non-admin member is refused management.
	memberToken := env.tokenForOwner(t, "mcp-ws-member") // same owner as above; tokenForOwner caches it
	memberSession := mcpConnect(t, env, memberToken)
	defer memberSession.Close()

	env.tokenForOwner(t, "mcp-ws-third")
	thirdUser, err := env.store.Users().ByEmail(ctx, "mcp-ws-third@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(mcp-ws-third): %v", err)
	}
	msg := callToolExpectIsError(t, memberSession, "add_workspace_member", map[string]any{
		"workspace_id": ws.ID, "user_id": thirdUser.ID, "role": "member",
	})
	if !strings.Contains(msg, "permitted") {
		t.Errorf("add_workspace_member by a non-admin member error = %q, want a permission refusal", msg)
	}

	// The admin changes the member's role.
	roleOut := callTool(t, adminSession, "set_workspace_member_role", map[string]any{
		"workspace_id": ws.ID, "user_id": memberUser.ID, "role": "admin",
	})
	if roleOut["role"] != "admin" {
		t.Fatalf("set_workspace_member_role result = %v, want role=admin", roleOut)
	}

	// The admin removes the (now ex-)member.
	removeOut := callTool(t, adminSession, "remove_workspace_member", map[string]any{
		"workspace_id": ws.ID, "user_id": memberUser.ID,
	})
	if removeOut["removed"] != true {
		t.Fatalf("remove_workspace_member result = %v, want removed=true", removeOut)
	}
	getOut2 := callTool(t, adminSession, "get_workspace", map[string]any{"workspace_id": ws.ID})
	if workspaceHasMember(getOut2, memberUser.ID) {
		t.Fatalf("get_workspace after remove_workspace_member = %v, still lists removed member %s", getOut2, memberUser.ID)
	}
}

func workspaceHasMember(ws map[string]any, userID string) bool {
	members, _ := ws["members"].([]any)
	for _, m := range members {
		mm, ok := m.(map[string]any)
		if ok && mm["user_id"] == userID {
			return true
		}
	}
	return false
}

// TestE2E_MCPOrgSettingsSelfDisableMCP proves update_org_settings' documented
// mcp_enabled self-disable behavior: the disabling call's own response
// still succeeds, but every /mcp request after it -- with no session-scoped
// grace period -- 404s, exactly as a REST-driven PATCH /api/v1/org would
// (TestE2E_MCPGating's own coverage), just triggered through MCP itself
// this time.
func TestE2E_MCPOrgSettingsSelfDisableMCP(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	client := env.loginViaHTTP(t, "mcp-org-admin@example.com")
	promoteToAdmin(t, env, "mcp-org-admin@example.com")

	accessToken, _, _ := mintMCPAccessToken(t, env, client)
	session := mcpConnect(t, env, accessToken)
	defer session.Close()

	getOut := callTool(t, session, "get_org_settings", map[string]any{})
	orgSettings, _ := getOut["settings"].(map[string]any)
	if orgSettings["mcp_enabled"] != true {
		t.Fatalf("get_org_settings before disabling = %v, want mcp_enabled=true", orgSettings)
	}

	updOut := callTool(t, session, "update_org_settings", map[string]any{
		"settings": map[string]any{"mcp_enabled": false},
	})
	updSettings, _ := updOut["settings"].(map[string]any)
	if updSettings["mcp_enabled"] != false {
		t.Fatalf("update_org_settings(mcp_enabled=false) result = %v, want mcp_enabled=false", updSettings)
	}

	resp, err := http.Get(env.baseURL + "/mcp")
	if err != nil {
		t.Fatalf("GET /mcp after self-disable: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /mcp after self-disabling mcp_enabled via MCP status = %d, want 404 (no session grace period)", resp.StatusCode)
	}
}

// TestE2E_MCPAuditListsMCPDrivenEntries proves list_audit_logs surfaces
// audit entries written by MCP-driven mutations (not just REST ones),
// filterable by action/user_id.
func TestE2E_MCPAuditListsMCPDrivenEntries(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	const owner = "mcp-audit-owner"
	token := env.tokenForOwner(t, owner)
	promoteToAdmin(t, env, owner+"@example.com")
	session := mcpConnect(t, env, token)
	defer session.Close()

	deployOut := callTool(t, session, "deploy_function", map[string]any{
		"owner": owner,
		"files": []any{
			deployFile("funcbox.yaml", "name: mcp-audit-app\n"),
			deployFile("index.js", `export default { fetch() { return new Response("ok"); } };`),
		},
	})
	if deployOut["version_id"] == "" {
		t.Fatalf("deploy_function (audit) did not persist: %v", deployOut)
	}

	auditOut := callTool(t, session, "list_audit_logs", map[string]any{"action": "function.deploy"})
	logs, _ := auditOut["audit_logs"].([]any)
	found := false
	for _, l := range logs {
		lm, ok := l.(map[string]any)
		if ok && lm["action"] == "function.deploy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("list_audit_logs(action=function.deploy) = %v, missing the MCP-driven deploy_function entry", logs)
	}
}

// TestE2E_MCPDevicesListAndRevokeOAuthGrant proves list_connected_devices
// shows the OAuth grant the harness's own mintMCPAccessToken mints
// (kind="oauth"), and that revoke_device actually kills its refresh
// grant -- a subsequent refresh_token exchange for it fails -- while the
// SAME already-issued access token (stateless, not tied to the grant row)
// keeps working, per §14.5's documented sliding-expiry design.
func TestE2E_MCPDevicesListAndRevokeOAuthGrant(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	client := env.loginViaHTTP(t, "mcp-device-user@example.com")

	accessToken, refreshToken, clientID := mintMCPAccessToken(t, env, client)
	session := mcpConnect(t, env, accessToken)
	defer session.Close()

	devicesOut := callTool(t, session, "list_connected_devices", map[string]any{})
	devices, _ := devicesOut["devices"].([]any)
	var grantID string
	for _, d := range devices {
		dm, ok := d.(map[string]any)
		if ok && dm["kind"] == "oauth" {
			grantID, _ = dm["id"].(string)
		}
	}
	if grantID == "" {
		t.Fatalf("list_connected_devices = %v, missing the oauth-kind grant from the harness's own mintMCPAccessToken", devices)
	}

	revokeOut := callTool(t, session, "revoke_device", map[string]any{"kind": "oauth", "id": grantID})
	if revokeOut["revoked"] != true {
		t.Fatalf("revoke_device result = %v, want revoked=true", revokeOut)
	}

	// The already-issued (stateless) access token still authenticates.
	if _, err := session.ListTools(context.Background(), &mcp.ListToolsParams{}); err != nil {
		t.Errorf("ListTools with the already-issued access token after revoke_device: %v (should still work; access tokens are not tied to the grant row)", err)
	}

	// But refreshing that grant now fails.
	refreshResp, err := http.PostForm(env.baseURL+"/oauth/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientID},
	})
	if err != nil {
		t.Fatalf("POST /oauth/token (refresh after revoke_device): %v", err)
	}
	defer refreshResp.Body.Close()
	if refreshResp.StatusCode == http.StatusOK {
		t.Fatalf("POST /oauth/token (refresh) after revoke_device status = %d, want a failure (grant was revoked)", refreshResp.StatusCode)
	}
}

// TestE2E_MCPStalePrivilegeMidSession is the regression coverage for
// Finding 1's per-request authorization half: a tool's registration at
// tools/list time is frozen to the actor's role AT INITIALIZE, but every
// handler must independently re-authorize the CURRENT call against the
// actor's CURRENT role -- so a mid-session demotion (or, symmetrically, a
// mid-session re-promotion) takes effect on the very next tool call, not
// on the next new session.
func TestE2E_MCPStalePrivilegeMidSession(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")
	ctx := context.Background()
	const owner = "mcp-stale-admin"
	email := owner + "@example.com"

	token := env.tokenForOwner(t, owner)
	promoteToAdmin(t, env, email)

	session := mcpConnect(t, env, token)
	defer session.Close()

	// tools/list, taken once at "initialize" time, includes the admin-only
	// users group -- this reflects the actor's role AT THAT MOMENT and is
	// never recomputed for the rest of the session's life (by this
	// package's own design: see mcpserver.go's getServer/registerTools doc
	// comments).
	listResult, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools (admin, before demotion): %v", err)
	}
	if !containsString(toolNames(listResult), "list_users") {
		t.Fatalf("admin tools/list = %v, missing list_users", toolNames(listResult))
	}

	// Demote out-of-band (e.g. another admin acting through the REST API),
	// entirely outside this MCP session.
	demoted, err := env.store.Users().ByEmail(ctx, email)
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	demoted.Role = store.RoleMember
	if err := env.store.Users().Update(ctx, demoted); err != nil {
		t.Fatalf("Users().Update (demote): %v", err)
	}

	// tools/list is STILL frozen at its initialize-time shape (list_users
	// still appears) -- proving the refusal below comes from the per-call
	// authorization check inside the handler, not from the tool having
	// disappeared from the list.
	listResult2, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools (after demotion): %v", err)
	}
	if !containsString(toolNames(listResult2), "list_users") {
		t.Fatalf("tools/list after demotion = %v, want list_users to still be listed (registration is frozen at initialize)", toolNames(listResult2))
	}

	// The SAME session, calling an admin tool that IS still listed, must
	// now be refused -- no state change, no "unknown tool" (it's still
	// registered), a clean authorization refusal instead.
	msg := callToolExpectIsError(t, session, "list_users", map[string]any{})
	if !strings.Contains(msg, "admin required") {
		t.Fatalf("list_users after demotion, error = %q, want it to mention \"admin required\"", msg)
	}

	// Re-promote (still out-of-band, same session): the very next call
	// succeeds again, proving authorization is re-derived FRESH on every
	// call rather than a session being permanently poisoned by one stale
	// check -- i.e. every tool call "acts as" the actor's CURRENT identity.
	demoted.Role = store.RoleAdmin
	if err := env.store.Users().Update(ctx, demoted); err != nil {
		t.Fatalf("Users().Update (re-promote): %v", err)
	}
	out := callTool(t, session, "list_users", map[string]any{})
	if _, ok := out["users"]; !ok {
		t.Fatalf("list_users after re-promotion = %v, want a successful users list", out)
	}
}

// TestE2E_MCPSessionBindingAndCaps covers Finding 1's session/user-binding
// half (a request authenticated as a DIFFERENT user than the one who
// established the session must be refused, even carrying a validly
// authenticated bearer token and a real, live Mcp-Session-Id) and Finding
// 2's concurrent-session cap (mirrors mcpserver's own unexported
// mcpMaxSessionsPerUser=5).
func TestE2E_MCPSessionBindingAndCaps(t *testing.T) {
	env := newTestEnvWithVisibility(t, "org")

	t.Run("a request carrying a different user's token but another session's id is rejected", func(t *testing.T) {
		tokenA := env.tokenForOwner(t, "mcp-bind-a")
		sessionA := mcpConnect(t, env, tokenA)
		defer sessionA.Close()
		sessionIDA := sessionA.ID()
		if sessionIDA == "" {
			t.Fatalf("session A's own ID() is empty -- can't drive this test without a real Mcp-Session-Id")
		}

		tokenB := env.tokenForOwner(t, "mcp-bind-b")

		post := func(token, sessionID string) *http.Response {
			t.Helper()
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
			req, err := http.NewRequest(http.MethodPost, env.baseURL+"/mcp", strings.NewReader(body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Mcp-Session-Id", sessionID)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST /mcp: %v", err)
			}
			return resp
		}

		// User B's own valid token, but session A's Mcp-Session-Id: this is
		// exactly the "session hijacking" shape Finding 1's second half
		// closes -- a stolen/guessed session ID plus the ATTACKER's own
		// (otherwise perfectly valid) credential must NOT ride along on
		// someone else's session.
		mismatched := post(tokenB, sessionIDA)
		defer mismatched.Body.Close()
		if mismatched.StatusCode != http.StatusForbidden {
			b, _ := io.ReadAll(mismatched.Body)
			t.Fatalf("POST /mcp (user B's token, session A's id) status = %d, want 403; body = %s", mismatched.StatusCode, b)
		}

		// Sanity: session A's OWN token against its OWN session id still
		// works -- proving the 403 above is specifically about the
		// user/session mismatch, not e.g. a broken tools/list request shape.
		own := post(tokenA, sessionIDA)
		defer own.Body.Close()
		if own.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(own.Body)
			t.Fatalf("POST /mcp (user A's own token, session A's id) status = %d, want 200; body = %s", own.StatusCode, b)
		}
	})

	t.Run("exceeding the concurrent per-user session cap is rejected", func(t *testing.T) {
		token := env.tokenForOwner(t, "mcp-cap-user")

		// Open sessions for the SAME user until one is refused, rather than
		// asserting an exact count first: a go-sdk client (as of the pinned
		// v1.7.0) can consume MORE than one server-side session slot per
		// logical Connect() call (it tries the newer "server/discover" RPC
		// first, which this non-Stateless server fully sessions but can
		// never hand the ID back for -- see mcpserver.go's own
		// mcpMaxSessionsPerUser doc comment for the full explanation), so
		// the exact number of successful Connect() calls before the cap
		// bites isn't a stable number to assert on. What this test actually
		// needs to prove -- that the cap is a REAL, finite ceiling, not
		// "unlimited" -- doesn't depend on that exact count.
		var sessions []*mcp.ClientSession
		defer func() {
			for _, s := range sessions {
				s.Close()
			}
		}()
		const attempts = 50 // comfortably more than any real per-user cap
		rejected := false
		for i := 0; i < attempts; i++ {
			client := mcp.NewClient(&mcp.Implementation{Name: "funcbox-e2e-cap-test-client", Version: "0.0.0"}, nil)
			transport := &mcp.StreamableClientTransport{
				Endpoint:   env.baseURL + "/mcp",
				HTTPClient: &http.Client{Transport: &bearerRoundTripper{token: token}},
			}
			s, err := client.Connect(context.Background(), transport, nil)
			if err != nil {
				rejected = true
				break
			}
			sessions = append(sessions, s)
		}
		if !rejected {
			t.Fatalf("opened %d concurrent sessions for the same user with none refused -- the per-user session cap is not enforced", attempts)
		}
		if len(sessions) == 0 {
			t.Fatalf("the very FIRST session for this user was refused -- the cap is misconfigured (too low) rather than actually being exceeded")
		}
	})
}
