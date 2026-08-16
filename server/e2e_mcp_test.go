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
func mintMCPAccessToken(t *testing.T, env *testEnv, client *http.Client) (accessToken, refreshToken string) {
	t.Helper()
	const redirectURI = "http://127.0.0.1:54123/callback"
	clientID := registerMCPClient(t, env, redirectURI)
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
	return out.AccessToken, out.RefreshToken
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

	accessToken, _ := mintMCPAccessToken(t, env, client)

	session := mcpConnect(t, env, accessToken)
	defer session.Close()

	listResult, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := toolNames(listResult)
	for _, want := range []string{"list_users", "approve_user", "reject_user", "set_user_role", "set_user_status"} {
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

	t.Run("member's tools/list excludes the users tool group", func(t *testing.T) {
		memberToken := env.tokenForOwner(t, "mcp-member") // aud-less, general-purpose -- also valid at /mcp
		memberSession := mcpConnect(t, env, memberToken)
		defer memberSession.Close()

		res, err := memberSession.ListTools(context.Background(), &mcp.ListToolsParams{})
		if err != nil {
			t.Fatalf("ListTools (member): %v", err)
		}
		if names := toolNames(res); len(names) != 0 {
			t.Errorf("member tools/list = %v, want empty (no users tools registered for a non-admin)", names)
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
