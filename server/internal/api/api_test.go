package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/config"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

// testAPIEnv is one fully-wired Handler (auth included) behind an
// httptest.Server, plus an admin API token every test uses to
// authenticate: this package's tests exercise CRUD/routing behavior, not
// the authorization matrix itself (that's internal/authz's and the
// top-level e2e suite's job), so acting as an org admin -- who can touch
// anything -- keeps them focused.
type testAPIEnv struct {
	baseURL    string
	deployer   *service.Deployer
	adminToken string
	admin      *store.User
}

func newTestAPI(t *testing.T) *testAPIEnv {
	t.Helper()
	ctx := context.Background()

	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	blobStore, err := blobfs.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobfs.New: %v", err)
	}
	manager := runtime.NewManager()
	t.Cleanup(func() { manager.Close() })

	authSvc, err := auth.New(auth.Config{
		Mode:          auth.ModeDev,
		BaseURL:       "http://127.0.0.1:0",
		ListenAddr:    "127.0.0.1:0",
		SessionSecret: "test-secret-value",
	}, st)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := st.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := st.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "admin", InternalUserID: admin.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create(admin): %v", err)
	}
	// NOTE: a blanket allow-all rule, deliberately WIDER than the real
	// login flow's bootstrap seeding (internal/auth's
	// Auth.seedBootstrapLoginRule only allows the bootstrap admin's own
	// exact email; see internal/auth/login_devflow_test.go). This
	// package's tests authenticate additional users (e.g. "mallory") that
	// never went through a real login, so login-rule evaluation --  which
	// every authenticated request goes through -- needs to not deny them
	// by default; which specific rules apply isn't what these tests are
	// about.
	if err := st.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionAllow},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	plaintext, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := st.Tokens().Create(ctx, &store.APIToken{
		UserID: admin.ID, TokenHash: hash, Name: "test", ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Tokens().Create: %v", err)
	}

	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	functions := &service.Functions{Store: st, Runtime: manager}
	hosting := &config.Config{
		ControlURL:     "https://dashboard.funcbox.example.com",
		FunctionDomain: "run.funcbox.example.com",
		OriginProfile:  "same-site",
	}
	handler := api.New(deployer, functions, st, authSvc, slog.New(slog.NewTextHandler(io.Discard, nil)), api.WithManagedFunctionURL(hosting.ManagedFunctionURL))

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &testAPIEnv{baseURL: srv.URL, deployer: deployer, adminToken: plaintext, admin: admin}
}

func seedFunction(t *testing.T, env *testAPIEnv, owner, name, indexJS string) string {
	t.Helper()
	actor := seedOwnerActor(t, env.deployer.Store, owner)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: " + name + "\n"),
		"index.js":     []byte(indexJS),
	}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	result, err := env.deployer.Deploy(context.Background(), service.DeployParams{
		Bundle: bytes.NewReader(packed),
		Owner:  owner,
		Name:   name,
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	return result.Version.ID
}

// seedOwnerActor creates a user and claims owner as their public User ID if it
// isn't already claimed, returning the user. Deploy requires an
// already-claimed User ID plus an authorized Actor (see
// internal/service.Deployer.Deploy); tests that seed multiple functions
// under the same owner call this more than once, so an already-claimed
// User ID is not an error.
func seedOwnerActor(t *testing.T, st store.Store, owner string) *store.User {
	t.Helper()
	ctx := context.Background()
	if id, err := st.PublicUserIDs().ByUserID(ctx, owner); err == nil {
		u, err := st.Users().ByID(ctx, id.InternalUserID)
		if err != nil {
			t.Fatalf("Users().ByID: %v", err)
		}
		return u
	}
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-" + owner, Email: owner + "@example.com", Name: owner, Role: store.RoleMember, Status: store.UserStatusActive}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: owner, InternalUserID: u.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	return u
}

func doRequest(t *testing.T, method, url, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

func getJSON(t *testing.T, url, token string) (int, map[string]any) {
	t.Helper()
	resp := doRequest(t, http.MethodGet, url, token, nil)
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil && err != io.EOF {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, body
}

func TestHandleGet(t *testing.T) {
	env := newTestAPI(t)
	seedFunction(t, env, "alice", "greet", `export default { fetch() { return new Response("hi"); } };`)

	status, body := getJSON(t, env.baseURL+"/api/v1/functions/alice/greet", env.adminToken)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	if body["name"] != "greet" {
		t.Errorf("name = %v, want %q", body["name"], "greet")
	}
	if body["url"] != "https://greet.run.funcbox.example.com/" {
		t.Errorf("url = %v, want canonical managed-function URL", body["url"])
	}
	av, ok := body["active_version"].(map[string]any)
	if !ok {
		t.Fatalf("active_version missing or not an object: %v", body)
	}
	if av["main_path"] != "index.js" {
		t.Errorf("active_version.main_path = %v, want %q", av["main_path"], "index.js")
	}
}

func TestDashboardLanguageSettings(t *testing.T) {
	env := newTestAPI(t)

	// A freshly created organization and user have no explicit Japanese
	// preference, so English is the default effective language.
	status, body := getJSON(t, env.baseURL+"/api/v1/me", env.adminToken)
	if status != http.StatusOK || body["language"] != nil || body["effective_language"] != "en" {
		t.Fatalf("initial GET /me = (%d, %v), want inherited English", status, body)
	}

	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org", env.adminToken,
		bytes.NewBufferString(`{"language":"ja"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH /org status = %d, body = %s", resp.StatusCode, b)
	}

	status, body = getJSON(t, env.baseURL+"/api/v1/me", env.adminToken)
	if status != http.StatusOK || body["language"] != nil || body["effective_language"] != "ja" {
		t.Fatalf("GET /me after org setting = (%d, %v), want inherited Japanese", status, body)
	}

	resp = doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/me", env.adminToken,
		bytes.NewBufferString(`{"language":"en"}`))
	defer resp.Body.Close()
	var patched map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode PATCH /me: %v", err)
	}
	if resp.StatusCode != http.StatusOK || patched["language"] != "en" || patched["effective_language"] != "en" {
		t.Fatalf("PATCH /me = (%d, %v), want individual English", resp.StatusCode, patched)
	}

	resp = doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/me", env.adminToken,
		bytes.NewBufferString(`{"language":null}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH /me inherit status = %d, body = %s", resp.StatusCode, b)
	}
	status, body = getJSON(t, env.baseURL+"/api/v1/me", env.adminToken)
	if status != http.StatusOK || body["language"] != nil || body["effective_language"] != "ja" {
		t.Fatalf("GET /me after inherit = (%d, %v), want inherited Japanese", status, body)
	}
}

func TestDashboardLanguageSettingsRejectUnsupportedLanguage(t *testing.T) {
	env := newTestAPI(t)
	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/me", env.adminToken,
		bytes.NewBufferString(`{"language":"fr"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH /me invalid language status = %d, body = %s", resp.StatusCode, b)
	}
	resp = doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org", env.adminToken,
		bytes.NewBufferString(`{"language":"fr"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH /org invalid language status = %d, body = %s", resp.StatusCode, b)
	}
}

// TestMePatch_GitHubProviderHandleChangeForbidden covers
// tmp/13-public-mode.md §13.2's fixed-handle rule: a GitHub-provider
// account's handle equals its GitHub username and cannot be changed
// through PATCH /api/v1/me, even though the dashboard normally exposes
// that field for Google accounts (see TestDashboardLanguageSettings's
// language-only PATCHes above, which never touch user_id).
func TestMePatch_GitHubProviderHandleChangeForbidden(t *testing.T) {
	env := newTestAPI(t)
	ctx := context.Background()

	ghUser := &store.User{Provider: store.ProviderGitHub, ProviderSubject: "12345", Email: "octocat@example.com", Name: "octocat", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := env.deployer.Store.Users().Create(ctx, ghUser); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := env.deployer.Store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "octocat", InternalUserID: ghUser.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	plaintext, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := env.deployer.Store.Tokens().Create(ctx, &store.APIToken{
		UserID: ghUser.ID, TokenHash: hash, Name: "test", ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Tokens().Create: %v", err)
	}

	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/me", plaintext,
		bytes.NewBufferString(`{"user_id":"someone-else"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH /me handle change for a GitHub account status = %d, body = %s, want 403", resp.StatusCode, b)
	}

	// The handle must be untouched.
	pid, err := env.deployer.Store.PublicUserIDs().ByOwner(ctx, ghUser.ID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByOwner: %v", err)
	}
	if pid.UserID != "octocat" {
		t.Fatalf("handle = %q, want unchanged %q", pid.UserID, "octocat")
	}

	// A PATCH that doesn't touch user_id (e.g. a language change) must
	// still be allowed for a GitHub-provider account.
	resp = doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/me", plaintext,
		bytes.NewBufferString(`{"language":"ja"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PATCH /me language-only change for a GitHub account status = %d, body = %s, want 200", resp.StatusCode, b)
	}
}

func TestHandleGet_RequiresAuthentication(t *testing.T) {
	env := newTestAPI(t)
	seedFunction(t, env, "alice", "greet", `export default { fetch() { return new Response("hi"); } };`)

	status, _ := getJSON(t, env.baseURL+"/api/v1/functions/alice/greet", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (no credential)", status)
	}
}

func TestHandleGet_UnknownFunctionIs404(t *testing.T) {
	env := newTestAPI(t)
	status, _ := getJSON(t, env.baseURL+"/api/v1/functions/nobody/nothing", env.adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

func TestHandleListVersions(t *testing.T) {
	env := newTestAPI(t)
	v1 := seedFunction(t, env, "bob", "app", `export default { fetch() { return new Response("v1"); } };`)
	v2 := seedFunction(t, env, "bob", "app", `export default { fetch() { return new Response("v2"); } };`)

	status, body := getJSON(t, env.baseURL+"/api/v1/functions/bob/app/versions", env.adminToken)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	versions, ok := body["versions"].([]any)
	if !ok || len(versions) != 2 {
		t.Fatalf("versions = %v, want 2 entries", body["versions"])
	}
	// Newest first.
	first := versions[0].(map[string]any)
	second := versions[1].(map[string]any)
	if first["id"] != v2 || second["id"] != v1 {
		t.Errorf("versions order = [%v, %v], want [%v, %v]", first["id"], second["id"], v2, v1)
	}
}

func TestHandleActivate_UnknownVersionIs404(t *testing.T) {
	env := newTestAPI(t)
	seedFunction(t, env, "carol", "app", `export default { fetch() { return new Response("v1"); } };`)

	resp := doRequest(t, http.MethodPost, env.baseURL+"/api/v1/functions/carol/app/versions/nonexistent/activate", env.adminToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHandleDelete(t *testing.T) {
	env := newTestAPI(t)
	seedFunction(t, env, "dave", "app", `export default { fetch() { return new Response("v1"); } };`)

	resp := doRequest(t, http.MethodDelete, env.baseURL+"/api/v1/functions/dave/app", env.adminToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}

	// Now gone.
	status, _ := getJSON(t, env.baseURL+"/api/v1/functions/dave/app", env.adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("status after delete = %d, want 404", status)
	}
}

// TestHandleDelete_NonOwnerNonAdminIsForbidden confirms mallory (who has no
// relationship at all to dave's function -- not its owner, not a member of
// any workspace that owns it) can't delete it. resolveVisible's CanView
// gate rejects her before CanManage is even consulted, so the response is
// 404 (indistinguishable from the function not existing at all), not 403
// -- see functions.go's doc comment on why unauthorized reads return 404
// while unauthorized writes on an already-visible resource return 403.
func TestHandleDelete_NonOwnerNonAdminIsForbidden(t *testing.T) {
	env := newTestAPI(t)
	seedFunction(t, env, "dave", "app", `export default { fetch() { return new Response("v1"); } };`)

	other := seedOwnerActor(t, env.deployer.Store, "mallory")
	plaintext, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := env.deployer.Store.Tokens().Create(context.Background(), &store.APIToken{
		UserID: other.ID, TokenHash: hash, Name: "mallory", ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Tokens().Create: %v", err)
	}

	resp := doRequest(t, http.MethodDelete, env.baseURL+"/api/v1/functions/dave/app", plaintext, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (mallory can't even see dave's function)", resp.StatusCode)
	}
}

func TestHandleList_NoOwnerReturnsAllFunctionsForAdmin(t *testing.T) {
	env := newTestAPI(t)
	seedFunction(t, env, "erin", "one", `export default { fetch() { return new Response("1"); } };`)

	status, body := getJSON(t, env.baseURL+"/api/v1/functions", env.adminToken)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	fns, ok := body["functions"].([]any)
	if !ok || len(fns) != 1 {
		t.Fatalf("functions = %v, want 1 entry (org admin sees every function)", body["functions"])
	}
	if got := fns[0].(map[string]any)["url"]; got != "https://one.run.funcbox.example.com/" {
		t.Errorf("function url = %v, want canonical managed-function URL", got)
	}
}

func TestHandleList_ByOwner(t *testing.T) {
	env := newTestAPI(t)
	seedFunction(t, env, "erin", "one", `export default { fetch() { return new Response("1"); } };`)
	seedFunction(t, env, "erin", "two", `export default { fetch() { return new Response("2"); } };`)

	status, body := getJSON(t, env.baseURL+"/api/v1/functions?owner=erin", env.adminToken)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %v", status, body)
	}
	fns, ok := body["functions"].([]any)
	if !ok || len(fns) != 2 {
		t.Fatalf("functions = %v, want 2 entries", body["functions"])
	}
}

// TestHandleOrgUserPatch_StatusAndCompat exercises PATCH
// /api/v1/org/users/{id}: a role change, a direct status change, and the
// deprecated {"disabled": bool} compatibility mapping (tmp/13-public-mode.md
// §13.3's users.disabled -> users.status generalization).
func TestHandleOrgUserPatch_StatusAndCompat(t *testing.T) {
	env := newTestAPI(t)
	ctx := context.Background()
	member := seedOwnerActor(t, env.deployer.Store, "carol")

	// Direct status field.
	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+member.ID, env.adminToken,
		bytes.NewBufferString(`{"status":"disabled"}`))
	defer resp.Body.Close()
	var patched map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.StatusCode != http.StatusOK || patched["status"] != "disabled" {
		t.Fatalf("PATCH status=disabled = (%d, %v), want 200 with status=disabled", resp.StatusCode, patched)
	}
	got, err := env.deployer.Store.Users().ByID(ctx, member.ID)
	if err != nil || got.Status != store.UserStatusDisabled {
		t.Fatalf("stored status = %v, %v; want %q", got, err, store.UserStatusDisabled)
	}

	// The deprecated {"disabled": false} shape maps to status=active.
	resp2 := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+member.ID, env.adminToken,
		bytes.NewBufferString(`{"disabled":false}`))
	defer resp2.Body.Close()
	var patched2 map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&patched2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp2.StatusCode != http.StatusOK || patched2["status"] != "active" {
		t.Fatalf("PATCH disabled=false (compat) = (%d, %v), want 200 with status=active", resp2.StatusCode, patched2)
	}

	// Last-admin guard: disabling the org's only admin (env.admin, the
	// bootstrap admin -- member/carol is not an admin yet) must 409, not
	// succeed.
	resp4 := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+env.admin.ID, env.adminToken,
		bytes.NewBufferString(`{"status":"disabled"}`))
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp4.Body)
		t.Fatalf("PATCH last admin status=disabled = %d, body = %s; want 409", resp4.StatusCode, b)
	}

	// Role change, independent of status. With a second active admin now
	// in place, disabling env.admin would no longer be blocked (not
	// exercised here; the guard's positive case is covered above).
	resp3 := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+member.ID, env.adminToken,
		bytes.NewBufferString(`{"role":"admin"}`))
	defer resp3.Body.Close()
	var patched3 map[string]any
	if err := json.NewDecoder(resp3.Body).Decode(&patched3); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp3.StatusCode != http.StatusOK || patched3["role"] != "admin" || patched3["status"] != "active" {
		t.Fatalf("PATCH role=admin = (%d, %v), want 200 with role=admin, status unchanged", resp3.StatusCode, patched3)
	}

	// An invalid status value is rejected.
	resp5 := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+member.ID, env.adminToken,
		bytes.NewBufferString(`{"status":"bogus"}`))
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp5.Body)
		t.Fatalf("PATCH status=bogus = %d, body = %s; want 400", resp5.StatusCode, b)
	}
}

// TestWorkspaceCreate_RequiresAdminOrWorkspaceManager is the HTTP-handler
// counterpart to internal/authz's TestMatrix_WorkspaceCreate: it confirms
// handleWorkspaceCreate actually wires CanCreateWorkspace in (not just
// that the pure decision function is correct), covering all three roles
// via a real POST /api/v1/workspaces.
func TestWorkspaceCreate_RequiresAdminOrWorkspaceManager(t *testing.T) {
	env := newTestAPI(t)
	ctx := context.Background()

	member := seedOwnerActor(t, env.deployer.Store, "grace")
	memberToken := mintTestToken(t, env.deployer.Store, member.ID)

	wsManager := seedOwnerActor(t, env.deployer.Store, "heidi")
	wsManager.Role = store.RoleWorkspaceManager
	if err := env.deployer.Store.Users().Update(ctx, wsManager); err != nil {
		t.Fatalf("promote heidi to workspace_manager: %v", err)
	}
	wsManagerToken := mintTestToken(t, env.deployer.Store, wsManager.ID)

	resp := doRequest(t, http.MethodPost, env.baseURL+"/api/v1/workspaces", memberToken,
		bytes.NewBufferString(`{"handle":"member-attempt","name":"nope"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("member create workspace status = %d, want 403", resp.StatusCode)
	}

	resp = doRequest(t, http.MethodPost, env.baseURL+"/api/v1/workspaces", wsManagerToken,
		bytes.NewBufferString(`{"handle":"managed","name":"Managed"}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("workspace_manager create workspace status = %d, body = %s, want 201", resp.StatusCode, b)
	}

	resp = doRequest(t, http.MethodPost, env.baseURL+"/api/v1/workspaces", env.adminToken,
		bytes.NewBufferString(`{"handle":"by-admin","name":"By Admin"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("admin create workspace status = %d, want 201", resp.StatusCode)
	}
}

// mintTestToken issues a real API token for userID directly against the
// store, the same test-only shortcut internal/dashboard's server_test.go
// uses for a personal handle already provisioned by seedOwnerActor.
func mintTestToken(t *testing.T, st store.Store, userID string) string {
	t.Helper()
	plaintext, hash, err := auth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := st.Tokens().Create(context.Background(), &store.APIToken{
		UserID: userID, TokenHash: hash, Name: "test", ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Tokens().Create: %v", err)
	}
	return plaintext
}

// TestOrgUserPatch_AcceptsWorkspaceManagerRole covers §14.1's PATCH
// /api/v1/org/users/{id} extension: role: "workspace_manager" is now a
// valid target role, distinct from the pre-existing admin/member pair.
func TestOrgUserPatch_AcceptsWorkspaceManagerRole(t *testing.T) {
	env := newTestAPI(t)
	member := seedOwnerActor(t, env.deployer.Store, "frank")
	if member.Role != store.RoleMember {
		t.Fatalf("seeded actor role = %q, want %q", member.Role, store.RoleMember)
	}

	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+member.ID, env.adminToken,
		bytes.NewBufferString(`{"role":"workspace_manager"}`))
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH role=workspace_manager status = %d, body = %v", resp.StatusCode, body)
	}
	if body["role"] != "workspace_manager" {
		t.Errorf("role = %v, want %q", body["role"], "workspace_manager")
	}

	updated, err := env.deployer.Store.Users().ByID(context.Background(), member.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if updated.Role != store.RoleWorkspaceManager {
		t.Errorf("stored role = %q, want %q", updated.Role, store.RoleWorkspaceManager)
	}
}

// TestOrgUserPatch_LastAdminGuardBlocksDemotionToWorkspaceManager is the
// §14.1 regression the task calls out explicitly: demoting the
// organization's last active admin to workspace_manager must still 409,
// exactly like demoting them to plain member always has -- workspace_manager
// is a member-equivalent role for this guard's purposes, not a second kind
// of admin.
func TestOrgUserPatch_LastAdminGuardBlocksDemotionToWorkspaceManager(t *testing.T) {
	env := newTestAPI(t) // env.admin is the organization's only admin

	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+env.admin.ID, env.adminToken,
		bytes.NewBufferString(`{"role":"workspace_manager"}`))
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("PATCH demoting the last admin to workspace_manager status = %d, body = %s, want 409", resp.StatusCode, b)
	}

	unchanged, err := env.deployer.Store.Users().ByID(context.Background(), env.admin.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if unchanged.Role != store.RoleAdmin {
		t.Errorf("last admin's role changed to %q despite the 409, want unchanged %q", unchanged.Role, store.RoleAdmin)
	}
}

// TestMeGet_FunctionQuotaAndPendingCount covers handleMeGet's §13.3/§13.4
// additions: personal_function_count/limit and pending_approval_count are
// present only when applicable (a limit set, or an admin caller).
func TestMeGet_FunctionQuotaAndPendingCount(t *testing.T) {
	env := newTestAPI(t)

	// No org limit set yet: personal_function_count/limit absent.
	status, body := getJSON(t, env.baseURL+"/api/v1/me", env.adminToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me status = %d", status)
	}
	if _, ok := body["personal_function_limit"]; ok {
		t.Errorf("GET /me = %v, want no personal_function_limit key when unlimited", body)
	}

	// Set a personal-function limit and re-check.
	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org", env.adminToken,
		bytes.NewBufferString(`{"max_functions_per_user":3}`))
	resp.Body.Close()

	status, body = getJSON(t, env.baseURL+"/api/v1/me", env.adminToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me status = %d", status)
	}
	if count, ok := body["personal_function_count"].(float64); !ok || count != 0 {
		t.Errorf("personal_function_count = %v, want 0", body["personal_function_count"])
	}
	if limit, ok := body["personal_function_limit"].(float64); !ok || limit != 3 {
		t.Errorf("personal_function_limit = %v, want 3", body["personal_function_limit"])
	}

	// pending_approval_count: present (and correct) for the admin caller,
	// absent for a non-admin member.
	seedPendingActor(t, env.deployer.Store, "grace2")
	seedPendingActor(t, env.deployer.Store, "heidi2")
	status, body = getJSON(t, env.baseURL+"/api/v1/me", env.adminToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me status = %d", status)
	}
	if n, ok := body["pending_approval_count"].(float64); !ok || n != 2 {
		t.Errorf("admin's pending_approval_count = %v, want 2", body["pending_approval_count"])
	}

	member := seedOwnerActor(t, env.deployer.Store, "ivan2")
	memberToken := mintTestToken(t, env.deployer.Store, member.ID)
	status, body = getJSON(t, env.baseURL+"/api/v1/me", memberToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me (member) status = %d", status)
	}
	if _, ok := body["pending_approval_count"]; ok {
		t.Errorf("non-admin GET /me = %v, want no pending_approval_count key", body)
	}
}

// seedPendingActor creates a store.UserStatusPending user directly against
// the store (tmp/13-public-mode.md §13.3) -- unlike seedOwnerActor, which
// always creates an active one.
func seedPendingActor(t *testing.T, st store.Store, owner string) *store.User {
	t.Helper()
	ctx := context.Background()
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-" + owner, Email: owner + "@example.com", Name: owner, Role: store.RoleMember, Status: store.UserStatusPending}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: owner, InternalUserID: u.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	return u
}

// TestPendingUser_Gets403PendingApprovalOnEveryRoute covers
// requirePendingApproved (handler.go): a pending user's session/API-token
// authentication succeeds (see internal/auth's validateAuthenticatable),
// but every /api/v1/* route -- a read (GET /me) as much as a write (POST
// /me/tokens, the API-token/CLI credential issuance path §13.3 calls
// out explicitly) -- must uniformly 403 with code pending_approval.
func TestPendingUser_Gets403PendingApprovalOnEveryRoute(t *testing.T) {
	env := newTestAPI(t)
	pending := seedPendingActor(t, env.deployer.Store, "dave")
	token := mintTestToken(t, env.deployer.Store, pending.ID)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   io.Reader
	}{
		{"GET /me", http.MethodGet, "/api/v1/me", nil},
		{"GET /functions", http.MethodGet, "/api/v1/functions", nil},
		{"POST /me/tokens", http.MethodPost, "/api/v1/me/tokens", bytes.NewBufferString(`{"name":"x","expires_at":"2099-01-01T00:00:00Z"}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, tc.method, env.baseURL+tc.path, token, tc.body)
			defer resp.Body.Close()
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s status = %d, body = %v, want 403", tc.name, resp.StatusCode, body)
			}
			errObj, _ := body["error"].(map[string]any)
			if errObj["code"] != "pending_approval" {
				t.Errorf("%s error.code = %v, want %q", tc.name, errObj["code"], "pending_approval")
			}
		})
	}

	// No NEW token must have been created by the blocked POST above (only
	// the one this test's own mintTestToken setup call issued as the
	// bearer credential itself, named "test").
	tokens, err := env.deployer.Store.Tokens().ListByUser(context.Background(), pending.ID)
	if err != nil {
		t.Fatalf("Tokens().ListByUser: %v", err)
	}
	for _, tok := range tokens {
		if tok.Name == "x" {
			t.Errorf("pending user's blocked token-create request still created a token named %q", tok.Name)
		}
	}
}

// TestOrgUserPatch_ApprovalIsAuditDistinguishable covers the audit
// coverage the task calls out: approving (pending -> active) or rejecting
// (pending -> disabled) a pending user's request must be distinguishable
// in the audit log from an ordinary status edit, via previous_status and
// the derived approval_action label.
func TestOrgUserPatch_ApprovalIsAuditDistinguishable(t *testing.T) {
	env := newTestAPI(t)
	pending := seedPendingActor(t, env.deployer.Store, "erin")

	resp := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+pending.ID, env.adminToken,
		bytes.NewBufferString(`{"status":"active"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH status=active status = %d", resp.StatusCode)
	}

	logs, err := env.deployer.Store.Audit().List(context.Background(), "", 20)
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	var found map[string]any
	for _, l := range logs {
		if l.Action == "org.user.update" && l.Target == "user:"+pending.ID {
			var detail map[string]any
			if err := json.Unmarshal(l.Detail, &detail); err != nil {
				t.Fatalf("unmarshal audit detail: %v", err)
			}
			found = detail
			break
		}
	}
	if found == nil {
		t.Fatal("no org.user.update audit row found for the approval")
	}
	if found["previous_status"] != "pending" || found["status"] != "active" {
		t.Errorf("audit detail = %v, want previous_status=pending status=active", found)
	}
	if found["approval_action"] != "approved" {
		t.Errorf("audit detail approval_action = %v, want %q", found["approval_action"], "approved")
	}

	// A plain status edit that ISN'T an approval (active -> disabled, not
	// starting from pending) must not be mislabeled as one.
	member := seedOwnerActor(t, env.deployer.Store, "frank2")
	resp2 := doRequest(t, http.MethodPatch, env.baseURL+"/api/v1/org/users/"+member.ID, env.adminToken,
		bytes.NewBufferString(`{"status":"disabled"}`))
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("PATCH status=disabled status = %d", resp2.StatusCode)
	}
	logs2, err := env.deployer.Store.Audit().List(context.Background(), "", 20)
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	for _, l := range logs2 {
		if l.Action == "org.user.update" && l.Target == "user:"+member.ID {
			var detail map[string]any
			if err := json.Unmarshal(l.Detail, &detail); err != nil {
				t.Fatalf("unmarshal audit detail: %v", err)
			}
			if detail["approval_action"] != "" {
				t.Errorf("ordinary active->disabled edit audit detail approval_action = %v, want empty (not an approval/rejection)", detail["approval_action"])
			}
			return
		}
	}
	t.Fatal("no org.user.update audit row found for the ordinary status edit")
}
