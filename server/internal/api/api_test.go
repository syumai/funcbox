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
	"github.com/syumai/funcbox/internal/api"
	"github.com/syumai/funcbox/internal/auth"
	blobfs "github.com/syumai/funcbox/internal/blob/fs"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/internal/store/sqlite"
	"github.com/syumai/funcbox/runtime"
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

	admin := &store.User{GoogleSub: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := st.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := st.Handles().Create(ctx, &store.Handle{Handle: "admin", OwnerType: store.OwnerTypeUser, OwnerID: admin.ID}); err != nil {
		t.Fatalf("Handles().Create(admin): %v", err)
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
	handler := api.New(deployer, functions, st, authSvc, slog.New(slog.NewTextHandler(io.Discard, nil)))

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

// seedOwnerActor creates a user and claims owner as their handle if it
// isn't already claimed, returning the user. Deploy requires an
// already-claimed handle plus an authorized Actor (see
// internal/service.Deployer.Deploy); tests that seed multiple functions
// under the same owner call this more than once, so an already-claimed
// handle is not an error.
func seedOwnerActor(t *testing.T, st store.Store, owner string) *store.User {
	t.Helper()
	ctx := context.Background()
	if h, err := st.Handles().ByHandle(ctx, owner); err == nil {
		u, err := st.Users().ByID(ctx, h.OwnerID)
		if err != nil {
			t.Fatalf("Users().ByID: %v", err)
		}
		return u
	}
	u := &store.User{GoogleSub: "sub-" + owner, Email: owner + "@example.com", Name: owner, Role: store.RoleMember}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.Handles().Create(ctx, &store.Handle{Handle: owner, OwnerType: store.OwnerTypeUser, OwnerID: u.ID}); err != nil {
		t.Fatalf("Handles().Create: %v", err)
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
	av, ok := body["active_version"].(map[string]any)
	if !ok {
		t.Fatalf("active_version missing or not an object: %v", body)
	}
	if av["main_path"] != "index.js" {
		t.Errorf("active_version.main_path = %v, want %q", av["main_path"], "index.js")
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
