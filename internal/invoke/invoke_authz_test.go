// invoke_authz_test.go covers tmp/05-auth-and-permissions.md §5.2's
// invoke-path authorization: visibility resolution (public/org/workspace)
// and the caller-identity check for anything narrower than public. Tokens
// are minted from a real dev-mode stub identity provider
// (internal/auth's FUNCBOX_AUTH_MODE=dev issuer), driven over actual HTTP,
// so these tests exercise the SAME ID-token verification code path
// production traffic would (see internal/auth/provider.go's doc comment).
package invoke

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	blobfs "github.com/syumai/funcbox/internal/blob/fs"
	"github.com/syumai/funcbox/internal/bundle"
	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/settings"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/internal/store/sqlite"

	"github.com/syumai/funcbox/internal/auth"
)

// devIdPEnv is a running dev-mode stub identity provider, for minting ID
// tokens in tests.
type devIdPEnv struct {
	auth     *auth.Auth
	server   *httptest.Server
	clientID string
}

func newDevIdPEnv(t *testing.T, st store.Store) *devIdPEnv {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a, err := auth.New(auth.Config{
		Mode:          auth.ModeDev,
		BaseURL:       srv.URL,
		ListenAddr:    "127.0.0.1:0",
		ClientID:      "test-invoke-client",
		ClientSecret:  "test-invoke-secret",
		SessionSecret: "test-secret-value",
	}, st)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	mux.Handle("/dev/oidc/", a.DevRoutes())

	return &devIdPEnv{auth: a, server: srv, clientID: "test-invoke-client"}
}

// mintIDToken drives the dev IdP's authorize+token endpoints directly
// (skipping the interactive browser form, and skipping /auth/callback
// entirely -- an invoke-path caller presents a raw ID token, not a
// session) to obtain a signed ID token for email.
func (e *devIdPEnv) mintIDToken(t *testing.T, email string) string {
	t.Helper()
	redirectURI := "http://localhost/callback"

	form := url.Values{
		"client_id":    {e.clientID},
		"redirect_uri": {redirectURI},
		"state":        {"s"},
		"nonce":        {"n"},
		"email":        {email},
	}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(e.server.URL+"/dev/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize redirect had no code: %s", resp.Header.Get("Location"))
	}

	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {e.clientID},
	}
	resp2, err := http.PostForm(e.server.URL+"/dev/oidc/token", tokenForm)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("token status = %d, body = %s", resp2.StatusCode, body)
	}
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if body.IDToken == "" {
		t.Fatal("token response had no id_token")
	}
	return body.IDToken
}

// authzTestEnv wires an Invoker (with a real Auth attached) plus a
// devIdPEnv for minting tokens against the SAME store.
type authzTestEnv struct {
	inv   *Invoker
	st    store.Store
	devIP *devIdPEnv
}

func newAuthzTestEnv(t *testing.T, orgDefaultVisibility string) *authzTestEnv {
	t.Helper()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	bootstrapTestOrg(t, st, orgDefaultVisibility)

	blobStore, err := blobfs.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobfs.New: %v", err)
	}
	manager := runtime.NewManager()
	t.Cleanup(func() { manager.Close() })

	devIP := newDevIdPEnv(t, st)

	inv := &Invoker{
		Store:   st,
		Blob:    blobStore,
		Manager: manager,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Timeout: 5 * time.Second,
		Auth:    devIP.auth,
	}
	return &authzTestEnv{inv: inv, st: st, devIP: devIP}
}

func (e *authzTestEnv) deploy(t *testing.T, owner, name string, files map[string][]byte, actor *store.User) {
	t.Helper()
	deployer := &service.Deployer{Store: e.st, Blob: e.inv.Blob, Runtime: e.inv.Manager}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	result, err := deployer.Deploy(context.Background(), service.DeployParams{
		Bundle: bytes.NewReader(packed), Owner: owner, Name: name, Actor: actor,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Function == nil {
		t.Fatal("Deploy did not create a function")
	}
}

func okHandlerFiles(manifestExtra string) map[string][]byte {
	return map[string][]byte{
		"funcbox.yaml": []byte("name: app\n" + manifestExtra),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
}

func TestInvokeAuthz_PublicVisibilityAllowsAnonymous(t *testing.T) {
	env := newAuthzTestEnv(t, "org") // org default visibility irrelevant: manifest is explicit
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin", "app", okHandlerFiles("visibility: public\n"), admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	env.inv.Serve(w, r, "admin", "app")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q, want 200 (public function, anonymous)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_OrgVisibilityRejectsAnonymous(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin", "app", okHandlerFiles(""), admin) // no explicit visibility -> org default applies

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	env.inv.Serve(w, r, "admin", "app")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %q, want 401 (org-visibility function, no credential)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_OrgVisibilityAcceptsValidIDToken(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin", "app", okHandlerFiles(""), admin)

	token := env.devIP.mintIDToken(t, admin.Email)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	env.inv.Serve(w, r, "admin", "app")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q, want 200 (valid org member ID token)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_OrgVisibilityRejectsNonMemberEmail(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin", "app", okHandlerFiles(""), admin)

	// A syntactically valid, correctly-signed ID token, but for an email
	// with no corresponding users row -- must still be rejected.
	token := env.devIP.mintIDToken(t, "stranger@example.com")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	env.inv.Serve(w, r, "admin", "app")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %q, want 401 (email not an org member)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_WorkspaceVisibilityRequiresMembership(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)

	ws := &store.Workspace{Name: "Team", Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
	if err := env.st.CreateWorkspace(context.Background(), ws, "team", admin.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	env.deploy(t, "team", "app", okHandlerFiles("visibility: workspace\n"), admin)

	member := &store.User{GoogleSub: "sub-member", Email: "member@example.com", Name: "Member", Role: store.RoleMember}
	if err := env.st.Users().Create(context.Background(), member); err != nil {
		t.Fatalf("Users().Create(member): %v", err)
	}
	outsider := &store.User{GoogleSub: "sub-outsider", Email: "outsider@example.com", Name: "Outsider", Role: store.RoleMember}
	if err := env.st.Users().Create(context.Background(), outsider); err != nil {
		t.Fatalf("Users().Create(outsider): %v", err)
	}
	if err := env.st.Workspaces().AddMember(context.Background(), &store.WorkspaceMember{
		WorkspaceID: ws.ID, UserID: member.ID, Role: store.RoleMember,
	}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	t.Run("member allowed", func(t *testing.T) {
		token := env.devIP.mintIDToken(t, member.Email)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/team/app", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		env.inv.Serve(w, r, "team", "app")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %q, want 200 (workspace member)", w.Code, w.Body.String())
		}
	})

	t.Run("non-member org user rejected", func(t *testing.T) {
		token := env.devIP.mintIDToken(t, outsider.Email)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/team/app", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		env.inv.Serve(w, r, "team", "app")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %q, want 403 (org member but not workspace member)", w.Code, w.Body.String())
		}
	})
}

func TestInvokeAuthz_CallerEmailHeaderInjected(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js": []byte(`
			export default {
				fetch(req) {
					return new Response(req.headers.get("X-Funcbox-Caller-Email") || "none");
				},
			};
		`),
	}
	env.deploy(t, "admin", "app", files, admin)

	token := env.devIP.mintIDToken(t, admin.Email)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	// A client-supplied X-Funcbox-* header must never survive to the guest.
	r.Header.Set("X-Funcbox-Caller-Email", "spoofed@evil.com")
	env.inv.Serve(w, r, "admin", "app")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if w.Body.String() != admin.Email {
		t.Fatalf("X-Funcbox-Caller-Email seen by guest = %q, want %q", w.Body.String(), admin.Email)
	}
}

func TestInvokeAuthz_BrowserFallbackRedirectsToLogin(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin", "app", okHandlerFiles(""), admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	env.inv.Serve(w, r, "admin", "app")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %q, want 302 (browser redirected to login)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc == "" || loc[:len(auth.LoginURL(""))] != auth.LoginURL("") {
		t.Fatalf("Location = %q, want it to start with %q", loc, auth.LoginURL(""))
	}
}

// bootstrapAdmin is a lighter variant of bootstrapTestOrg for tests that
// need direct access to the admin *store.User (bootstrapTestOrg above only
// returns it too, but this name documents the intent at call sites that
// don't care about overriding default_visibility).
func bootstrapAdmin(t *testing.T, st store.Store) *store.User {
	t.Helper()
	u, err := st.Users().ByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(admin): %v (was bootstrapTestOrg called?)", err)
	}
	return u
}
