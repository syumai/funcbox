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
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/runtime"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"

	"github.com/syumai/funcbox/server/internal/auth"
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
	env.deploy(t, "admin-user", "app", okHandlerFiles("visibility: public\n"), admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	env.inv.Serve(w, r, "admin-user", "app")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q, want 200 (public function, anonymous)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_OrgVisibilityRejectsAnonymous(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", okHandlerFiles(""), admin) // no explicit visibility -> org default applies

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	env.inv.Serve(w, r, "admin-user", "app")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %q, want 401 (org-visibility function, no credential)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_OrgVisibilityAcceptsValidIDToken(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", okHandlerFiles(""), admin)

	token := env.devIP.mintIDToken(t, admin.Email)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	env.inv.Serve(w, r, "admin-user", "app")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q, want 200 (valid org member ID token)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_OrgVisibilityRejectsNonMemberEmail(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", okHandlerFiles(""), admin)

	// A syntactically valid, correctly-signed ID token, but for an email
	// with no corresponding users row -- must still be rejected.
	token := env.devIP.mintIDToken(t, "stranger@example.com")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	env.inv.Serve(w, r, "admin-user", "app")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %q, want 401 (email not an org member)", w.Code, w.Body.String())
	}
}

func TestInvokeAuthz_WorkspaceVisibilityRequiresMembership(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)

	ws := &store.Workspace{Name: "Team", Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
	if err := env.st.CreateWorkspace(context.Background(), ws, admin.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	env.deploy(t, ws.ID, "app", okHandlerFiles("visibility: workspace\n"), admin)

	member := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-member", Email: "member@example.com", Name: "Member", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := env.st.Users().Create(context.Background(), member); err != nil {
		t.Fatalf("Users().Create(member): %v", err)
	}
	outsider := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-outsider", Email: "outsider@example.com", Name: "Outsider", Role: store.RoleMember, Status: store.UserStatusActive}
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
		r := httptest.NewRequest(http.MethodGet, "/workspace/app", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		env.inv.Serve(w, r, ws.ID, "app")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %q, want 200 (workspace member)", w.Code, w.Body.String())
		}
	})

	t.Run("non-member org user rejected", func(t *testing.T) {
		token := env.devIP.mintIDToken(t, outsider.Email)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/workspace/app", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		env.inv.Serve(w, r, ws.ID, "app")
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
	env.deploy(t, "admin-user", "app", files, admin)

	token := env.devIP.mintIDToken(t, admin.Email)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	// A client-supplied X-Funcbox-* header must never survive to the guest.
	r.Header.Set("X-Funcbox-Caller-Email", "spoofed@evil.com")
	env.inv.Serve(w, r, "admin-user", "app")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if w.Body.String() != admin.Email {
		t.Fatalf("X-Funcbox-Caller-Email seen by guest = %q, want %q", w.Body.String(), admin.Email)
	}
}

// setOpenMode flips the already-bootstrapped test organization's
// open_mode/expose_caller_identity settings, preserving whatever
// default_visibility bootstrapTestOrg set.
func setOpenMode(t *testing.T, st store.Store, openMode, exposeCallerIdentity bool) {
	t.Helper()
	ctx := context.Background()
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	orgSet.OpenMode = openMode
	orgSet.ExposeCallerIdentity = exposeCallerIdentity
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := st.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}
}

// callerEmailHeaderTestFiles is TestInvokeAuthz_CallerEmailHeaderInjected's
// manifest+source, reused by the open-mode suppression tests below.
func callerEmailHeaderTestFiles() map[string][]byte {
	return map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js": []byte(`
			export default {
				fetch(req) {
					return new Response(req.headers.get("X-Funcbox-Caller-Email") || "none");
				},
			};
		`),
	}
}

// TestInvokeAuthz_CallerEmailHeaderSuppressedInOpenMode covers
// tmp/13-public-mode.md §13.1 item 2's last bullet: with open_mode on and
// expose_caller_identity left at its default (false), the invoked
// function must NOT see the caller's email, even though the caller was
// authenticated and authorized normally.
func TestInvokeAuthz_CallerEmailHeaderSuppressedInOpenMode(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", callerEmailHeaderTestFiles(), admin)
	setOpenMode(t, env.st, true, false)

	token := env.devIP.mintIDToken(t, admin.Email)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	env.inv.Serve(w, r, "admin-user", "app")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if w.Body.String() != "none" {
		t.Fatalf("X-Funcbox-Caller-Email seen by guest under open mode = %q, want suppressed (\"none\")", w.Body.String())
	}
}

// TestInvokeAuthz_CallerEmailHeaderExposedWhenOptedIn covers the opt-back-in
// half of the same rule: expose_caller_identity=true restores the header
// even while open_mode is on.
func TestInvokeAuthz_CallerEmailHeaderExposedWhenOptedIn(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", callerEmailHeaderTestFiles(), admin)
	setOpenMode(t, env.st, true, true)

	token := env.devIP.mintIDToken(t, admin.Email)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	env.inv.Serve(w, r, "admin-user", "app")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if w.Body.String() != admin.Email {
		t.Fatalf("X-Funcbox-Caller-Email seen by guest with expose_caller_identity=true = %q, want %q", w.Body.String(), admin.Email)
	}
}

func TestInvokeAuthz_BrowserFallbackRedirectsToInvokeSSO(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", okHandlerFiles(""), admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	env.inv.Serve(w, r, "admin-user", "app")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %q, want 302 (browser redirected to login)", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "/auth/invoke?") ||
		!strings.Contains(loc, "function=app") || !strings.Contains(loc, "return_to=%2Fadmin%2Fapp") {
		t.Fatalf("Location = %q, want browser SSO handoff", loc)
	}
}

// TestInvokeAuthz_UnauthenticatedNonBrowserGets401WithBearerGuidance covers
// §14.3 item 1's second row: a non-browser-like unauthenticated request
// (no Accept: text/html, or a non-GET/HEAD method) must keep getting the
// original 401 JSON response, but now carrying WWW-Authenticate: Bearer
// and a message that tells a terminal user how to obtain a credential
// (funcbox print-access-token, §14.5).
func TestInvokeAuthz_UnauthenticatedNonBrowserGets401WithBearerGuidance(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", okHandlerFiles(""), admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/app", nil)
	// No Accept header at all -- the curl/API-client case.
	env.inv.Serve(w, r, "admin-user", "app")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %q, want 401", w.Code, w.Body.String())
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, "Bearer")
	}
	if !strings.Contains(w.Body.String(), "print-access-token") {
		t.Fatalf("401 body = %q, want it to mention `funcbox print-access-token`", w.Body.String())
	}
}

// TestInvokeAuthz_NonGetWithOnlyCookieGets401WithBearerGuidance covers §14.3
// item 5: a POST (or any non-GET/HEAD method) presenting only a cookie --
// never accepted for CSRF reasons, §5.2 -- must be rejected the same way
// as no credential at all: 401 with the access-token guidance, not a
// redirect (redirecting a POST through a GET-based login flow would drop
// the request body/method anyway) and not treated as "authenticated but
// forbidden" (there IS no resolved identity here; the cookie was never
// even looked at).
func TestInvokeAuthz_NonGetWithOnlyCookieGets401WithBearerGuidance(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)
	env.deploy(t, "admin-user", "app", okHandlerFiles(""), admin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/app", nil)
	// A cookie alone must never authorize a non-GET/HEAD invocation, even
	// one that happens to look exactly like a real invoke cookie in shape.
	r.AddCookie(&http.Cookie{Name: "__Host-fbx_invoke", Value: "whatever"})
	env.inv.Serve(w, r, "admin-user", "app")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %q, want 401 (POST + cookie-only)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, "Bearer")
	}
	if !strings.Contains(w.Body.String(), "print-access-token") {
		t.Fatalf("401 body = %q, want it to mention `funcbox print-access-token`", w.Body.String())
	}
}

// TestInvokeAuthz_WorkspaceNonMemberBrowserGetsAccessDeniedPage covers
// §14.3 item 3's UX decision: a browser-like request (GET + Accept:
// text/html) from an authenticated-but-not-authorized caller (here: an org
// member who isn't a member of the function's workspace) renders the
// Go-side bilingual "access denied" HTML page instead of bare JSON, while
// still answering 403 -- and a non-browser request to the exact same URL
// still gets the plain JSON body (see the "member allowed"/"non-member org
// user rejected" subtests above for that JSON-body coverage).
func TestInvokeAuthz_WorkspaceNonMemberBrowserGetsAccessDeniedPage(t *testing.T) {
	env := newAuthzTestEnv(t, "org")
	admin := bootstrapAdmin(t, env.st)

	ws := &store.Workspace{Name: "Team", Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
	if err := env.st.CreateWorkspace(context.Background(), ws, admin.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	env.deploy(t, ws.ID, "app", okHandlerFiles("visibility: workspace\n"), admin)

	outsider := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-outsider2", Email: "outsider2@example.com", Name: "Outsider2", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := env.st.Users().Create(context.Background(), outsider); err != nil {
		t.Fatalf("Users().Create(outsider): %v", err)
	}

	token := env.devIP.mintIDToken(t, outsider.Email)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/workspace/app", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	env.inv.Serve(w, r, ws.ID, "app")

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %q, want 403", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html (browser-like request)", ct)
	}
	if !strings.Contains(w.Body.String(), "Access denied") || !strings.Contains(w.Body.String(), "アクセス権がありません") {
		t.Fatalf("access-denied page body missing expected EN/JA text: %q", w.Body.String())
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
