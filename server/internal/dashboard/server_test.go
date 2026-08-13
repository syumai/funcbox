package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/internal/api"
	"github.com/syumai/funcbox/internal/auth"
	blobfs "github.com/syumai/funcbox/internal/blob/fs"
	fcrypto "github.com/syumai/funcbox/internal/crypto"
	"github.com/syumai/funcbox/internal/server"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/internal/store/sqlite"
	"github.com/syumai/funcbox/runtime"
)

const testSessionSecret = "dashboard-test-session-secret"

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testEnv wires a full funcbox-server stack (real in-memory sqlite, a
// filesystem blob store, dev-mode auth, and internal/server's router with
// this package's Server mounted as Deps.Dashboard) behind an
// httptest.Server -- the same composition cmd/funcbox-server/main.go
// builds, minus config-from-env. distDir selects which dist/ the dashboard
// pool serves (testdata/dist's hand-written fixture by default; see
// TestDashboard_RealBuildServesFunctionList for the real-esbuild-output
// variant).
type testEnv struct {
	baseURL string
	store   store.Store
	server  *httptest.Server
	dash    *Server
}

func newTestEnv(t *testing.T, distDir string) *testEnv {
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

	logger := testLogger()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	authSvc, err := auth.New(auth.Config{
		Mode:          auth.ModeDev,
		BaseURL:       srv.URL,
		ListenAddr:    "127.0.0.1:0",
		SessionSecret: testSessionSecret,
	}, st)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	envKey, err := fcrypto.DeriveKey(testSessionSecret, "funcbox:env-vars")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	functions := &service.Functions{Store: st, Runtime: manager, EnvKey: envKey}
	apiHandler := api.New(deployer, functions, st, authSvc, logger)

	dash, err := New(Config{
		Auth:          authSvc,
		API:           apiHandler,
		SessionSecret: testSessionSecret,
		Logger:        logger,
		DistDir:       distDir,
	})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	t.Cleanup(func() { dash.Close() })

	handler := server.New(server.Deps{
		Logger:    logger,
		API:       apiHandler,
		Auth:      authSvc.Routes(),
		DevOIDC:   authSvc.DevRoutes(),
		Dashboard: dash,
	})
	mux.Handle("/", handler)

	return &testEnv{baseURL: srv.URL, store: st, server: srv, dash: dash}
}

// bootstrap creates the organization's first (admin) user directly against
// the store, mirroring e2e_test.go's own helper of the same shape.
func (e *testEnv) bootstrap(t *testing.T) *store.User {
	t.Helper()
	ctx := context.Background()
	admin := &store.User{GoogleSub: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := e.store.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := e.store.Handles().Create(ctx, &store.Handle{Handle: "admin", OwnerType: store.OwnerTypeUser, OwnerID: admin.ID}); err != nil {
		t.Fatalf("Handles().Create: %v", err)
	}
	if err := e.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
	return admin
}

// loginViaHTTP drives the full /auth/login -> dev IdP -> /auth/callback
// flow (identical in spirit to e2e_test.go's helper of the same name),
// returning a cookie-jar-equipped client authenticated as email.
func (e *testEnv) loginViaHTTP(t *testing.T, email string) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(e.baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/login status = %d, want 302", resp.StatusCode)
	}
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	form := url.Values{
		"client_id":    {authorizeURL.Query().Get("client_id")},
		"redirect_uri": {authorizeURL.Query().Get("redirect_uri")},
		"state":        {authorizeURL.Query().Get("state")},
		"nonce":        {authorizeURL.Query().Get("nonce")},
		"email":        {email},
	}
	resp, err = client.PostForm(e.baseURL+"/dev/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST dev authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST dev authorize status = %d, want 302", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")

	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET callback status = %d, want 302 (successful login)", resp.StatusCode)
	}
	return client
}

// --- hosting-path tests (testdata's hand-written fixture; no pnpm needed) ---

func TestDashboard_AssetsServedDirectlyWithoutSession(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	resp, err := http.Get(env.baseURL + "/dashboard/assets/hello.txt")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (assets need no session)", resp.StatusCode)
	}
	if !strings.Contains(string(body), "hello from a content-hashed") {
		t.Errorf("body = %q, want the fixture asset's content", body)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("Cache-Control = %q, want immutable (content-hashed filename)", cc)
	}
}

func TestDashboard_AnonymousRequestRedirectsToLogin(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(env.baseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/auth/login") {
		t.Errorf("Location = %q, want a /auth/login redirect", loc)
	}
}

func TestDashboard_TrailingSlashRedirectsToBarePath(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(env.baseURL + "/dashboard/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", loc)
	}
}

func TestDashboard_AuthenticatedRequestReachesPoolAndInternalAPI(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	env.bootstrap(t)
	client := env.loginViaHTTP(t, "newuser@example.com")

	resp, err := client.Get(env.baseURL + "/dashboard/whoami")
	if err != nil {
		t.Fatalf("GET /dashboard/whoami: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200", resp.StatusCode, body)
	}

	// The fixture's /whoami handler relays env.INTERNAL_API("GET", "/me", ...)
	// verbatim: {"status":200,"body":{... "email": "newuser@example.com" ...}}.
	var result struct {
		Status int `json:"status"`
		Body   struct {
			Email  string `json:"email"`
			Handle string `json:"handle"`
		} `json:"body"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode whoami response: %v (body: %s)", err, body)
	}
	if result.Status != http.StatusOK {
		t.Fatalf("INTERNAL_API GET /me status = %d, want 200", result.Status)
	}
	if result.Body.Email != "newuser@example.com" {
		t.Errorf("me.email = %q, want %q -- the caller identity crossing the host/guest boundary via the signed token is the whole point of this test", result.Body.Email, "newuser@example.com")
	}
	if result.Body.Handle != "newuser" {
		t.Errorf("me.handle = %q, want %q", result.Body.Handle, "newuser")
	}
}

func TestDashboard_ForgedCallerTokenIsRejectedEndToEnd(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	env.bootstrap(t)
	client := env.loginViaHTTP(t, "newuser@example.com")

	// /forge deliberately calls env.INTERNAL_API with a fabricated token
	// instead of the one Go actually injected -- proving that even a guest
	// that can see the binding's call shape cannot manufacture a working
	// identity claim without the HMAC key.
	resp, err := client.Get(env.baseURL + "/dashboard/forge")
	if err != nil {
		t.Fatalf("GET /dashboard/forge: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403 (forged token rejected)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "rejected:") {
		t.Errorf("body = %q, want the guest's catch-block prefix", body)
	}
}

func TestDashboard_NotBuiltShowsClearErrorPage(t *testing.T) {
	env := newTestEnv(t, t.TempDir()) // empty dir: no server.js
	env.bootstrap(t)
	client := env.loginViaHTTP(t, "newuser@example.com")

	resp, err := client.Get(env.baseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	if !strings.Contains(string(body), "make server") {
		t.Errorf("body = %q, want a clear \"run make server\" hint", body)
	}
}

func TestDashboard_ReadyReportsMissingAssets(t *testing.T) {
	env := newTestEnv(t, t.TempDir())
	if err := env.dash.Ready(); err == nil {
		t.Fatal("Ready() = nil, want an error (empty dist dir)")
	}
}

func TestDashboard_ReadyReportsBuiltAssets(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	if err := env.dash.Ready(); err != nil {
		t.Fatalf("Ready() = %v, want nil (testdata/dist has server.js)", err)
	}
}

// --- caller-token unit tests ---

func TestCallerToken_RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	claims := callerClaims{UserID: "u1", Email: "a@example.com", Name: "A", Role: "admin", IssuedAt: time.Now().Unix()}
	tok, err := signCallerToken(key, claims)
	if err != nil {
		t.Fatalf("signCallerToken: %v", err)
	}
	got, err := verifyCallerToken(key, tok)
	if err != nil {
		t.Fatalf("verifyCallerToken: %v", err)
	}
	if got != claims {
		t.Errorf("verifyCallerToken = %+v, want %+v", got, claims)
	}
}

func TestCallerToken_RejectsWrongKey(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	otherKey := []byte("ffffffffffffffffffffffffffffffff")
	tok, err := signCallerToken(key, callerClaims{UserID: "u1", IssuedAt: time.Now().Unix()})
	if err != nil {
		t.Fatalf("signCallerToken: %v", err)
	}
	if _, err := verifyCallerToken(otherKey, tok); err == nil {
		t.Fatal("verifyCallerToken with the wrong key = nil error, want a signature mismatch")
	}
}

func TestCallerToken_RejectsTamperedPayload(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	tok, err := signCallerToken(key, callerClaims{UserID: "u1", Role: "member", IssuedAt: time.Now().Unix()})
	if err != nil {
		t.Fatalf("signCallerToken: %v", err)
	}
	// Swap "member" for "admin" in the token's base64 payload segment by
	// re-signing a DIFFERENT payload with the ORIGINAL signature -- the
	// signature check must fail since it no longer matches this payload.
	forged, err := signCallerToken(key, callerClaims{UserID: "u1", Role: "admin", IssuedAt: time.Now().Unix()})
	if err != nil {
		t.Fatalf("signCallerToken: %v", err)
	}
	forgedPayload, _, _ := strings.Cut(forged, ".")
	_, origSig, _ := strings.Cut(tok, ".")
	tampered := forgedPayload + "." + origSig
	if _, err := verifyCallerToken(key, tampered); err == nil {
		t.Fatal("verifyCallerToken accepted a payload/signature mismatch, want an error")
	}
}

func TestCallerToken_RejectsExpired(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	tok, err := signCallerToken(key, callerClaims{UserID: "u1", IssuedAt: time.Now().Add(-2 * callerTokenTTL).Unix()})
	if err != nil {
		t.Fatalf("signCallerToken: %v", err)
	}
	if _, err := verifyCallerToken(key, tok); err == nil {
		t.Fatal("verifyCallerToken accepted an expired token, want an error")
	}
}

func TestCallerToken_RejectsMalformed(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, bad := range []string{"", "no-dot-here", "not-base64!!!.deadbeef", "e30=.wrongsigformat"} {
		if _, err := verifyCallerToken(key, bad); err == nil {
			t.Errorf("verifyCallerToken(%q) = nil error, want an error", bad)
		}
	}
}

// --- real-build e2e test (tmp/09-dashboard.md §9.6's actual pnpm/esbuild
// pipeline; skipped in short mode or when pnpm isn't on PATH) ---

func TestDashboard_RealBuildServesFunctionList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pnpm build in -short mode")
	}
	pnpmPath, err := exec.LookPath("pnpm")
	if err != nil {
		t.Skip("pnpm not found on PATH; skipping real-build e2e test")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	dashboardDir := filepath.Join(wd, "..", "..", "dashboard")
	if _, err := os.Stat(filepath.Join(dashboardDir, "package.json")); err != nil {
		t.Skipf("dashboard/ not found at %s; skipping", dashboardDir)
	}

	runPnpm := func(args ...string) {
		cmd := exec.Command(pnpmPath, args...)
		cmd.Dir = dashboardDir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("pnpm %v: %v\n%s", args, err, out)
		}
	}
	runPnpm("install", "--frozen-lockfile")
	runPnpm("build")

	distDir := filepath.Join(wd, "dist") // internal/dashboard/dist -- see build.ts's doc comment
	if _, err := os.Stat(filepath.Join(distDir, "server.js")); err != nil {
		t.Fatalf("pnpm build did not produce %s/server.js: %v", distDir, err)
	}

	env := newTestEnv(t, distDir)
	env.bootstrap(t)
	client := env.loginViaHTTP(t, "newuser@example.com")

	resp, err := client.Get(env.baseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200", resp.StatusCode, body)
	}
	html := string(body)
	if !strings.Contains(html, "関数") {
		t.Errorf("body does not contain the function list page's title (関数); got: %s", html)
	}
	if !strings.Contains(html, `class="shell"`) {
		t.Errorf("body does not look like the Operator shell layout; got: %s", html)
	}
}
