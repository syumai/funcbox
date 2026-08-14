package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-spidermonkey/compat/cfworkers"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/browserjar"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/server"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
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
	auth    *auth.Auth
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

	return &testEnv{baseURL: srv.URL, store: st, auth: authSvc, server: srv, dash: dash}
}

// bootstrap creates the organization's first (admin) user directly against
// the store, mirroring e2e_test.go's own helper of the same shape.
func (e *testEnv) bootstrap(t *testing.T) *store.User {
	t.Helper()
	ctx := context.Background()
	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := e.store.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := e.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "admin", InternalUserID: admin.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
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
			UserID string `json:"user_id"`
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
	if result.Body.UserID != "newuser" {
		t.Errorf("me.user_id = %q, want %q", result.Body.UserID, "newuser")
	}
}

// TestDashboard_NotSubjectToInvokeManagerLRUCap is 14.2 Pool LRU's dashboard
// exemption made concrete: the dashboard hosts its OWN cfworkers.Pool
// (Server.pool, built by ensurePool) entirely independently of any
// runtime.Manager -- Config has no Manager field at all, so there is no way
// for cmd/funcbox-server to route the dashboard through the invoke path's
// capped Manager even by accident. This test proves the observable
// consequence: a separate, aggressively-capped runtime.Manager (as
// FUNCBOX_POOL_MAX_FUNCTIONS configures for user functions) evicting many
// pools has zero effect on the dashboard -- it keeps serving on the exact
// same pool instance the whole time, never a cold start.
func TestDashboard_NotSubjectToInvokeManagerLRUCap(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	env.bootstrap(t)
	client := env.loginViaHTTP(t, "newuser@example.com")

	// One authenticated dashboard request to force Server.ensurePool to
	// build (and cache) the dashboard's pool, then record its identity.
	mustWhoami := func() {
		t.Helper()
		resp, err := client.Get(env.baseURL + "/dashboard/whoami")
		if err != nil {
			t.Fatalf("GET /dashboard/whoami: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, body = %s, want 200", resp.StatusCode, body)
		}
	}
	mustWhoami()

	env.dash.mu.Lock()
	firstPool := env.dash.pool
	env.dash.mu.Unlock()
	if firstPool == nil {
		t.Fatal("dashboard pool was not built by the first request")
	}

	// A completely separate runtime.Manager, capped exactly like the
	// invoke path's Manager is under FUNCBOX_POOL_MAX_FUNCTIONS -- driven
	// hard enough to evict repeatedly. Real (tiny, single-instance)
	// cfworkers pools, not fakes, so this is a genuine LRU churn, not a
	// bookkeeping-only exercise.
	var evictions int
	evictedCh := make(chan string, 10)
	mgr := runtime.NewManager(runtime.WithMaxPools(1), runtime.WithEvictHook(func(key string) { evictedCh <- key }))
	t.Cleanup(func() { mgr.Close() })
	buildTinyPool := func(context.Context) (*cfworkers.Pool, error) {
		return cfworkers.NewPool(cfworkers.PoolConfig{
			Size:   1,
			Source: `export default { async fetch(req) { return new Response("ok"); } };`,
		})
	}
	ctx := context.Background()
	const distinctKeys = 5
	for i := 0; i < distinctKeys; i++ {
		key := fmt.Sprintf("unrelated-function-version-%d", i)
		if _, err := mgr.HandlerFor(ctx, runtime.VersionSpec{Key: key, Build: buildTinyPool}); err != nil {
			t.Fatalf("mgr.HandlerFor(%q): %v", key, err)
		}
	}
	// cap=1 evicts on every insert past the first, so distinctKeys-1
	// evictions should have fired (or be about to -- eviction runs on a
	// background goroutine per HandlerFor's doc comment).
	for i := 0; i < distinctKeys-1; i++ {
		select {
		case <-evictedCh:
			evictions++
		case <-time.After(2 * time.Second):
			t.Fatalf("only observed %d/%d expected evictions from the unrelated Manager", evictions, distinctKeys-1)
		}
	}

	// The dashboard must still be serving through the SAME pool instance
	// it built before the unrelated Manager's churn -- untouched by it.
	mustWhoami()
	env.dash.mu.Lock()
	secondPool := env.dash.pool
	env.dash.mu.Unlock()
	if secondPool != firstPool {
		t.Fatal("dashboard's pool changed after an unrelated, LRU-capped runtime.Manager evicted pools -- the dashboard must never be subject to FUNCBOX_POOL_MAX_FUNCTIONS")
	}
}

// TestDashboard_PendingUserSeesRequestPendingPage covers §13.3's "申請中画
// 面のみ" experience: a pending user's session authenticates fine (a
// normal /auth/login round trip succeeds), but EVERY /dashboard/* route --
// not just "/dashboard" itself -- must render the Go-rendered "access
// request pending" page (server.go's writePendingApprovalPage) instead of
// ever reaching the guest pool, and must never invoke env.INTERNAL_API
// (checked here by asserting the response is NOT the fixture's normal
// output, which would only appear if the pool actually ran).
//
// Also covers item 2 of the auth-pages styling work: the page renders in
// ONLY the organization's default language (settings.Org.Language), not the
// old bilingual English+Japanese stack -- default/en organizations see
// English text and no Japanese, ja organizations see Japanese text and no
// English.
func TestDashboard_PendingUserSeesRequestPendingPage(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		orgLanguage           string // "" leaves the org language at its default (en)
		wantText, wantNotText string
	}{
		{name: "default org language renders English only", orgLanguage: "", wantText: "Access request pending", wantNotText: "アクセスリクエスト申請中"},
		{name: "ja org language renders Japanese only", orgLanguage: "ja", wantText: "アクセスリクエスト申請中", wantNotText: "Access request pending"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, filepath.Join("testdata", "dist"))
			env.bootstrap(t)

			ctx := context.Background()
			if err := env.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
				{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
				{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
			}); err != nil {
				t.Fatalf("ReplaceLoginRules: %v", err)
			}
			if tc.orgLanguage != "" {
				setOrgLanguage(t, env, tc.orgLanguage)
			}

			client := env.loginViaHTTP(t, "pending@example.com")
			// loginViaHTTP creates the user active (require_approval was off at
			// login time); flip it to pending directly against the store, exactly
			// as if require_approval had been on -- this test is about the
			// dashboard's RENDERING of the pending state, not auth's assignment of
			// it (see server/internal/auth/approval_test.go for that).
			u, err := env.store.Users().ByEmail(ctx, "pending@example.com")
			if err != nil {
				t.Fatalf("Users().ByEmail: %v", err)
			}
			requestedAt := u.CreatedAt
			u.Status = store.UserStatusPending
			if err := env.store.Users().Update(ctx, u); err != nil {
				t.Fatalf("Users().Update: %v", err)
			}

			for _, path := range []string{"/dashboard", "/dashboard/workspaces", "/dashboard/org", "/dashboard/whoami"} {
				resp, err := client.Get(env.baseURL + path)
				if err != nil {
					t.Fatalf("GET %s: %v", path, err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("GET %s status = %d, body = %s, want 200 (the pending page itself, not an error)", path, resp.StatusCode, body)
				}
				html := string(body)
				if !strings.Contains(html, "pending@example.com") {
					t.Errorf("GET %s body missing the account identity; got: %s", path, html)
				}
				if !strings.Contains(html, requestedAt.UTC().Format("2006-01-02")) {
					t.Errorf("GET %s body missing the request date; got: %s", path, html)
				}
				if !strings.Contains(html, tc.wantText) {
					t.Errorf("GET %s body missing expected %q; got: %s", path, tc.wantText, html)
				}
				if strings.Contains(html, tc.wantNotText) {
					t.Errorf("GET %s body unexpectedly contains %q (single-language rendering must not leak the other language); got: %s", path, tc.wantNotText, html)
				}
				// The fixture's normal pages (e.g. /dashboard/whoami's INTERNAL_API
				// relay) would contain this marker; its absence is evidence the
				// pool was never invoked for this pending user.
				if strings.Contains(html, `"status":200`) {
					t.Errorf("GET %s looks like it reached the guest pool (INTERNAL_API response leaked through) instead of the pending page; got: %s", path, html)
				}
			}
		})
	}
}

// setOrgLanguage sets the (already-bootstrapped) organization's
// settings.Org.Language directly against the store -- a lighter-weight
// alternative to a PATCH /api/v1/org round trip for tests that only care
// about its downstream effect on a Go-rendered page's language.
func setOrgLanguage(t *testing.T, env *testEnv, language string) {
	t.Helper()
	ctx := context.Background()
	org, err := env.store.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		t.Fatalf("settings.ParseOrg: %v", err)
	}
	orgSet.Language = language
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := env.store.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}
}

// TestDashboard_DeniedLoginShowsErrorPageInsteadOfLooping is the regression
// test for a reported bug: a login rejected by internal/auth (here, an
// email the organization's login rules don't permit) redirects to
// /dashboard?login_error=... (login.go's loginFailed) -- but the browser at
// that point is still anonymous (login never got far enough to set a
// session cookie), so the dashboard's own anonymous-request handling used
// to unconditionally redirect straight into /auth/login again, discarding
// the message and immediately restarting the sign-in flow. From the user's
// point of view that's indistinguishable from a silent infinite loop with
// no explanation. It must instead render a clear error page.
//
// Also covers item 2 of the auth-pages styling work (see
// TestDashboard_PendingUserSeesRequestPendingPage's doc comment): the page
// renders in ONLY the organization's default language, not the old
// bilingual stack.
func TestDashboard_DeniedLoginShowsErrorPageInsteadOfLooping(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		orgLanguage           string // "" leaves the org language at its default (en)
		wantText, wantNotText string
	}{
		{name: "default org language renders English only", orgLanguage: "", wantText: "Sign-in failed", wantNotText: "サインインに失敗しました"},
		{name: "ja org language renders Japanese only", orgLanguage: "ja", wantText: "サインインに失敗しました", wantNotText: "Sign-in failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, filepath.Join("testdata", "dist"))
			env.bootstrap(t) // seeds [email_domain example.com allow, default deny]
			if tc.orgLanguage != "" {
				setOrgLanguage(t, env, tc.orgLanguage)
			}

			client := &http.Client{Jar: mustCookieJar(t), CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

			resp, err := client.Get(env.baseURL + "/auth/login")
			if err != nil {
				t.Fatalf("GET /auth/login: %v", err)
			}
			resp.Body.Close()
			authorizeURL, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			form := url.Values{
				"client_id": {authorizeURL.Query().Get("client_id")}, "redirect_uri": {authorizeURL.Query().Get("redirect_uri")},
				"state": {authorizeURL.Query().Get("state")}, "nonce": {authorizeURL.Query().Get("nonce")},
				"email": {"mallory@evil.example"}, // not permitted by the seeded login rules
			}
			resp, err = client.PostForm(env.baseURL+"/dev/oidc/authorize", form)
			if err != nil {
				t.Fatalf("POST dev authorize: %v", err)
			}
			resp.Body.Close()
			callbackURL := resp.Header.Get("Location")

			resp, err = client.Get(callbackURL)
			if err != nil {
				t.Fatalf("GET callback: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("GET callback status = %d, want 302 (denied login redirects with login_error)", resp.StatusCode)
			}
			loginErrorURL := resp.Header.Get("Location")
			if !strings.Contains(loginErrorURL, "login_error=") {
				t.Fatalf("callback redirect = %q, want it to carry login_error=", loginErrorURL)
			}

			// The browser is still anonymous at this point -- no session cookie was
			// ever set for a denied login. Following the redirect must render the
			// error directly, NOT bounce back into another /auth/login round trip.
			resp, err = client.Get(env.baseURL + loginErrorURL)
			if err != nil {
				t.Fatalf("GET %s: %v", loginErrorURL, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s status = %d, body = %s, want 200 (an error page, not another redirect)", loginErrorURL, resp.StatusCode, body)
			}
			html := string(body)
			if !strings.Contains(html, tc.wantText) {
				t.Errorf("body missing expected %q; got: %s", tc.wantText, html)
			}
			if strings.Contains(html, tc.wantNotText) {
				t.Errorf("body unexpectedly contains %q (single-language rendering must not leak the other language); got: %s", tc.wantNotText, html)
			}
			if !strings.Contains(html, "not permitted to sign in") {
				t.Errorf("body does not surface the actual denial reason; got: %s", html)
			}

			if _, err := env.store.Users().ByEmail(context.Background(), "mallory@evil.example"); err == nil {
				t.Error("a login-rule-denied signup must not create a user record")
			}
		})
	}
}

// TestDashboard_ApprovalFlow_LoginPendingApproveDashboard is the browser-
// faithful (browserjar) end-to-end coverage for §13.3's account-approval
// mode requested alongside the Bug #4 investigation: with require_approval
// on and the org's existing login rules already permitting the new email
// (default-allow domain rule, unrelated to require_approval), a brand-new
// user's login must still succeed (a session IS issued) and every
// /dashboard/* request for that session must render the Go-rendered
// "access request pending" page -- NOT loop back to /auth/login -- until an
// admin approves them, at which point the SAME session immediately reaches
// the real dashboard with no further action from the user.
func TestDashboard_ApprovalFlow_LoginPendingApproveDashboard(t *testing.T) {
	env := newTestEnv(t, filepath.Join("testdata", "dist"))
	env.bootstrap(t) // seeds [email_domain example.com allow, default deny] -- new @example.com signups are already permitted

	adminToken := mintAPIToken(t, env, "admin")
	orgResp := apiRequest(t, env, http.MethodPatch, "/api/v1/org", adminToken, `{"require_approval":true}`)
	orgBody, _ := io.ReadAll(orgResp.Body)
	orgResp.Body.Close()
	if orgResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /api/v1/org require_approval=true status = %d, body = %s", orgResp.StatusCode, orgBody)
	}

	// browserjar.New, not net/http/cookiejar: the session cookie this login
	// depends on is "__Host-" prefixed over this httptest server's plain-http
	// origin (secureCookies() false), which a real browser would refuse to
	// store without Secure -- see browserjar's doc comment and
	// loginViaHTTP's, which this drives by hand instead of reusing (that
	// helper asserts a 302-to-/dashboard on the callback and doesn't apply
	// here quite as cleanly since we want to inspect the pending page next).
	client := &http.Client{Jar: browserjar.New(), CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(env.baseURL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	const newEmail = "newpending@example.com"
	form := url.Values{
		"client_id": {authorizeURL.Query().Get("client_id")}, "redirect_uri": {authorizeURL.Query().Get("redirect_uri")},
		"state": {authorizeURL.Query().Get("state")}, "nonce": {authorizeURL.Query().Get("nonce")},
		"email": {newEmail},
	}
	resp, err = client.PostForm(env.baseURL+"/dev/oidc/authorize", form)
	if err != nil {
		t.Fatalf("POST dev authorize: %v", err)
	}
	resp.Body.Close()
	callbackURL := resp.Header.Get("Location")

	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/dashboard" {
		t.Fatalf("callback status/location = %d %q, want 302 to /dashboard (login must succeed even though the new user is pending, §13.3)", resp.StatusCode, resp.Header.Get("Location"))
	}

	u, err := env.store.Users().ByEmail(context.Background(), newEmail)
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	if u.Status != store.UserStatusPending {
		t.Fatalf("new user's status = %q, want %q", u.Status, store.UserStatusPending)
	}

	pendingResp, err := client.Get(env.baseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard (pending): %v", err)
	}
	pendingBody, _ := io.ReadAll(pendingResp.Body)
	pendingResp.Body.Close()
	if pendingResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /dashboard (pending) status = %d, body = %s, want 200 (the pending page itself -- not a redirect/loop)", pendingResp.StatusCode, pendingBody)
	}
	if !strings.Contains(string(pendingBody), newEmail) || !strings.Contains(strings.ToLower(string(pendingBody)), "pending") {
		t.Fatalf("GET /dashboard (pending) body does not look like the pending page; got: %s", pendingBody)
	}

	// Admin approves: PATCH status -> active.
	approveResp := apiRequest(t, env, http.MethodPatch, "/api/v1/org/users/"+u.ID, adminToken, `{"status":"active"}`)
	approveBody, _ := io.ReadAll(approveResp.Body)
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d, body = %s", approveResp.StatusCode, approveBody)
	}

	// The SAME session, no re-login: the next request already reaches the
	// real dashboard pool instead of the pending page.
	afterResp, err := client.Get(env.baseURL + "/dashboard/whoami")
	if err != nil {
		t.Fatalf("GET /dashboard/whoami (approved): %v", err)
	}
	afterBody, _ := io.ReadAll(afterResp.Body)
	afterResp.Body.Close()
	if afterResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /dashboard/whoami (approved) status = %d, body = %s, want 200 (dashboard reachable immediately after approval)", afterResp.StatusCode, afterBody)
	}
	if !strings.Contains(string(afterBody), `"status":200`) {
		t.Fatalf("GET /dashboard/whoami (approved) body does not look like the fixture's normal INTERNAL_API relay (still on the pending page?); got: %s", afterBody)
	}
}

func mustCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return jar
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

// pipeline; skipped in short mode or when pnpm isn't on PATH) ---
//
// TestDashboard_RealBuildServesFunctionList keeps its original name (the
// function list is still its first assertion) but now covers the whole
// authenticated SSR surface against a REAL esbuild-produced dist/server.js,
// not just the list: both a user-owned and a workspace-owned function's
// detail page (reached via the list page's OWN rendered links, not a
// hand-typed URL -- see functionDTOsWithOwners's doc comment in
// internal/api/functions.go for the bug this specifically guards against),
// and the personal-settings page's "connected devices" section (§14.4;
// every field labeled, a seeded device listed, and a revoke round trip).
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
	if !strings.Contains(html, "Functions") {
		t.Errorf("body does not contain the function list page's title (Functions); got: %s", html)
	}
	if !strings.Contains(html, `class="shell"`) {
		t.Errorf("body does not look like the Operator shell layout; got: %s", html)
	}
	if !strings.Contains(html, `<html lang="en">`) {
		t.Errorf("default dashboard document language is not English; got: %s", html)
	}

	// Organization language changes apply to users without a personal
	// preference. A personal choice then takes precedence over that default.
	orgLanguageResp := apiRequest(t, env, http.MethodPatch, "/api/v1/org", mintAPIToken(t, env, "admin"), `{"language":"ja"}`)
	orgLanguageResp.Body.Close()
	if orgLanguageResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH organization language status = %d, want 200", orgLanguageResp.StatusCode)
	}
	jaResp, err := client.Get(env.baseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard with organization Japanese: %v", err)
	}
	jaBody, _ := io.ReadAll(jaResp.Body)
	jaResp.Body.Close()
	if jaResp.StatusCode != http.StatusOK || !strings.Contains(string(jaBody), `<html lang="ja">`) || !strings.Contains(string(jaBody), "関数") {
		t.Fatalf("organization Japanese dashboard = (%d, %s), want Japanese", jaResp.StatusCode, jaBody)
	}
	personalLanguageResp := apiRequest(t, env, http.MethodPatch, "/api/v1/me", mintAPIToken(t, env, "newuser"), `{"language":"en"}`)
	personalLanguageResp.Body.Close()
	if personalLanguageResp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH personal language status = %d, want 200", personalLanguageResp.StatusCode)
	}
	personalResp, err := client.Get(env.baseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard with personal English: %v", err)
	}
	personalBody, _ := io.ReadAll(personalResp.Body)
	personalResp.Body.Close()
	if personalResp.StatusCode != http.StatusOK || !strings.Contains(string(personalBody), `<html lang="en">`) || !strings.Contains(string(personalBody), "Functions") {
		t.Fatalf("personal English dashboard = (%d, %s), want English", personalResp.StatusCode, personalBody)
	}

	// --- function DETAIL pages, for both a user-owned and a
	// workspace-owned function, reached via the SAME link the list page
	// itself renders (not a hand-typed URL) --
	//
	// This is a regression test for a real bug: GET /api/v1/functions
	// (no ?owner=) -- the call the dashboard's OWN function list makes --
	// used to omit "owner" from every function it returned (see
	// internal/api/functions.go's functionDTOsWithOwners doc comment), so
	// every row's "詳細" link rendered as
	// /dashboard/functions//{name} (an empty owner segment). Hono's
	// :owner/:name route never matches that, so clicking the link 404'd
	// with "funcbox dashboard: not found" -- the function detail page
	// "did not display" exactly as reported, even though hand-typing the
	// correct /dashboard/functions/{owner}/{name} URL worked fine (which
	// is why a test that only ever constructs the URL itself, rather than
	// following the list's own link, would miss this).
	token := mintAPIToken(t, env, "newuser")
	deployHello(t, env, token, "newuser") // personal (user-owned)

	// Workspace creation (§14.1) is admin/workspace_manager only; promote
	// newuser directly against the store (there's no API for a member to
	// grant themselves a role) so it can create "Acme" below purely to
	// get a workspace-owned function for this test's real subject -- the
	// function detail page link regression above.
	promoteToWorkspaceManager(t, env, "newuser")

	wsResp := apiRequest(t, env, http.MethodPost, "/api/v1/workspaces", token, `{"name":"Acme"}`)
	if wsResp.StatusCode != http.StatusCreated {
		t.Fatalf("create workspace status = %d", wsResp.StatusCode)
	}
	var workspace struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(wsResp.Body).Decode(&workspace); err != nil {
		t.Fatalf("decode workspace: %v", err)
	}
	deployHello(t, env, token, workspace.ID) // workspace-owned

	listResp, err := client.Get(env.baseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard (with functions): %v", err)
	}
	listBody, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	listHTML := string(listBody)
	if strings.Contains(listHTML, `functions//hello`) {
		t.Fatalf("list page links to an empty-owner function detail URL (functions//hello); got: %s", listHTML)
	}
	for _, want := range []string{
		`href="/dashboard/functions/newuser/hello"`,
		`href="/dashboard/functions/` + workspace.ID + `/workspace-hello"`,
	} {
		if !strings.Contains(listHTML, want) {
			t.Errorf("list page missing detail link %q; got: %s", want, listHTML)
		}
	}

	for _, tc := range []struct {
		owner    string
		wantPill string
	}{
		{owner: "newuser", wantPill: `class="pill pub"`},   // personal/user-owned
		{owner: workspace.ID, wantPill: `class="pill ws"`}, // workspace-owned
	} {
		name := "hello"
		if tc.owner == workspace.ID {
			name = "workspace-hello"
		}
		detailResp, err := client.Get(env.baseURL + "/dashboard/functions/" + tc.owner + "/" + name)
		if err != nil {
			t.Fatalf("GET detail page for %s: %v", tc.owner, err)
		}
		detailBody, _ := io.ReadAll(detailResp.Body)
		detailResp.Body.Close()
		if detailResp.StatusCode != http.StatusOK {
			t.Fatalf("detail page for %s status = %d, body = %s, want 200", tc.owner, detailResp.StatusCode, detailBody)
		}
		detailHTML := string(detailBody)
		if !strings.Contains(detailHTML, tc.wantPill) {
			t.Errorf("detail page for %s missing owner-type pill %q; got: %s", tc.owner, tc.wantPill, detailHTML)
		}
		if !strings.Contains(detailHTML, "Effective fetch policy") {
			t.Errorf("detail page for %s missing the fetch-policy panel; got: %s", tc.owner, detailHTML)
		}
		// Regression check: the page used to render the function's name as
		// a heading TWICE -- once from Page's own title <h4> (props.title),
		// once more from a second, separate <h4> the detail route rendered
		// itself right after it (routes/functions.tsx) purely to sit the
		// owner-type/compat pills next to the name. There must be exactly
		// ONE <h4>, and it must carry both the name and the pill together
		// (titleExtra), not two headings side by side.
		if got := strings.Count(detailHTML, "<h4>"); got != 1 {
			t.Errorf("detail page for %s has %d <h4> elements, want exactly 1 (duplicate title heading); got: %s", tc.owner, got, detailHTML)
		}
		if idx := strings.Index(detailHTML, "<h4>"); idx >= 0 {
			end := strings.Index(detailHTML[idx:], "</h4>")
			if end < 0 {
				t.Fatalf("detail page for %s has an unterminated <h4>; got: %s", tc.owner, detailHTML)
			}
			h4 := detailHTML[idx : idx+end]
			if !strings.Contains(h4, name) || !strings.Contains(h4, tc.wantPill) {
				t.Errorf("detail page for %s's single <h4> does not contain both the name %q and the pill %q; got: %s", tc.owner, name, tc.wantPill, h4)
			}
		}
	}

	// --- /dashboard/settings: every field labeled, the "connected
	// devices" section explained (§14.4 -- devices replace API tokens),
	// and a revoke round trip ---
	settingsResp, err := client.Get(env.baseURL + "/dashboard/settings")
	if err != nil {
		t.Fatalf("GET /dashboard/settings: %v", err)
	}
	settingsBody, _ := io.ReadAll(settingsResp.Body)
	settingsResp.Body.Close()
	settingsHTML := string(settingsBody)
	for _, want := range []string{
		`<label for="settings-user-id"`, // User ID field has a real <label>
		"Connected devices",             // the devices section heading is present
		"funcbox login",                 // the CLI-usage explanation is present
	} {
		if !strings.Contains(settingsHTML, want) {
			t.Errorf("settings page missing %q; got: %s", want, settingsHTML)
		}
	}

	// Devices are only ever created by the real loopback+PKCE login flow
	// (see TestE2E_CLILoginFullFlow at the top-level e2e suite for that),
	// not a dashboard form -- seed one directly against the store, exactly
	// like mintAPIToken does for an access token, to exercise the
	// list -> revoke round trip this page provides.
	newuserID, err := env.store.PublicUserIDs().ByUserID(context.Background(), "newuser")
	if err != nil {
		t.Fatalf("look up User ID newuser: %v", err)
	}
	cred := &store.CLICredential{UserID: newuserID.InternalUserID, Name: "e2e-test-device", SecretHash: "unused-hash-for-listing-only"}
	if err := env.store.CLICredentials().Create(context.Background(), cred); err != nil {
		t.Fatalf("CLICredentials().Create: %v", err)
	}

	devicesResp, err := client.Get(env.baseURL + "/dashboard/settings")
	if err != nil {
		t.Fatalf("GET /dashboard/settings (with a device): %v", err)
	}
	devicesBody, _ := io.ReadAll(devicesResp.Body)
	devicesResp.Body.Close()
	devicesHTML := string(devicesBody)
	if !strings.Contains(devicesHTML, "e2e-test-device") {
		t.Errorf("settings page does not list the seeded device; got: %s", devicesHTML)
	}

	revokePath := fmt.Sprintf("/dashboard/settings/devices/%s/delete", cred.ID)
	if !strings.Contains(devicesHTML, revokePath) {
		t.Fatalf("no revoke form found for device %s on settings page; got: %s", cred.ID, devicesHTML)
	}
	revokeResp, err := client.PostForm(env.baseURL+revokePath, url.Values{})
	if err != nil {
		t.Fatalf("POST %s: %v", revokePath, err)
	}
	revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke status = %d, want 303", revokeResp.StatusCode)
	}

	afterRevokeResp, err := client.Get(env.baseURL + "/dashboard/settings")
	if err != nil {
		t.Fatalf("GET /dashboard/settings after revoke: %v", err)
	}
	afterRevokeBody, _ := io.ReadAll(afterRevokeResp.Body)
	afterRevokeResp.Body.Close()
	if strings.Contains(string(afterRevokeBody), "e2e-test-device") {
		t.Errorf("revoked device still listed after revoke; got: %s", afterRevokeBody)
	}
}

// promoteToWorkspaceManager sets owner's user directly to
// store.RoleWorkspaceManager against the store, bypassing the API (a
// member has no self-service way to grant themselves a role; only an org
// admin can via PATCH /api/v1/org/users/{id}, which this sidesteps as a
// test convenience).
func promoteToWorkspaceManager(t *testing.T, env *testEnv, owner string) {
	t.Helper()
	ctx := context.Background()
	id, err := env.store.PublicUserIDs().ByUserID(ctx, owner)
	if err != nil {
		t.Fatalf("look up User ID %s: %v", owner, err)
	}
	u, err := env.store.Users().ByID(ctx, id.InternalUserID)
	if err != nil {
		t.Fatalf("look up user %s: %v", owner, err)
	}
	u.Role = store.RoleWorkspaceManager
	if err := env.store.Users().Update(ctx, u); err != nil {
		t.Fatalf("promote %s to workspace_manager: %v", owner, err)
	}
}

// mintAPIToken mints a real access token (§14.5) for the owner's user (a
// public User ID already provisioned, e.g. by loginViaHTTP), signed
// directly via the Auth service rather than going through the CLI's full
// loopback+PKCE login + credential-exchange flow -- used here purely as a
// deploy/management-API credential.
func mintAPIToken(t *testing.T, env *testEnv, owner string) string {
	t.Helper()
	ctx := context.Background()
	id, err := env.store.PublicUserIDs().ByUserID(ctx, owner)
	if err != nil {
		t.Fatalf("look up User ID %s: %v", owner, err)
	}
	token, _, err := env.auth.IssueAccessToken(ctx, id.InternalUserID, 0)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	return token
}

// deployHello packs testdata/hello (a personal-or-workspace-agnostic
// fixture: the owner argument decides which) and POSTs it to
// /api/v1/functions as owner, authenticated with token.
func deployHello(t *testing.T, env *testEnv, token, owner string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	testdataDir := filepath.Join(wd, "..", "..", "..", "testdata", "hello")
	files := map[string][]byte{}
	for _, name := range []string{"funcbox.yaml", "index.js", filepath.Join("lib", "x.js")} {
		data, err := os.ReadFile(filepath.Join(testdataDir, name))
		if err != nil {
			t.Fatalf("read testdata/hello/%s: %v", name, err)
		}
		files[filepath.ToSlash(name)] = data
	}
	// Global function names are first-claim-wins, so the workspace fixture
	// must not reuse the personal fixture's "hello" name.
	if strings.HasPrefix(owner, "01") {
		files["funcbox.yaml"] = bytes.Replace(files["funcbox.yaml"], []byte("name: hello"), []byte("name: workspace-hello"), 1)
	}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="bundle"; filename="bundle.tar.gz"`)
	h.Set("Content-Type", "application/gzip")
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := pw.Write(packed); err != nil {
		t.Fatalf("write bundle part: %v", err)
	}
	_ = mw.WriteField("owner", owner)
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, env.baseURL+"/api/v1/functions", &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("deploy request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy(%s) status = %d, body = %s", owner, resp.StatusCode, body)
	}
}

// apiRequest issues a bearer-authenticated JSON request against the
// management API, for setup calls (like workspace creation) this file's
// real-build e2e test needs but that don't warrant their own named helper.
func apiRequest(t *testing.T, env *testEnv, method, path, token, jsonBody string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, env.baseURL+path, strings.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}
