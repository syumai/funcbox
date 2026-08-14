// e2e_loopbackalias_test.go is a failing-first regression test for the
// loopback-alias login bug: a real deployment runs with, say,
// FUNCBOX_BASE_URL=http://127.0.0.1:8093 (the only host that appears in
// every OAuth redirect_uri and, in dev mode, the stub issuer URL --
// internal/auth's provider.go/config.go), but a user opens the dashboard
// at http://localhost:8093 instead -- localhost and 127.0.0.1 both reach
// the same loopback interface, but a browser treats them as two
// completely separate cookie origins. Before internal/server's
// canonicalOriginMiddleware (middleware.go), the OAuth state cookie
// /auth/login set on "localhost" was invisible to /auth/callback once the
// identity provider's redirect_uri bounced the browser to "127.0.0.1",
// producing "missing OAuth state cookie (it may have expired -- try
// logging in again)" on an otherwise perfectly valid login. This is
// exactly funcbox login's own real-world trigger: `funcbox login` opens
// the browser at ".../dashboard/cli-auth?...", the server's
// FUNCBOX_BASE_URL says one loopback alias, and the CLI's own "server:"
// config or a user's typed URL says another.
//
// This env deliberately configures ONLY BaseURL (no FUNCBOX_CONTROL_URL /
// FUNCBOX_FUNCTION_DOMAIN) -- config.Config.FromEnv's common, legacy
// single-origin/path-routed shape (the README quick-start's own
// FUNCBOX_BASE_URL=http://127.0.0.1:... with nothing else set), which is
// the exact configuration the bug report reproduced against. There is no
// real network here: like e2e_hostrouting_test.go, every request --
// including go-oidc's own server-side discovery/token HTTP calls -- is
// routed straight to the in-process top-level http.Handler via
// handlerTransport (defined in e2e_hostrouting_test.go, this same
// package), using the SAME literal port for both the "localhost" and
// "127.0.0.1" authorities so http.Client's cookiejar keeps their cookies
// exactly as separate as two real loopback aliases would, without any
// actual socket I/O.
package funcbox_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/browserjar"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/dashboard"
	"github.com/syumai/funcbox/server/internal/invoke"
	"github.com/syumai/funcbox/server/internal/server"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

// loopbackAliasBaseURL is this file's canonical control origin -- the
// stand-in for a real deployment's FUNCBOX_BASE_URL. The port is never
// actually dialed (handlerTransport bypasses the network entirely), so it
// only needs to be internally consistent across every URL this file
// builds.
const loopbackAliasBaseURL = "http://127.0.0.1:8093"

// loopbackAliasEnv is this file's counterpart to e2e_test.go's testEnv /
// e2e_hostrouting_test.go's hostRoutedEnv: a fully-wired funcbox-server
// instance (including the real internal/dashboard, whose anonymous-visit
// session gate is exactly what a real `funcbox login` browser tab hits
// first) configured with BaseURL alone -- no ControlURL/FunctionDomain --
// matching the bug report's exact configuration.
type loopbackAliasEnv struct {
	handler http.Handler
	store   store.Store
	auth    *auth.Auth
	ctx     context.Context // oidc.ClientContext-wrapped, see hostRoutedEnv.ctx's doc comment
}

func newLoopbackAliasEnv(t *testing.T) *loopbackAliasEnv {
	t.Helper()

	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	blobStore, err := blobfs.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobfs.New: %v", err)
	}

	manager := runtime.NewManager()
	t.Cleanup(func() { manager.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	authSvc, err := auth.New(auth.Config{
		Mode:          auth.ModeDev,
		BaseURL:       loopbackAliasBaseURL,
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

	invoker := &invoke.Invoker{
		Store: st, Blob: blobStore, Manager: manager,
		Logger: logger, Timeout: 10 * time.Second, Auth: authSvc, EnvKey: envKey,
	}

	// internal/dashboard.New does NOT require dist/server.js to actually
	// be built (see its own doc comment): the anonymous-visit session
	// gate this file's tests rely on (server.go's ServeHTTP, redirect to
	// /auth/login) runs BEFORE the built-assets pool is ever touched, so
	// this works whether or not `make server`'s dashboard build has run
	// in this checkout.
	dashboardSrv, err := dashboard.New(dashboard.Config{
		Auth: authSvc, API: apiHandler, SessionSecret: testSessionSecret, Logger: logger,
	})
	if err != nil {
		t.Fatalf("dashboard.New: %v", err)
	}
	t.Cleanup(func() { dashboardSrv.Close() })

	handler := server.New(server.Deps{
		Logger: logger, API: apiHandler, Invoker: invoker,
		Auth: authSvc.Routes(), DevOIDC: authSvc.DevRoutes(), Dashboard: dashboardSrv,
		// Deliberately no ControlURL/FunctionDomain: the legacy,
		// single-origin path router, driven purely by BaseURL -- see this
		// file's package doc comment.
		BaseURL: loopbackAliasBaseURL,
	})

	env := &loopbackAliasEnv{handler: handler, store: st, auth: authSvc}
	env.ctx = oidc.ClientContext(context.Background(), &http.Client{Transport: handlerTransport{handler}})
	env.bootstrap(t)
	return env
}

// bootstrap creates the organization's first (admin) user directly
// against the store and a login rule wide enough for a fresh identity
// logging in over the real HTTP flow below (e.g. "clitester@example.com")
// to succeed without an admin-issued rule change first -- the identical
// pattern e2e_test.go's testEnv.bootstrap and e2e_hostrouting_test.go's
// hostRoutedEnv.bootstrap both use.
func (e *loopbackAliasEnv) bootstrap(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := e.store.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := e.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "admin-user", InternalUserID: admin.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create(admin): %v", err)
	}
	if err := e.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
}

// newClient returns a fresh cookie-jar-equipped client wired through
// handlerTransport, redirects NOT auto-followed -- every hop below is
// inspected (and its Host asserted on) explicitly. browserjar.New (not
// net/http/cookiejar) matches e2e_test.go's loginViaHTTP: irrelevant to
// THIS bug (loopbackAliasBaseURL is plain http, so cookies here are never
// __Host--prefixed), but keeps this file's client behavior identical to
// every other real-HTTP-login test in this package.
func (e *loopbackAliasEnv) newClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{
		Jar:           browserjar.New(),
		Transport:     handlerTransport{e.handler},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (e *loopbackAliasEnv) do(t *testing.T, client *http.Client, method, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	return resp
}

// doOIDC is do, but carries e.ctx so server-side code handling the
// request (handleLogin's provider discovery, handleCallback's token
// exchange -- internal/auth's provider.go) can make its OWN further
// outbound HTTP calls back into this same in-process handler. See
// hostRoutedEnv.doOIDC's doc comment (e2e_hostrouting_test.go) for why
// this must be a separate, narrowly-used method.
func (e *loopbackAliasEnv) doOIDC(t *testing.T, client *http.Client, method, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(e.ctx, method, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	return resp
}

// devLogin is hostRoutedEnv.devLogin (e2e_hostrouting_test.go), adapted
// to post against whatever origin authorizeURL itself names (this file's
// flow crosses from "localhost" to "127.0.0.1" partway through, unlike
// hostRoutedEnv's fixed testControlOrigin).
func (e *loopbackAliasEnv) devLogin(t *testing.T, client *http.Client, authorizeURL, email string) string {
	t.Helper()
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize URL %q: %v", authorizeURL, err)
	}
	origin := u.Scheme + "://" + u.Host
	form := url.Values{
		"client_id":    {u.Query().Get("client_id")},
		"redirect_uri": {u.Query().Get("redirect_uri")},
		"state":        {u.Query().Get("state")},
		"nonce":        {u.Query().Get("nonce")},
		"email":        {email},
	}
	req, err := http.NewRequest(http.MethodPost, origin+"/dev/oidc/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest(POST /dev/oidc/authorize): %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /dev/oidc/authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /dev/oidc/authorize status = %d, body = %s", resp.StatusCode, body)
	}
	return resolveLocation(origin+"/dev/oidc/authorize", resp.Header.Get("Location"))
}

// TestE2E_LoopbackAliasLoginRedirect_NormalizesAndCompletesFullFlow drives
// the EXACT bug report scenario -- funcbox login opening the browser at
// http://localhost:PORT/dashboard/cli-auth while the server's own
// FUNCBOX_BASE_URL says http://127.0.0.1:PORT -- against the real,
// unmodified server.New. Before canonicalOriginMiddleware existed, this
// test failed at the /auth/callback hop with exactly the reported
// "missing OAuth state cookie (it may have expired -- try logging in
// again)" error (verified by temporarily reverting middleware.go's
// wiring and re-running this test -- see this change's commit history /
// PR description for that failing-run output). With the fix, the first
// hop instead normalizes the "localhost" alias to the canonical
// "127.0.0.1" origin BEFORE the dashboard's session gate, the OAuth state
// cookie, or anything else in the flow ever runs, so the login round trip
// completes cleanly. It then drives the CLI-auth
// approve -> loopback-callback exchange to completion too (POST
// /api/v1/cli/authorize with the session+CSRF cookies the login just
// produced -- the same session-authenticated call the dashboard's real
// /dashboard/cli-auth/approve form makes, per internal/auth/cliauth.go's
// doc comment -- then the unauthenticated POST /api/v1/cli/token a CLI's
// own loopback listener would make), proving the ENTIRE `funcbox login`
// flow this bug broke now works end to end.
func TestE2E_LoopbackAliasLoginRedirect_NormalizesAndCompletesFullFlow(t *testing.T) {
	env := newLoopbackAliasEnv(t)
	client := env.newClient(t)

	verifier, challenge := cliPKCEPair(t)
	redirectParam := url.QueryEscape("http://127.0.0.1:54321/callback")
	cliAuthURL := "http://localhost:8093/dashboard/cli-auth?redirect=" + redirectParam + "&challenge=" + challenge + "&name=laptop"

	// Hop 1: anonymous GET on the "localhost" alias -> the FIX: a 302
	// that normalizes straight to the canonical "127.0.0.1" origin,
	// SAME path and query, before the dashboard's session gate (or
	// anything else) ever runs.
	resp := env.do(t, client, http.MethodGet, cliAuthURL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hop1 status = %d, want 302 (canonical-origin normalization)", resp.StatusCode)
	}
	wantNormalized := "http://127.0.0.1:8093/dashboard/cli-auth?redirect=" + redirectParam + "&challenge=" + challenge + "&name=laptop"
	if got := resp.Header.Get("Location"); got != wantNormalized {
		t.Fatalf("hop1 Location = %q, want %q", got, wantNormalized)
	}
	current := resolveLocation(cliAuthURL, resp.Header.Get("Location"))

	// Hop 2: now on "127.0.0.1", anonymous -> 302 to /auth/login
	// (relative, stays on "127.0.0.1").
	resp = env.do(t, client, http.MethodGet, current)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hop2 status = %d, want 302", resp.StatusCode)
	}
	current = resolveLocation(current, resp.Header.Get("Location"))
	if !strings.HasPrefix(current, "http://127.0.0.1:8093/auth/login") {
		t.Fatalf("hop2 Location resolved to %q, want it to stay on 127.0.0.1", current)
	}

	// Hop 3: /auth/login sets the OAuth state cookie on "127.0.0.1" --
	// the SAME host /auth/callback will land on -- then 302s to the dev
	// IdP authorize endpoint.
	resp = env.doOIDC(t, client, http.MethodGet, current)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hop3 status = %d, want 302", resp.StatusCode)
	}
	authorizeURL := resolveLocation(current, resp.Header.Get("Location"))

	// Hop 4: complete the dev IdP login -> lands on /auth/callback.
	callbackURL := env.devLogin(t, client, authorizeURL, "clitester@example.com")

	// Hop 5: /auth/callback -- the state cookie IS present this time (set
	// on the same "127.0.0.1" origin in hop 3), so the login succeeds:
	// sets the session/CSRF cookies and 302s back to return_to
	// (/dashboard/cli-auth?..., still on "127.0.0.1").
	resp = env.doOIDC(t, client, http.MethodGet, callbackURL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (successful login)", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "login_error=") {
		t.Fatalf("callback redirected to %q, want a successful-login redirect (no login_error) -- the state cookie should have been found", loc)
	}
	current = resolveLocation(callbackURL, loc)
	if !strings.HasPrefix(current, "http://127.0.0.1:8093/dashboard/cli-auth") {
		t.Fatalf("post-login redirect = %q, want it to carry return_to back to /dashboard/cli-auth on 127.0.0.1", current)
	}

	// The session now lives on "127.0.0.1", proving the whole login round
	// trip completed on a single, consistent cookie origin. Finish the
	// CLI-auth exchange itself directly against the management API (the
	// same session+CSRF-authenticated call the dashboard's real approval
	// form submission makes -- see internal/auth/cliauth.go's doc
	// comment), rather than parsing the SSR'd approval page's HTML.
	csrfTok := csrfCookieFor(t, client, "http://127.0.0.1:8093")

	authorizeReq, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8093/api/v1/cli/authorize",
		strings.NewReader(`{"redirect":"http://127.0.0.1:54321/callback","challenge":"`+challenge+`","name":"laptop"}`))
	if err != nil {
		t.Fatalf("NewRequest(POST /api/v1/cli/authorize): %v", err)
	}
	authorizeReq.Header.Set("Content-Type", "application/json")
	authorizeReq.Header.Set("X-CSRF-Token", csrfTok)
	// RequireCSRF (internal/auth/session.go) also checks Origin against
	// the configured control origin for session-authenticated mutations --
	// a real browser sets this automatically on a cross-document POST; a
	// raw http.Client (like this test's) must set it explicitly.
	authorizeReq.Header.Set("Origin", loopbackAliasBaseURL)
	authorizeResp, err := client.Do(authorizeReq)
	if err != nil {
		t.Fatalf("POST /api/v1/cli/authorize: %v", err)
	}
	defer authorizeResp.Body.Close()
	if authorizeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(authorizeResp.Body)
		t.Fatalf("POST /api/v1/cli/authorize status = %d, body = %s", authorizeResp.StatusCode, body)
	}
	var authorizeBody struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(authorizeResp.Body).Decode(&authorizeBody); err != nil {
		t.Fatalf("decode /api/v1/cli/authorize response: %v", err)
	}
	if authorizeBody.Code == "" {
		t.Fatal("/api/v1/cli/authorize returned an empty code")
	}

	// The loopback callback's own code+verifier exchange -- UNAUTHENTICATED
	// (no session/CSRF at all, exactly what the CLI's local listener does
	// on redirect), but still routed through the in-process transport
	// like every other request in this file rather than package-level
	// http.Post, which would dial a REAL "127.0.0.1:8093" -- easy to get
	// wrong quietly, since a real funcbox-server happening to run on that
	// port locally would answer with a plausible-looking response instead
	// of a connection error.
	tokenReq, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8093/api/v1/cli/token",
		strings.NewReader(`{"code":"`+authorizeBody.Code+`","verifier":"`+verifier+`"}`))
	if err != nil {
		t.Fatalf("NewRequest(POST /api/v1/cli/token): %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenResp, err := (&http.Client{Transport: handlerTransport{env.handler}}).Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /api/v1/cli/token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST /api/v1/cli/token status = %d, body = %s", tokenResp.StatusCode, body)
	}
	var tokenBody struct {
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("decode /api/v1/cli/token response: %v", err)
	}
	if !strings.HasPrefix(tokenBody.Credential, "fbxc_") {
		t.Fatalf("credential = %q, want fbxc_ prefix -- the full funcbox login flow must produce a real CLI credential", tokenBody.Credential)
	}
}

// csrfCookieFor is e2e_test.go's testEnv.csrfCookie, adapted to take a raw
// origin string instead of an env (this file's flow crosses hosts
// mid-test, so there's no single fixed baseURL to key the jar lookup on).
func csrfCookieFor(t *testing.T, client *http.Client, origin string) string {
	t.Helper()
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatalf("parse origin %q: %v", origin, err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "__Host-fbx_csrf" || c.Name == "fbx_csrf_insecure" {
			return c.Value
		}
	}
	t.Fatal("no CSRF cookie present; was the login flow driven to completion?")
	return ""
}
