// e2e_hostrouting_test.go exercises tmp/14-auth-and-pool-improvements.md
// §14.3 (the function login-redirect flow) against the ORIGIN-SEPARATED
// host router (server/internal/server's serveByHost: a distinct control
// origin plus a wildcard function-subdomain), rather than the legacy
// single-origin path router the rest of this file's tests use.
//
// This distinction isn't incidental: internal/auth's handleInvokeStart
// (the browser SSO round trip §14.3 relies on) refuses to operate at all
// unless FunctionDomain is configured -- it exists specifically to hand a
// short-lived, function-host-scoped cookie across the origin boundary
// between the control plane and a function's own subdomain, and has
// nothing to do in a same-origin deployment (there, the dashboard's own
// session cookie would already be sent on every request regardless). So
// §14.3's browser-redirect behavior can only be driven end-to-end against
// the host-routed configuration.
//
// There is no real network here: every request -- including the go-oidc
// library's OWN internal discovery/token/JWKS HTTP calls, made from
// server-side code back to this same process's dev IdP -- is routed
// straight to the in-process top-level http.Handler via handlerTransport,
// using fake but distinct hostnames ("dashboard.test" for the control
// plane, "<name>.func.test" for a function) so http.Client's cookiejar
// keeps their cookies exactly as separate as two real origins would,
// without any actual DNS resolution or socket I/O.
package funcbox_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/invoke"
	"github.com/syumai/funcbox/server/internal/server"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

const (
	testControlOrigin  = "http://dashboard.test"
	testFunctionDomain = "func.test"
)

// handlerTransport is an http.RoundTripper that dispatches every request
// straight to an in-process http.Handler (via httptest.NewRecorder)
// instead of dialing a real network connection. It's what lets this file's
// tests use distinct, unregistered hostnames to stand in for the control
// plane and a function's own subdomain -- server.New's router only ever
// looks at the request's Host/URL, never actually resolves it, so nothing
// here needs a real listener.
type handlerTransport struct{ handler http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// A real net/http.Server populates Request.Host from the wire's Host:
	// header before a handler ever sees it; http.NewRequest's client-side
	// construction leaves it empty and relies on req.URL.Host instead
	// (that's the field a real Transport would actually dial and send).
	// Mimic the server-side population here so router.serveByHost (which
	// reads r.Host) sees exactly what a real deployment would.
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	// A real net/http.Server (and httptest.NewRequest, which deliberately
	// mimics it) never hands a handler a nil Body -- a bodyless request
	// still gets http.NoBody. Client-side construction (http.NewRequest,
	// used throughout this file so requests can also be *sent* through a
	// real http.Client) leaves Body nil for a GET, since a real Transport
	// just omits the body on the wire. Left nil here, the guest pool's own
	// request-body read (io.ReadAll wrapping req.Body) panics on it -- so
	// normalize exactly like a real server would before dispatching.
	if req.Body == nil {
		req.Body = http.NoBody
	}
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}

// hostRoutedEnv is this file's counterpart to e2e_test.go's testEnv, wired
// with server.Deps.ControlURL/FunctionDomain so the origin-separated host
// router is actually exercised.
type hostRoutedEnv struct {
	handler http.Handler
	store   store.Store
	blob    *blobfs.Store
	manager *runtime.Manager
	auth    *auth.Auth

	// ctx carries an oidc.ClientContext-wrapped *http.Client (Transport:
	// handlerTransport) so that server-side OIDC discovery/token-exchange
	// calls -- issued by code running INSIDE a ServeHTTP call this same
	// context threads through -- also resolve in-process rather than
	// attempting real DNS/network I/O against "dashboard.test".
	ctx context.Context
}

func newHostRoutedEnv(t *testing.T, defaultVisibility string) *hostRoutedEnv {
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
		Mode:           auth.ModeDev,
		BaseURL:        testControlOrigin,
		ControlOrigin:  testControlOrigin,
		FunctionDomain: testFunctionDomain,
		ListenAddr:     "127.0.0.1:0",
		SessionSecret:  testSessionSecret,
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

	handler := server.New(server.Deps{
		Logger: logger, API: apiHandler, Invoker: invoker,
		Auth: authSvc.Routes(), DevOIDC: authSvc.DevRoutes(),
		ControlURL: testControlOrigin, FunctionDomain: testFunctionDomain,
	})

	env := &hostRoutedEnv{handler: handler, store: st, blob: blobStore, manager: manager, auth: authSvc}
	env.ctx = oidc.ClientContext(context.Background(), &http.Client{Transport: handlerTransport{handler}})
	env.bootstrap(t, defaultVisibility)
	return env
}

// bootstrap is this file's counterpart to e2e_test.go's testEnv.bootstrap:
// creates the organization's first (admin) user directly against the
// store, and an email_domain login rule wide enough for this file's tests
// to log additional @example.com users in without per-user rule changes.
func (e *hostRoutedEnv) bootstrap(t *testing.T, defaultVisibility string) *store.User {
	t.Helper()
	ctx := context.Background()

	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := e.store.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := e.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "admin-user", InternalUserID: admin.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create(admin): %v", err)
	}

	org, err := e.store.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet := settings.DefaultOrg()
	orgSet.DefaultVisibility = defaultVisibility
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := e.store.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}

	if err := e.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
	return admin
}

// setRequireApproval flips the organization's require_approval setting
// (tmp/13-public-mode.md §13.3), preserving whatever default_visibility
// bootstrap set.
func (e *hostRoutedEnv) setRequireApproval(t *testing.T, on bool) {
	t.Helper()
	ctx := context.Background()
	org, err := e.store.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	orgSet.RequireApproval = on
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := e.store.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}
}

// deployEchoFunction deploys a GLOBAL-namespace function (host-routed mode
// serves by name alone, invoke.Invoker.ServeByName -- see
// server/internal/server/routes.go's serveByHost) named name, owned by
// actor, whose response body reveals whether the guest ever saw a Cookie
// header: "ok/no-cookie" normally, "ok/LEAKED" if one reached it -- so
// every test using it doubles as a cookie-non-propagation check just by
// reading the body.
func (e *hostRoutedEnv) deployEchoFunction(t *testing.T, owner, name string, visibility string, actor *store.User) {
	t.Helper()
	manifestExtra := ""
	if visibility != "" {
		manifestExtra = "visibility: " + visibility + "\n"
	}
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: " + name + "\n" + manifestExtra),
		"index.js": []byte(`
			export default {
				async fetch(req) {
					const cookieSeen = req.headers.get("Cookie") === null ? "no-cookie" : "LEAKED";
					return new Response("ok/" + cookieSeen);
				},
			};
		`),
	}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	deployer := &service.Deployer{Store: e.store, Blob: e.blob, Runtime: e.manager}
	result, err := deployer.Deploy(context.Background(), service.DeployParams{
		Bundle: bytes.NewReader(packed), Owner: owner, Name: name, Actor: actor,
	})
	if err != nil {
		t.Fatalf("Deploy(%s): %v", name, err)
	}
	if result.Function == nil {
		t.Fatalf("Deploy(%s) did not create a function", name)
	}
}

// newClient returns a fresh cookie-jar-equipped client wired through
// handlerTransport, with automatic redirect-following disabled so each
// test can inspect (and choose whether to follow) every hop itself --
// exactly what's needed to assert on the specific redirect chain §14.3
// describes, and (for the pending-user test) to bound how many hops it
// takes without ever actually looping forever.
func (e *hostRoutedEnv) newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Jar:           jar,
		Transport:     handlerTransport{e.handler},
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// do issues method to rawURL through client (whose own Transport is
// already handlerTransport-equipped, so this needs no special context for
// ROUTING) and returns the response. Only the two hops that trigger
// SERVER-SIDE code making its own further outbound OIDC calls (handleLogin's
// discovery, handleCallback's token exchange -- see doOIDC) need anything
// more than context.Background() here.
func (e *hostRoutedEnv) do(t *testing.T, client *http.Client, method, rawURL string) *http.Response {
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

// doOIDC is do, but carries e.ctx (the in-process oidc.ClientContext) on
// the request so that server-side code handling it -- specifically
// handleLogin's provider discovery and handleCallback's token exchange,
// internal/auth's provider.go -- can make ITS OWN further outbound HTTP
// calls back into this same in-process handler instead of attempting real
// network/DNS I/O against "dashboard.test". It must NOT be used for a
// request that ends up reaching guest code (the invoke pool): embedding an
// *http.Client in the request context this deep trips up the guest
// runtime, which is exactly why this is a separate, narrowly-used method
// rather than do's default.
func (e *hostRoutedEnv) doOIDC(t *testing.T, client *http.Client, method, rawURL string) *http.Response {
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

// browserGet is do with the Accept header a real browser navigation
// carries -- the exact signal invoke.go's wantsHTMLRedirect keys on.
func (e *hostRoutedEnv) browserGet(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(GET %s): %v", rawURL, err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

// resolveLocation resolves a (possibly relative) Location header against
// the URL of the request that produced it -- exactly what following a
// redirect actually means, and what every hop below needs since some
// handlers redirect with an absolute URL (a different origin) and others
// with a same-origin relative path.
func resolveLocation(from, location string) string {
	base, err := url.Parse(from)
	if err != nil {
		panic(err)
	}
	ref, err := url.Parse(location)
	if err != nil {
		panic(err)
	}
	return base.ResolveReference(ref).String()
}

// devLogin drives the dev IdP's authorize+token endpoints directly (the
// same shortcut e2e_test.go's own mintIDToken/loginViaHTTP use) from
// authorizeURL -- the discovered provider's authorization endpoint, as
// already redirected to by /auth/login -- through to the OAuth client's
// redirect_uri, returning that final Location (the control-plane
// /auth/callback URL, not yet followed).
func (e *hostRoutedEnv) devLogin(t *testing.T, client *http.Client, authorizeURL, email string) string {
	t.Helper()
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize URL %q: %v", authorizeURL, err)
	}
	form := url.Values{
		"client_id":    {u.Query().Get("client_id")},
		"redirect_uri": {u.Query().Get("redirect_uri")},
		"state":        {u.Query().Get("state")},
		"nonce":        {u.Query().Get("nonce")},
		"email":        {email},
	}
	req, err := http.NewRequest(http.MethodPost, testControlOrigin+"/dev/oidc/authorize", strings.NewReader(form.Encode()))
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
	return resolveLocation(testControlOrigin+"/dev/oidc/authorize", resp.Header.Get("Location"))
}

// TestE2E_HostRouted_BrowserLoginRedirectAndCookieNeverLeaksToGuest is
// tmp/14-auth-and-pool-improvements.md §14.3's central happy path,
// end-to-end and over real HTTP semantics (redirects, cookies scoped per
// origin): a browser-like, completely unauthenticated GET to an
// org-visibility function
//
//  1. 302s to the control plane's /auth/invoke SSO entry point;
//  2. (no dashboard session yet) 302s onward to /auth/login;
//  3. /auth/login 302s to the dev IdP's authorize endpoint;
//  4. logging in there completes the OAuth dance, lands on /auth/callback,
//     which sets the dashboard session cookie and 302s back to the ORIGINAL
//     /auth/invoke URL (carried through the whole login round trip as
//     return_to);
//  5. now authenticated, /auth/invoke mints a one-time code and 303s to the
//     function host's own /.funcbox/auth/callback;
//  6. that consumes the code, sets the function-host-scoped invoke cookie,
//     and 303s back to the function's own URL;
//  7. THAT request finally reaches the guest, authorized via the invoke
//     cookie -- and its response proves both that the guest actually ran
//     (§14.3's whole point) and that it never once saw a Cookie header
//     (§14.3's "Cookie は関数自体には一切伝播しない" guarantee), despite a
//     real, currently-valid funcbox credential having ridden along on
//     every single one of those seven requests.
func TestE2E_HostRouted_BrowserLoginRedirectAndCookieNeverLeaksToGuest(t *testing.T) {
	env := newHostRoutedEnv(t, "org")
	admin, err := env.store.Users().ByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(admin): %v", err)
	}
	env.deployEchoFunction(t, "admin-user", "orgapp", "", admin) // visibility: org default applies

	// The browsing user logs in as a FRESH identity ("orguser@example.com",
	// allowed by bootstrap's example.com domain rule) via the real dev IdP
	// HTTP flow below, rather than as the admin: the admin user this file's
	// bootstrap creates directly against the store (like e2e_test.go's own
	// testEnv.bootstrap) uses a placeholder ProviderSubject that doesn't
	// match what the dev IdP actually derives for admin@example.com
	// (sha256("dev-subject:"+email)), so logging "the admin" back in via
	// HTTP would collide on email against that pre-existing row instead of
	// resolving to it -- e2e_test.go's own TestE2E_AuthDevLoginFlow makes
	// the identical choice, and explains it, for the same reason. Being a
	// plain org member (not the admin) is enough to reach an
	// org-visibility function anyway.

	client := env.newClient(t)
	functionURL := "http://orgapp." + testFunctionDomain + "/"

	// Hop 1: unauthenticated browser GET -> 302 to /auth/invoke.
	resp := env.browserGet(t, client, functionURL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hop1 status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, testControlOrigin+"/auth/invoke?") || !strings.Contains(loc, "function=orgapp") {
		t.Fatalf("hop1 Location = %q, want /auth/invoke SSO handoff for orgapp", loc)
	}
	current := resolveLocation(functionURL, loc)

	// Hop 2: /auth/invoke, no session yet -> 302 to /auth/login.
	resp = env.do(t, client, http.MethodGet, current)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hop2 status = %d, want 302", resp.StatusCode)
	}
	loc = resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/auth/login?return_to=") {
		t.Fatalf("hop2 Location = %q, want /auth/login?return_to=...", loc)
	}
	current = resolveLocation(current, loc)

	// Hop 3: /auth/login -> 302 to the dev IdP's authorize endpoint. This
	// triggers real OIDC provider discovery server-side, so it needs doOIDC.
	resp = env.doOIDC(t, client, http.MethodGet, current)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hop3 status = %d, want 302", resp.StatusCode)
	}
	authorizeURL := resolveLocation(current, resp.Header.Get("Location"))
	if !strings.HasPrefix(authorizeURL, testControlOrigin+"/dev/oidc/authorize?") {
		t.Fatalf("hop3 Location = %q, want the dev IdP authorize endpoint", authorizeURL)
	}

	// Hop 4: complete the dev IdP login -> lands on /auth/callback.
	callbackURL := env.devLogin(t, client, authorizeURL, "orguser@example.com")

	// Hop 5: /auth/callback -- sets the dashboard session cookie, 302s back
	// to the ORIGINAL /auth/invoke URL (return_to survived the whole OAuth
	// round trip, per §14.3's "next" requirement). This triggers the token
	// exchange server-side, so it needs doOIDC too.
	resp = env.doOIDC(t, client, http.MethodGet, callbackURL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("hop5 (/auth/callback) status = %d, want 302", resp.StatusCode)
	}
	loc = resp.Header.Get("Location")
	if !strings.Contains(loc, "/auth/invoke") || !strings.Contains(loc, "function=orgapp") {
		t.Fatalf("post-login redirect = %q, want it to carry return_to back to the original /auth/invoke URL", loc)
	}
	current = resolveLocation(callbackURL, loc)

	// Hop 6: /auth/invoke, now authenticated -> 303 to the function host's
	// own /.funcbox/auth/callback.
	resp = env.do(t, client, http.MethodGet, current)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("hop6 status = %d, want 303", resp.StatusCode)
	}
	loc = resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://orgapp."+testFunctionDomain+"/.funcbox/auth/callback?code=") {
		t.Fatalf("hop6 Location = %q, want the function-host SSO callback", loc)
	}
	current = resolveLocation(current, loc)

	// Hop 7: the function-host callback -- sets the invoke cookie, 303s
	// back to the original function path ("/").
	resp = env.do(t, client, http.MethodGet, current)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("hop7 status = %d, want 303", resp.StatusCode)
	}
	loc = resp.Header.Get("Location")
	current = resolveLocation(current, loc)

	// Final: the function itself, now reached with a valid invoke cookie.
	resp = env.browserGet(t, client, current)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d, body = %q, want 200 (authorized via invoke cookie)", resp.StatusCode, body)
	}
	if string(body) != "ok/no-cookie" {
		t.Fatalf("final body = %q, want %q -- guest must never see a Cookie header even when a real invoke credential authorized it", string(body), "ok/no-cookie")
	}
}

// TestE2E_HostRouted_PendingUserNoRedirectLoop covers §14.3 item 3's
// explicit "no redirect loop" requirement: a user with an otherwise
// perfectly valid dashboard session, but store.UserStatusPending
// (tmp/13-public-mode.md §13.3), hitting an org-visibility function in a
// browser must NOT bounce between the function host and the control
// plane's login/SSO endpoints forever. It must terminate in a 403 within a
// small, fixed number of hops.
func TestE2E_HostRouted_PendingUserNoRedirectLoop(t *testing.T) {
	env := newHostRoutedEnv(t, "org")
	admin, err := env.store.Users().ByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(admin): %v", err)
	}
	env.deployEchoFunction(t, "admin-user", "orgapp", "", admin)
	env.setRequireApproval(t, true) // a brand-new identity logs in as UserStatusPending

	client := env.newClient(t)

	// Log the pending user in via the real dashboard login flow (NOT
	// hand-crafted): /auth/login -> dev IdP -> /auth/callback. This is the
	// exact same login path bootstrap-based tests skip, driven here on
	// purpose so the resulting session is completely ordinary -- the only
	// thing unusual about this user is their status.
	resp := env.doOIDC(t, client, http.MethodGet, testControlOrigin+"/auth/login")
	resp.Body.Close()
	authorizeURL := resolveLocation(testControlOrigin+"/auth/login", resp.Header.Get("Location"))
	callbackURL := env.devLogin(t, client, authorizeURL, "newbie@example.com")
	resp = env.doOIDC(t, client, http.MethodGet, callbackURL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/auth/callback status = %d, want 302 (login itself must still succeed for a pending user, §13.3)", resp.StatusCode)
	}

	pending, err := env.store.Users().ByEmail(context.Background(), "newbie@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(newbie): %v", err)
	}
	if pending.Status != store.UserStatusPending {
		t.Fatalf("newbie status = %q, want %q (setRequireApproval should have made this login create a pending user)", pending.Status, store.UserStatusPending)
	}

	// Now, already logged in (with a session cookie for a pending user),
	// browse straight to the org-visibility function and follow whatever
	// redirects come back, up to a small bound. If §14.3's redirect-loop
	// fix regressed, this loop would exhaust maxHops while still bouncing
	// between 302s and never reach a final response.
	current := "http://orgapp." + testFunctionDomain + "/"
	const maxHops = 6
	var resp2 *http.Response
	for hop := 0; hop < maxHops; hop++ {
		resp2 = env.browserGet(t, client, current)
		if resp2.StatusCode != http.StatusFound && resp2.StatusCode != http.StatusSeeOther {
			break
		}
		loc := resp2.Header.Get("Location")
		resp2.Body.Close()
		current = resolveLocation(current, loc)
	}
	if resp2 == nil {
		t.Fatal("no response recorded")
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("final status after following redirects = %d (url=%s, body=%q), want 403 -- either it looped past maxHops=%d without terminating, or landed on the wrong status", resp2.StatusCode, current, body, maxHops)
	}
	if !strings.Contains(string(body), "Access denied") {
		t.Fatalf("403 body = %q, want the browser-facing access-denied page", body)
	}
}
