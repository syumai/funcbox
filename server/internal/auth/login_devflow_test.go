// login_devflow_test.go drives the ENTIRE dev-IdP login flow through real
// HTTP round trips (login -> dev authorize form submission -> dev token
// exchange -> callback -> session cookie), rather than unit-testing its
// pieces in isolation. This is deliberately the same mechanism the
// top-level e2e suite (e2e_test.go) exercises against the full server;
// having it here too catches auth-specific regressions fast, without
// paying for the rest of the stack (store/blob/runtime wiring) on every
// run.
package auth

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
)

// devLoginTestEnv wires a's /auth/* and /dev/oidc/* routes behind one
// httptest.Server, matching how internal/server mounts them in
// production.
type devLoginTestEnv struct {
	t      *testing.T
	server *httptest.Server
	auth   *Auth
}

func newDevLoginTestEnv(t *testing.T) *devLoginTestEnv {
	t.Helper()
	st := newTestStore(t)

	mux := http.NewServeMux()
	env := &devLoginTestEnv{t: t}

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a, err := New(Config{
		Mode:          ModeDev,
		BaseURL:       srv.URL,
		ListenAddr:    "127.0.0.1:0",
		SessionSecret: "test-secret-value",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux.Handle("/auth/", a.Routes())
	mux.Handle(devOIDCPrefix+"/", a.DevRoutes())

	env.server = srv
	env.auth = a
	return env
}

// login drives a full browser-less dev login for email through the real
// HTTP endpoints, returning the client (with the resulting session/CSRF
// cookies in its jar) and the final redirect location.
func (env *devLoginTestEnv) login(t *testing.T, email string) (*http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't auto-follow; we drive each hop
		},
	}

	// Step 1: GET /auth/login -> redirect to the dev authorize endpoint.
	resp, err := client.Get(env.server.URL + "/auth/login")
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

	// Step 2: simulate submitting the dev sign-in form with the chosen
	// email (instead of rendering/parsing the HTML form, which carries no
	// extra information beyond the same query params).
	form := url.Values{
		"client_id":    {authorizeURL.Query().Get("client_id")},
		"redirect_uri": {authorizeURL.Query().Get("redirect_uri")},
		"state":        {authorizeURL.Query().Get("state")},
		"nonce":        {authorizeURL.Query().Get("nonce")},
		"email":        {email},
	}
	resp, err = client.PostForm(env.server.URL+devOIDCPrefix+"/authorize", form)
	if err != nil {
		t.Fatalf("POST %s/authorize: %v", devOIDCPrefix, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST authorize status = %d, want 302", resp.StatusCode)
	}
	callbackURL := resp.Header.Get("Location")

	// Step 3: GET /auth/callback (the dev authorize step redirected
	// straight here, exactly like a real IdP would) -> exchanges the code,
	// verifies the id token, and (if this is a new session) sets cookies.
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()

	return client, resp.Header.Get("Location")
}

func TestDevLoginFlow_FirstUserBecomesAdminWithDerivedHandle(t *testing.T) {
	env := newDevLoginTestEnv(t)
	client, location := env.login(t, "alice@example.com")

	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("final redirect = %q, want a /dashboard location (successful login)", location)
	}

	u, err := env.auth.store.Users().ByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	if u.Role != store.RoleAdmin {
		t.Fatalf("first user's role = %q, want %q", u.Role, store.RoleAdmin)
	}

	h, err := env.auth.store.Handles().ByOwner(context.Background(), store.OwnerTypeUser, u.ID)
	if err != nil {
		t.Fatalf("Handles().ByOwner: %v", err)
	}
	if h.Handle != "alice" {
		t.Fatalf("derived handle = %q, want %q", h.Handle, "alice")
	}

	// The session cookie should now authenticate management API requests.
	sessionURL, _ := url.Parse(env.server.URL)
	cookies := client.Jar.Cookies(sessionURL)
	var hasSession, hasCSRF bool
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			hasSession = true
		}
		if c.Name == csrfCookieName {
			hasCSRF = true
		}
	}
	if !hasSession || !hasCSRF {
		t.Fatalf("cookies = %v, want both %q and %q set", cookies, sessionCookieName, csrfCookieName)
	}
}

// security fix in action: bootstrap seeds an allow rule for the FIRST
// user's exact email only (internal/auth/login.go's
// seedBootstrapLoginRule), not their whole domain. A second user sharing
// that domain -- the common case when the first admin happens to sign up
// with a public provider like gmail.com -- must NOT be silently admitted;
// see TestDevLoginFlow_AdminWidensRulesThenSecondUserBecomesMember for the
// case where an admin deliberately opens the domain up.
func TestDevLoginFlow_SecondUserSameDomainDeniedByDefault(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com") // bootstrap: seeds an allow rule for alice@example.com ONLY

	_, location := env.login(t, "bob@example.com")
	if strings.HasPrefix(location, "/dashboard") && !strings.Contains(location, "login_error") {
		t.Fatalf("second user from the same domain (but a different exact address) logged in (redirect = %q), want denial", location)
	}

	if _, err := env.auth.store.Users().ByEmail(context.Background(), "bob@example.com"); err == nil {
		t.Fatal("a denied login must not create a user record")
	}
}

// TestDevLoginFlow_AdminWidensRulesThenSecondUserBecomesMember covers the
// intended path for admitting more users after bootstrap: the admin
// explicitly widens the login rules (here, to the whole domain), and only
// THEN does a second user's login succeed.
func TestDevLoginFlow_AdminWidensRulesThenSecondUserBecomesMember(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com") // bootstrap: seeds an allow rule for alice@example.com ONLY

	if err := env.auth.store.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	_, location := env.login(t, "bob@example.com")
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("second user's login redirect = %q, want /dashboard (should be allowed by the widened domain rule)", location)
	}

	u, err := env.auth.store.Users().ByEmail(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	if u.Role != store.RoleMember {
		t.Fatalf("second user's role = %q, want %q", u.Role, store.RoleMember)
	}
}

func TestDevLoginFlow_UserFromOtherDomainDenied(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com") // bootstrap: seeds an allow rule for alice@example.com only

	_, location := env.login(t, "mallory@evil.com")
	if strings.HasPrefix(location, "/dashboard") && !strings.Contains(location, "login_error") {
		t.Fatalf("login from a non-allowed domain succeeded (redirect = %q), want denial", location)
	}

	if _, err := env.auth.store.Users().ByEmail(context.Background(), "mallory@evil.com"); err == nil {
		t.Fatal("a denied login must not create a user record")
	}
}

func TestDevLoginFlow_LoginRuleChangeLocksOutExistingSession(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com") // bootstrap: seeds an allow rule for alice@example.com ONLY

	// Admit bob explicitly (bootstrap alone would deny him -- see
	// TestDevLoginFlow_SecondUserSameDomainDeniedByDefault) so he can log
	// in and establish the session this test then locks out.
	if err := env.auth.store.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: "alice@example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeEmailExact, Value: "bob@example.com", Action: store.LoginRuleActionAllow},
		{Ord: 2, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules (admit bob): %v", err)
	}
	client, location := env.login(t, "bob@example.com")
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("bob's login redirect = %q, want /dashboard", location)
	}

	// Confirm bob's session currently authenticates.
	bobSessionCookie := findCookie(client, env.server.URL, sessionCookieName)
	if bobSessionCookie == "" {
		t.Fatal("bob has no session cookie after login")
	}
	httpReq := httptest.NewRequest(http.MethodGet, "/api/v1/functions", nil)
	httpReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: bobSessionCookie})
	if _, err := env.auth.Authenticate(httpReq); err != nil {
		t.Fatalf("Authenticate(bob's session) before rule change: %v", err)
	}

	// Now tighten the login rules to exclude bob's domain entirely.
	if err := env.auth.store.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: "alice@example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	if _, err := env.auth.Authenticate(httpReq); err == nil {
		t.Fatal("bob's existing session should be rejected after the login rule change excludes him")
	}
}

func findCookie(client *http.Client, rawURL, name string) string {
	u, _ := url.Parse(rawURL)
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
