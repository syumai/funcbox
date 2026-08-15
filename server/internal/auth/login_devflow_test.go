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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/browserjar"
	"github.com/syumai/funcbox/server/internal/settings"
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
	// browserjar.New (not net/http/cookiejar.New directly): this is the
	// dedicated regression coverage for the "__Host- cookie over plain
	// http" bug -- the httptest server here is plain http, exactly the
	// deployment shape (FUNCBOX_BASE_URL=http://127.0.0.1:... per the
	// README quick-start) where a real browser silently discards a
	// "__Host-" prefixed Set-Cookie lacking Secure and loops the user back
	// to the login form forever. net/http/cookiejar doesn't enforce that
	// rule, so it would stay green even against the pre-fix code; see
	// browserjar's doc comment.
	client := &http.Client{
		Jar: browserjar.New(),
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

// TestDevLoginFlow_SignInFormUsesSharedStyledShell covers items 1 and 2 of
// the auth-pages styling work for the dev IdP's own sign-in form
// (devidp.go's handleAuthorizeForm): it must render through the shared
// webpage.Page shell (asserted here via a couple of its CSS class markers,
// since asserting the full inlined stylesheet would just be a change-
// detector) and in exactly one language -- English before any organization
// exists yet (webpage.OrgLanguage's documented fail-closed default), and
// Japanese once the organization's settings.Org.Language is set to "ja".
func TestDevLoginFlow_SignInFormUsesSharedStyledShell(t *testing.T) {
	env := newDevLoginTestEnv(t)

	authorizeURL := env.server.URL + devOIDCPrefix + "/authorize?response_type=code&client_id=c&redirect_uri=" +
		url.QueryEscape(env.server.URL+"/auth/callback")

	get := func() string {
		t.Helper()
		resp, err := http.Get(authorizeURL)
		if err != nil {
			t.Fatalf("GET %s: %v", authorizeURL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", authorizeURL, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return string(body)
	}

	// No organization exists yet: OrgLanguage fails closed to English.
	body := get()
	if !strings.Contains(body, `class="wp-card"`) || !strings.Contains(body, `class="wp-brand"`) {
		t.Errorf("dev sign-in form does not use the shared webpage.Page shell; got: %s", body)
	}
	if !strings.Contains(body, "funcbox dev sign-in") {
		t.Errorf("dev sign-in form missing expected English heading; got: %s", body)
	}
	if strings.Contains(body, "開発用サインイン") {
		t.Errorf("dev sign-in form unexpectedly contains Japanese before any org language is set; got: %s", body)
	}

	// Bootstrap an org and set its language to ja; the SAME (pre-login,
	// anonymous) form must now render Japanese only.
	ctx := context.Background()
	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := env.auth.store.BootstrapFirstUser(ctx, admin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	org, err := env.auth.store.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		t.Fatalf("settings.ParseOrg: %v", err)
	}
	orgSet.Language = "ja"
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := env.auth.store.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}

	body = get()
	if !strings.Contains(body, "開発用サインイン") {
		t.Errorf("dev sign-in form missing expected Japanese heading after org language = ja; got: %s", body)
	}
	if strings.Contains(body, "funcbox dev sign-in") {
		t.Errorf("dev sign-in form unexpectedly still contains English after org language = ja; got: %s", body)
	}
}

func TestDevLoginFlow_FirstUserBecomesAdminWithDerivedUserID(t *testing.T) {
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

	id, err := env.auth.store.PublicUserIDs().ByOwner(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByOwner: %v", err)
	}
	if id.UserID != "alice" {
		t.Fatalf("derived User ID = %q, want %q", id.UserID, "alice")
	}

	// The session cookie should now authenticate management API requests.
	sessionURL, _ := url.Parse(env.server.URL)
	cookies := client.Jar.Cookies(sessionURL)
	var hasSession, hasCSRF bool
	for _, c := range cookies {
		if c.Name == env.auth.sessionCookieName() {
			hasSession = true
		}
		if c.Name == env.auth.csrfCookieName() {
			hasCSRF = true
		}
	}
	if !hasSession || !hasCSRF {
		t.Fatalf("cookies = %v, want both %q and %q set", cookies, env.auth.sessionCookieName(), env.auth.csrfCookieName())
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

// newOpenModeLoginTestEnv is newDevLoginTestEnv with OpenMode set, for
// bootstrap-time seeding.
func newOpenModeLoginTestEnv(t *testing.T) *devLoginTestEnv {
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
		OpenMode:      true,
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

// TestDevLoginFlow_OpenModeBootstrapSeedsDefaultAllowAndOrgSetting covers
// the rule that with FUNCBOX_OPEN_MODE=1 (auth.Config.OpenMode) at
// process startup, the very first (bootstrap) login seeds a
// default-allow login rule -- unlike normal mode's email_exact(admin)-only
// rule -- so a completely unrelated stranger, from any domain, can log in
// and become a normal member right away; and the organization's own
// open_mode setting is set to true as a side effect, so it's the
// authoritative source from then on (not the env var).
func TestDevLoginFlow_OpenModeBootstrapSeedsDefaultAllowAndOrgSetting(t *testing.T) {
	env := newOpenModeLoginTestEnv(t)

	// First login: bootstraps the org, becomes admin, per the normal
	// bootstrap path -- open mode doesn't change who the bootstrap admin
	// is, only the seeded rule set.
	_, location := env.login(t, "admin@example.com")
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("bootstrap login redirect = %q, want /dashboard", location)
	}
	adminUser, err := env.auth.store.Users().ByEmail(context.Background(), "admin@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(admin): %v", err)
	}
	if adminUser.Role != store.RoleAdmin {
		t.Fatalf("bootstrap user role = %q, want %q", adminUser.Role, store.RoleAdmin)
	}

	org, err := env.auth.store.Organizations().Get(context.Background())
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if !orgSet.OpenMode {
		t.Error("organization's open_mode setting was not seeded to true at bootstrap")
	}

	// A completely unrelated stranger -- different domain than the
	// bootstrap admin, never granted any rule of their own -- must still
	// be admitted, unlike normal mode (see
	// TestDevLoginFlow_UserFromOtherDomainDenied for the same scenario
	// under normal mode, where it's denied).
	_, strangerLocation := env.login(t, "stranger@totally-unrelated.example")
	if !strings.HasPrefix(strangerLocation, "/dashboard") {
		t.Fatalf("stranger's login redirect = %q, want /dashboard (open mode default-allows registration)", strangerLocation)
	}
	stranger, err := env.auth.store.Users().ByEmail(context.Background(), "stranger@totally-unrelated.example")
	if err != nil {
		t.Fatalf("Users().ByEmail(stranger): %v", err)
	}
	if stranger.Role != store.RoleMember {
		t.Fatalf("stranger's role = %q, want %q", stranger.Role, store.RoleMember)
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
	bobSessionCookie := findCookie(client, env.server.URL, env.auth.sessionCookieName())
	if bobSessionCookie == "" {
		t.Fatal("bob has no session cookie after login")
	}
	httpReq := httptest.NewRequest(http.MethodGet, "/api/v1/functions", nil)
	httpReq.AddCookie(&http.Cookie{Name: env.auth.sessionCookieName(), Value: bobSessionCookie})
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
