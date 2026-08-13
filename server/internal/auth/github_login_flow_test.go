// github_login_flow_test.go drives the ENTIRE GitHub login flow through
// real HTTP round trips (login -> fake GitHub token exchange -> fake
// GitHub /user + /user/emails -> callback), against an httptest fake
// standing in for github.com/api.github.com -- the mechanism
// login_devflow_test.go uses for the dev-IdP flow, applied to GitHub's
// very different (OAuth2 + REST, no OIDC) shape.
package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
)

// fakeGitHubUser is one fixture identity the fake GitHub server can serve.
type fakeGitHubUser struct {
	id     int64
	login  string
	emails []githubEmailResponse
}

// fakeGitHub stands in for github.com (token endpoint) and api.github.com
// (/user, /user/emails) behind a single httptest.Server, matching how
// Config's githubTokenURL/githubAPIBaseURL point at one origin in tests.
type fakeGitHub struct {
	server *httptest.Server

	mu      sync.Mutex
	byCode  map[string]fakeGitHubUser
	byToken map[string]fakeGitHubUser
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{byCode: map[string]fakeGitHubUser{}, byToken: map[string]fakeGitHubUser{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", f.handleToken)
	mux.HandleFunc("GET /user", f.handleUser)
	mux.HandleFunc("GET /user/emails", f.handleEmails)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// addCode registers user as the identity a subsequent token exchange for
// code should resolve to -- the fake's equivalent of "the user approved
// the OAuth consent screen for this authorization code".
func (f *fakeGitHub) addCode(code string, user fakeGitHubUser) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byCode[code] = user
}

func (f *fakeGitHub) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	f.mu.Lock()
	user, ok := f.byCode[code]
	f.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad_verification_code"})
		return
	}
	token := "gho_test_" + code
	f.mu.Lock()
	f.byToken[token] = user
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "bearer",
		"scope":        "read:user,user:email",
	})
}

func (f *fakeGitHub) userFor(r *http.Request) (fakeGitHubUser, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return fakeGitHubUser{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byToken[tok]
	return u, ok
}

func (f *fakeGitHub) handleUser(w http.ResponseWriter, r *http.Request) {
	user, ok := f.userFor(r)
	if !ok {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, githubUserResponse{ID: user.id, Login: user.login})
}

func (f *fakeGitHub) handleEmails(w http.ResponseWriter, r *http.Request) {
	user, ok := f.userFor(r)
	if !ok {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, user.emails)
}

// githubLoginTestEnv wires a's /auth/* routes (Mode: ModeGitHub) behind one
// httptest.Server, pointed at a fakeGitHub standing in for github.com.
type githubLoginTestEnv struct {
	t      *testing.T
	server *httptest.Server
	auth   *Auth
	gh     *fakeGitHub
}

func newGitHubLoginTestEnv(t *testing.T) *githubLoginTestEnv {
	t.Helper()
	st := newTestStore(t)
	gh := newFakeGitHub(t)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a, err := New(Config{
		Mode:               ModeGitHub,
		BaseURL:            srv.URL,
		ListenAddr:         "127.0.0.1:0",
		GitHubClientID:     "test-client-id",
		GitHubClientSecret: "test-client-secret",
		SessionSecret:      "test-secret-value",
		githubAuthorizeURL: gh.server.URL + "/login/oauth/authorize",
		githubTokenURL:     gh.server.URL + "/login/oauth/access_token",
		githubAPIBaseURL:   gh.server.URL,
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mux.Handle("/auth/", a.Routes())

	return &githubLoginTestEnv{t: t, server: srv, auth: a, gh: gh}
}

// login drives GET /auth/login -> (fake) GitHub token exchange -> GET
// /auth/callback for the given fixture user, registered under a
// fresh one-time authorization code. It returns the client (cookies
// retained in its jar) and the callback's final redirect Location.
func (env *githubLoginTestEnv) login(t *testing.T, code string, user fakeGitHubUser) (*http.Client, string) {
	t.Helper()
	env.gh.addCode(code, user)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
	state := authorizeURL.Query().Get("state")

	// The real GitHub authorize/consent step is never exercised here
	// (there is no interactive consent to simulate in this fake); the
	// test plays the role of "GitHub redirecting back with a code" by
	// hitting the callback directly, exactly like login_devflow_test.go
	// skips rendering/parsing the dev IdP's HTML form.
	callbackURL := env.server.URL + "/auth/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	resp, err = client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	resp.Body.Close()

	return client, resp.Header.Get("Location")
}

func TestGitHubLoginFlow_FreshSignupBecomesAdminWithGitHubHandle(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	client, location := env.login(t, "code-1", fakeGitHubUser{
		id: 1001, login: "octocat",
		emails: []githubEmailResponse{{Email: "octocat@example.com", Primary: true, Verified: true}},
	})

	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("final redirect = %q, want a /dashboard location (successful login)", location)
	}

	u, err := env.auth.store.Users().ByProviderSubject(context.Background(), store.ProviderGitHub, "1001")
	if err != nil {
		t.Fatalf("Users().ByProviderSubject: %v", err)
	}
	if u.Role != store.RoleAdmin {
		t.Fatalf("first user's role = %q, want admin (bootstrap)", u.Role)
	}
	if u.Email != "octocat@example.com" {
		t.Fatalf("email = %q, want %q", u.Email, "octocat@example.com")
	}

	pid, err := env.auth.store.PublicUserIDs().ByOwner(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByOwner: %v", err)
	}
	if pid.UserID != "octocat" {
		t.Fatalf("handle = %q, want %q (GitHub username, fixed)", pid.UserID, "octocat")
	}

	sessionURL, _ := url.Parse(env.server.URL)
	var hasSession bool
	for _, c := range client.Jar.Cookies(sessionURL) {
		if c.Name == sessionCookieName {
			hasSession = true
		}
	}
	if !hasSession {
		t.Fatal("no session cookie set after a successful GitHub login")
	}
}

func TestGitHubLoginFlow_SecondLoginSameSubjectReusesUser(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	octocat := fakeGitHubUser{
		id: 1001, login: "octocat",
		emails: []githubEmailResponse{{Email: "octocat@example.com", Primary: true, Verified: true}},
	}
	env.login(t, "code-1", octocat)
	_, location := env.login(t, "code-2", octocat)

	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("second login redirect = %q, want /dashboard", location)
	}

	users, err := env.auth.store.Users().List(context.Background())
	if err != nil {
		t.Fatalf("Users().List: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("got %d users after two logins by the same GitHub subject, want 1", len(users))
	}
}

func TestGitHubLoginFlow_ReservedUsernameRejected(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	_, location := env.login(t, "code-1", fakeGitHubUser{
		id: 2002, login: "admin", // collides with manifest.ReservedNames
		emails: []githubEmailResponse{{Email: "admin-person@example.com", Primary: true, Verified: true}},
	})

	if !strings.Contains(location, "login_error") {
		t.Fatalf("login with a reserved GitHub username succeeded (redirect = %q), want a login_error denial", location)
	}

	if _, err := env.auth.store.Users().ByProviderSubject(context.Background(), store.ProviderGitHub, "2002"); err == nil {
		t.Fatal("a rejected reserved-username login must not create a user record")
	}
}

func TestGitHubLoginFlow_NoVerifiedEmailRejected(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	_, location := env.login(t, "code-1", fakeGitHubUser{
		id: 3003, login: "unverified-person",
		emails: []githubEmailResponse{{Email: "unverified-person@example.com", Primary: true, Verified: false}},
	})

	if !strings.Contains(location, "login_error") {
		t.Fatalf("login with no verified primary email succeeded (redirect = %q), want a login_error denial", location)
	}

	if _, err := env.auth.store.Users().ByProviderSubject(context.Background(), store.ProviderGitHub, "3003"); err == nil {
		t.Fatal("a rejected unverified-email login must not create a user record")
	}
}

// TestGitHubLoginFlow_EmailLinkRequiresConfirmation covers the full
// tmp/13-public-mode.md §13.2 account-link path: an existing Google user
// logs in via GitHub with a matching verified email. The link must NOT be
// applied immediately -- the callback redirects to the confirmation page,
// which must render the handle-change warning, and only completing that
// page's form actually links the account (updates provider/subject,
// renames the handle, and audit-logs the change).
func TestGitHubLoginFlow_EmailLinkRequiresConfirmation(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	ctx := context.Background()

	googleUser := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-1", Email: "alice@example.com", Name: "Alice"}
	if err := env.auth.store.BootstrapFirstUser(ctx, googleUser, "funcbox"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := env.auth.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "alice", InternalUserID: googleUser.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	if err := env.auth.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: "alice@example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	client, location := env.login(t, "code-1", fakeGitHubUser{
		id: 4004, login: "alice-gh",
		emails: []githubEmailResponse{{Email: "alice@example.com", Primary: true, Verified: true}},
	})

	if !strings.HasPrefix(location, "/auth/link/confirm?token=") {
		t.Fatalf("callback redirect = %q, want /auth/link/confirm?token=... (link must be confirmed, not applied immediately)", location)
	}

	// The link must not have taken effect yet.
	reloaded, err := env.auth.store.Users().ByID(ctx, googleUser.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if reloaded.Provider != store.ProviderGoogle {
		t.Fatalf("provider = %q, want still %q before confirmation", reloaded.Provider, store.ProviderGoogle)
	}
	var hasSessionBeforeConfirm bool
	sessionURL, _ := url.Parse(env.server.URL)
	for _, c := range client.Jar.Cookies(sessionURL) {
		if c.Name == sessionCookieName {
			hasSessionBeforeConfirm = true
		}
	}
	if hasSessionBeforeConfirm {
		t.Fatal("a session must not be created before the link is confirmed")
	}

	// GET the confirmation page and assert the handle-change warning
	// renders, mentioning both the target email and the new (GitHub)
	// handle.
	confirmResp, err := client.Get(env.server.URL + location)
	if err != nil {
		t.Fatalf("GET confirm page: %v", err)
	}
	defer confirmResp.Body.Close()
	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("GET confirm page status = %d, want 200", confirmResp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(confirmResp.Body)
	if err != nil {
		t.Fatalf("read confirm page body: %v", err)
	}
	body := string(bodyBytes)
	if !strings.Contains(body, "alice-gh") {
		t.Errorf("confirmation page does not mention the new handle %q:\n%s", "alice-gh", body)
	}
	if !strings.Contains(strings.ToLower(body), "handle") {
		t.Errorf("confirmation page does not mention the handle change at all:\n%s", body)
	}

	// Extract the hidden token field to submit the confirmation form.
	const marker = `name="token" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("confirmation page has no hidden token field:\n%s", body)
	}
	rest := body[idx+len(marker):]
	token := rest[:strings.Index(rest, `"`)]

	form := url.Values{"token": {token}}
	client2 := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	submitResp, err := client2.PostForm(env.server.URL+"/auth/link/confirm", form)
	if err != nil {
		t.Fatalf("POST confirm: %v", err)
	}
	submitResp.Body.Close()
	if submitResp.StatusCode != http.StatusFound || !strings.HasPrefix(submitResp.Header.Get("Location"), "/dashboard") {
		t.Fatalf("POST confirm status/location = %d/%q, want 302 to /dashboard", submitResp.StatusCode, submitResp.Header.Get("Location"))
	}

	// The link must have taken effect now: provider/subject/handle
	// updated, an audit row recorded.
	linked, err := env.auth.store.Users().ByID(ctx, googleUser.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if linked.Provider != store.ProviderGitHub || linked.ProviderSubject != "4004" {
		t.Fatalf("provider/subject = %q/%q, want %q/%q", linked.Provider, linked.ProviderSubject, store.ProviderGitHub, "4004")
	}
	pid, err := env.auth.store.PublicUserIDs().ByOwner(ctx, googleUser.ID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByOwner: %v", err)
	}
	if pid.UserID != "alice-gh" {
		t.Fatalf("handle after link = %q, want %q", pid.UserID, "alice-gh")
	}
	if _, err := env.auth.store.PublicUserIDs().ByUserID(ctx, "alice"); err == nil {
		t.Fatal("the old handle \"alice\" should no longer resolve after the link renamed it")
	}

	logs, err := env.auth.store.Audit().List(ctx, "", 20)
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	var foundLinkAudit bool
	for _, l := range logs {
		if l.Action == "user.provider.link" && l.ActorID == googleUser.ID {
			foundLinkAudit = true
			var detail map[string]any
			if err := json.Unmarshal(l.Detail, &detail); err != nil {
				t.Fatalf("unmarshal audit detail: %v", err)
			}
			if detail["new_handle"] != "alice-gh" {
				t.Errorf("audit detail new_handle = %v, want %q", detail["new_handle"], "alice-gh")
			}
			if detail["old_handle"] != "alice" {
				t.Errorf("audit detail old_handle = %v, want %q", detail["old_handle"], "alice")
			}
		}
	}
	if !foundLinkAudit {
		t.Error("no user.provider.link audit row found for the linked account")
	}

	// The now-linked session must authenticate.
	var hasSessionAfterConfirm bool
	for _, c := range client2.Jar.Cookies(sessionURL) {
		if c.Name == sessionCookieName {
			hasSessionAfterConfirm = true
		}
	}
	if !hasSessionAfterConfirm {
		t.Fatal("no session cookie set after confirming the account link")
	}
}

// TestGitHubLoginFlow_LinkTargetHandleAlreadyTaken exercises the corner
// case where the GitHub-derived handle collides with a THIRD account (not
// the one being linked): the link must be refused outright, since GitHub's
// fixed-handle rule leaves no fallback name to offer instead.
func TestGitHubLoginFlow_LinkTargetHandleAlreadyTaken(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	ctx := context.Background()

	googleUser := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-1", Email: "alice@example.com", Name: "Alice"}
	if err := env.auth.store.BootstrapFirstUser(ctx, googleUser, "funcbox"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := env.auth.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "alice", InternalUserID: googleUser.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	// A third, unrelated user already occupies the handle the GitHub
	// login would need to claim.
	third := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-2", Email: "bob@example.com", Name: "Bob", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := env.auth.store.Users().Create(ctx, third); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := env.auth.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "alice-gh", InternalUserID: third.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	if err := env.auth.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: "alice@example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	_, location := env.login(t, "code-1", fakeGitHubUser{
		id: 4004, login: "alice-gh",
		emails: []githubEmailResponse{{Email: "alice@example.com", Primary: true, Verified: true}},
	})

	if strings.HasPrefix(location, "/auth/link/confirm") || !strings.Contains(location, "login_error") {
		t.Fatalf("redirect = %q, want a login_error denial (target handle already taken)", location)
	}
	reloaded, err := env.auth.store.Users().ByID(ctx, googleUser.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if reloaded.Provider != store.ProviderGoogle {
		t.Fatalf("provider = %q, want unchanged %q", reloaded.Provider, store.ProviderGoogle)
	}
}
