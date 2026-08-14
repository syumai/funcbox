package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

func testAuth(t *testing.T) *Auth {
	t.Helper()
	st := newTestStore(t)
	a, err := New(Config{
		Mode:          ModeDev,
		BaseURL:       "http://127.0.0.1:8080",
		ListenAddr:    "127.0.0.1:8080",
		SessionSecret: "test-secret-value",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Error("equal strings should compare equal")
	}
	if constantTimeEqual("abc", "abd") {
		t.Error("different strings should not compare equal")
	}
	if constantTimeEqual("abc", "abcd") {
		t.Error("different-length strings should not compare equal")
	}
}

func TestRequireCSRF_SafeMethodsPass(t *testing.T) {
	a := testAuth(t)
	called := false
	h := a.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/functions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("GET request should pass through RequireCSRF without a token")
	}
}

func TestRequireCSRF_BearerTokenExempt(t *testing.T) {
	a := testAuth(t)
	called := false
	h := a.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/functions", nil)
	req = req.WithContext(WithActor(req.Context(), &Actor{
		User: &store.User{ID: "u1"}, Method: MethodAccessToken,
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("bearer-token-authenticated mutating request should be exempt from CSRF")
	}
}

func TestRequireCSRF_SessionWithoutTokenRejected(t *testing.T) {
	a := testAuth(t)
	called := false
	h := a.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/functions", nil)
	req = req.WithContext(WithActor(req.Context(), &Actor{
		User: &store.User{ID: "u1"}, Method: MethodSession, csrfCookie: "csrf-abc",
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called {
		t.Fatal("session-authenticated mutating request without X-CSRF-Token header should be rejected")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRequireCSRF_SessionWithMismatchedTokenRejected(t *testing.T) {
	a := testAuth(t)
	called := false
	h := a.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/functions", nil)
	req.Header.Set(csrfHeaderName, "wrong-token")
	req = req.WithContext(WithActor(req.Context(), &Actor{
		User: &store.User{ID: "u1"}, Method: MethodSession, csrfCookie: "csrf-abc",
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called {
		t.Fatal("mismatched X-CSRF-Token should be rejected")
	}
}

func TestRequireCSRF_SessionWithMatchingTokenPasses(t *testing.T) {
	a := testAuth(t)
	called := false
	h := a.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/functions", nil)
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	req.Header.Set(csrfHeaderName, "csrf-abc")
	req = req.WithContext(WithActor(req.Context(), &Actor{
		User: &store.User{ID: "u1"}, Method: MethodSession, csrfCookie: "csrf-abc",
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called {
		t.Fatal("matching X-CSRF-Token should pass")
	}
}

func TestRequireCSRF_SessionFromOtherOriginRejected(t *testing.T) {
	a := testAuth(t)
	h := a.RequireCSRF(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler called for untrusted Origin")
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/functions", nil)
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set(csrfHeaderName, "csrf-abc")
	req = req.WithContext(WithActor(req.Context(), &Actor{User: &store.User{ID: "u1"}, Method: MethodSession, csrfCookie: "csrf-abc"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestAuthenticate_IgnoresLegacySessionCookie(t *testing.T) {
	a := testAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: legacySessionCookieName, Value: "attacker-controlled"})
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("legacy session cookie was accepted")
	}
}

// TestSetSessionCookies_InsecureDeploymentUsesFallbackNames covers a
// plain-http deployment (testAuth's BaseURL is "http://127.0.0.1:8080"):
// setSessionCookies must NOT use the "__Host-" prefixed names here, since a
// real browser unconditionally discards a "__Host-" cookie whose
// Set-Cookie lacks Secure -- see session.go's sessionCookieName doc
// comment and server/internal/browserjar. It must fall back to the
// distinct, non-prefixed insecure names instead, still expiring the
// legacy unprefixed cookies alongside them.
func TestSetSessionCookies_InsecureDeploymentUsesFallbackNames(t *testing.T) {
	a := testAuth(t)
	rec := httptest.NewRecorder()
	a.setSessionCookies(rec, "session", time.Hour)
	seen := map[string]*http.Cookie{}
	for _, cookie := range rec.Result().Cookies() {
		seen[cookie.Name] = cookie
	}
	for _, name := range []string{sessionCookieNameInsecure, csrfCookieNameInsecure} {
		cookie := seen[name]
		if cookie == nil || cookie.Path != "/" || cookie.Domain != "" || cookie.Secure {
			t.Fatalf("cookie %q = %#v", name, cookie)
		}
	}
	// The "__Host-" prefixed names must never be set at all over plain
	// http: a real browser would discard them anyway, but this is the
	// no-downgrade-path guarantee, checked at the source.
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		if cookie := seen[name]; cookie != nil {
			t.Fatalf("insecure deployment set the __Host- prefixed cookie %q = %#v, want it never set", name, cookie)
		}
	}
	for _, name := range []string{legacySessionCookieName, legacyCSRFCookieName} {
		if cookie := seen[name]; cookie == nil || cookie.MaxAge >= 0 {
			t.Fatalf("legacy cookie %q was not expired: %#v", name, cookie)
		}
	}
}

// TestSetSessionCookies_SecureDeploymentUsesHostPrefixesAndExpiresLegacy is
// TestSetSessionCookies_InsecureDeploymentUsesFallbackNames's https
// counterpart: this is the anti-shadowing hardening (the "__Host-" prefix,
// Secure, Path=/, no Domain) that must NOT regress by this fix -- a
// deployment that CAN be Secure must keep behaving exactly as before.
func TestSetSessionCookies_SecureDeploymentUsesHostPrefixesAndExpiresLegacy(t *testing.T) {
	st := newTestStore(t)
	a, err := New(Config{
		Mode: ModeGoogle, BaseURL: "https://dashboard.example.com",
		SessionSecret: "test-secret-value", ClientID: "id", ClientSecret: "secret",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	a.setSessionCookies(rec, "session", time.Hour)
	seen := map[string]*http.Cookie{}
	for _, cookie := range rec.Result().Cookies() {
		seen[cookie.Name] = cookie
	}
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		if cookie := seen[name]; cookie == nil || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure {
			t.Fatalf("cookie %q = %#v", name, cookie)
		}
	}
	for _, name := range []string{sessionCookieNameInsecure, csrfCookieNameInsecure} {
		if cookie := seen[name]; cookie != nil {
			t.Fatalf("secure deployment set the insecure fallback cookie %q = %#v, want it never set", name, cookie)
		}
	}
	for _, name := range []string{legacySessionCookieName, legacyCSRFCookieName} {
		if cookie := seen[name]; cookie == nil || cookie.MaxAge >= 0 {
			t.Fatalf("legacy cookie %q was not expired: %#v", name, cookie)
		}
	}
}

func TestMiddleware_NoCredentialIs401(t *testing.T) {
	a := testAuth(t)
	called := false
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/functions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called {
		t.Fatal("handler should not be called without a credential")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMiddleware_ValidTokenPasses(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub1", Email: "u1@example.com", Name: "U1", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := a.store.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	plaintext, _, err := a.IssueAccessToken(t.Context(), u.ID, 0)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	var gotActor *Actor
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotActor = ActorFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/functions", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotActor == nil || gotActor.User.ID != u.ID {
		t.Fatalf("actor = %+v, want user %q", gotActor, u.ID)
	}
	if gotActor.Method != MethodAccessToken {
		t.Fatalf("actor.Method = %v, want MethodAccessToken", gotActor.Method)
	}
}

func TestMiddleware_DisabledUserRejected(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub2", Email: "u2@example.com", Name: "U2", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := a.store.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	plaintext, _, err := a.IssueAccessToken(t.Context(), u.ID, 0)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	// Disable the user AFTER minting the token: unlike a session (looked
	// up by opaque id), an access token's claims are self-contained, so
	// this proves the disabled check re-runs on every use (loadActiveUser)
	// rather than being baked into the token at issuance time.
	u.Status = store.UserStatusDisabled
	if err := a.store.Users().Update(t.Context(), u); err != nil {
		t.Fatalf("Users().Update: %v", err)
	}

	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run for a disabled user")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/functions", nil)
	req.Header.Set("Authorization", "Bearer "+plaintext)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSignAndParseState_RoundTrip(t *testing.T) {
	a := testAuth(t)
	st := oauthState{State: "s1", Nonce: "n1", Verifier: "v1", ReturnTo: "/dashboard/foo", IssuedAt: time.Now().Unix()}

	cookieVal, err := a.signState(st)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}
	got, err := a.parseState(cookieVal)
	if err != nil {
		t.Fatalf("parseState: %v", err)
	}
	if got != st {
		t.Fatalf("parseState = %+v, want %+v", got, st)
	}
}

func TestParseState_TamperedFails(t *testing.T) {
	a := testAuth(t)
	st := oauthState{State: "s1", Nonce: "n1", Verifier: "v1", IssuedAt: time.Now().Unix()}
	cookieVal, err := a.signState(st)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}
	tampered := cookieVal + "x"
	if _, err := a.parseState(tampered); err == nil {
		t.Fatal("parseState should reject a tampered cookie value")
	}
}

func TestSanitizeReturnTo(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"/dashboard", "/dashboard"},
		{"", ""},
		{"https://evil.com", ""},
		{"//evil.com", ""},
		{"not-a-path", ""},
	}
	for _, tt := range tests {
		if got := sanitizeReturnTo(tt.in); got != tt.want {
			t.Errorf("sanitizeReturnTo(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func seedAllowAllLoginRule(t *testing.T, st store.Store) {
	t.Helper()
	if err := st.Organizations().ReplaceLoginRules(t.Context(), []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionAllow},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
}
