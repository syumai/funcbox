package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

func newInvokeSSOAuth(t *testing.T) (*Auth, store.Store, *store.User, *store.Function) {
	t.Helper()
	st := newTestStore(t)
	u := &store.User{ID: store.NewID(), Provider: store.ProviderGoogle, ProviderSubject: "invoke-sub", Email: "invoke@example.com", Name: "Invoke"}
	if err := st.BootstrapFirstUser(context.Background(), u, "Test"); err != nil {
		t.Fatal(err)
	}
	if err := st.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{{
		Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow,
	}}); err != nil {
		t.Fatal(err)
	}
	fn := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: u.ID, Name: "report"}
	if err := st.Functions().Create(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Mode: ModeDev, BaseURL: "http://dashboard.example.test", ControlOrigin: "http://dashboard.example.test",
		FunctionDomain: "run.example.test", ListenAddr: "127.0.0.1:8080", SessionSecret: "invoke-test-secret"}, st)
	if err != nil {
		t.Fatal(err)
	}
	return a, st, u, fn
}

func TestInvokeCallbackConsumesCodeAndBindsCookie(t *testing.T) {
	a, st, u, fn := newInvokeSSOAuth(t)
	raw := "one-time-secret"
	code := &store.InvokeAuthCode{ID: hashInvokeValue(raw), UserID: u.ID, FunctionID: fn.ID,
		Host: "report.run.example.test", ReturnTo: "/items?q=1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := st.InvokeAuthCodes().Create(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://report.run.example.test/.funcbox/auth/callback?code="+raw, nil)
	rec := httptest.NewRecorder()
	a.HandleInvokeCallback(rec, req, fn, req.Host)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != code.ReturnTo {
		t.Fatalf("response = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var invokeCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.invokeCookieName() {
			invokeCookie = c
		}
	}
	if invokeCookie == nil || !invokeCookie.HttpOnly || invokeCookie.Domain != "" || invokeCookie.Path != "/" {
		t.Fatalf("cookie = %#v", invokeCookie)
	}
	if claims, err := a.parseInvokeCookie(invokeCookie.Value, fn.ID, "report.run.example.test"); err != nil {
		t.Fatalf("parseInvokeCookie: %v (fn=%q cookie=%q)", err, fn.ID, invokeCookie.Value)
	} else if claims.UserID != u.ID {
		t.Fatalf("claims user = %q, want %q", claims.UserID, u.ID)
	}
	authed := httptest.NewRequest(http.MethodGet, "http://report.run.example.test/items", nil)
	authed.AddCookie(invokeCookie)
	if got, err := a.ResolveInvokeCookie(authed, fn.ID, authed.Host); err != nil || got.ID != u.ID {
		t.Fatalf("ResolveInvokeCookie = %#v, %v", got, err)
	}
	replay := httptest.NewRecorder()
	a.HandleInvokeCallback(replay, req, fn, req.Host)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d", replay.Code)
	}
}

func TestInvokeCallbackRejectsWrongAudienceWithoutConsuming(t *testing.T) {
	a, st, u, fn := newInvokeSSOAuth(t)
	raw := "audience-secret"
	code := &store.InvokeAuthCode{ID: hashInvokeValue(raw), UserID: u.ID, FunctionID: fn.ID,
		Host: "report.run.example.test", ReturnTo: "/", ExpiresAt: time.Now().Add(time.Minute)}
	if err := st.InvokeAuthCodes().Create(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	wrong := httptest.NewRequest(http.MethodGet, "http://other.run.example.test/.funcbox/auth/callback?code="+raw, nil)
	rec := httptest.NewRecorder()
	a.HandleInvokeCallback(rec, wrong, fn, wrong.Host)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong-host status = %d", rec.Code)
	}
	good := httptest.NewRequest(http.MethodGet, "http://report.run.example.test/.funcbox/auth/callback?code="+raw, nil)
	rec = httptest.NewRecorder()
	a.HandleInvokeCallback(rec, good, fn, good.Host)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("good status after mismatch = %d", rec.Code)
	}
}

// TestResolveInvokeCookie_DistinguishesForbiddenFromUnauthenticated covers
// the redirect-loop fix: a cookie that resolves to a real user who simply
// isn't authorized right now
// (pending approval here) must report ErrInvokeForbidden, NOT
// ErrUnauthenticated -- server/internal/invoke's authorize() relies on that
// distinction to avoid redirecting such a user through the login/SSO flow
// forever (see ErrInvokeForbidden's doc comment). A missing cookie, by
// contrast, is the ordinary "please log in" case and must stay
// ErrUnauthenticated.
func TestResolveInvokeCookie_DistinguishesForbiddenFromUnauthenticated(t *testing.T) {
	a, st, u, fn := newInvokeSSOAuth(t)

	raw := "pending-user-secret"
	code := &store.InvokeAuthCode{ID: hashInvokeValue(raw), UserID: u.ID, FunctionID: fn.ID,
		Host: "report.run.example.test", ReturnTo: "/", ExpiresAt: time.Now().Add(time.Minute)}
	if err := st.InvokeAuthCodes().Create(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	callback := httptest.NewRequest(http.MethodGet, "http://report.run.example.test/.funcbox/auth/callback?code="+raw, nil)
	rec := httptest.NewRecorder()
	a.HandleInvokeCallback(rec, callback, fn, callback.Host)
	var invokeCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == a.invokeCookieName() {
			invokeCookie = c
		}
	}
	if invokeCookie == nil {
		t.Fatal("HandleInvokeCallback did not set an invoke cookie")
	}

	req := httptest.NewRequest(http.MethodGet, "http://report.run.example.test/items", nil)
	req.AddCookie(invokeCookie)

	// Sanity: the freshly-minted cookie works while the user is active.
	if _, err := a.ResolveInvokeCookie(req, fn.ID, req.Host); err != nil {
		t.Fatalf("ResolveInvokeCookie(active user) = %v, want nil", err)
	}

	// The SAME cookie, once the underlying user is no longer active
	// (pending approval is used here as the concrete §13.3 case; disabled
	// and login-rule denial take the identical path through
	// validateActiveUser): must report ErrInvokeForbidden, and specifically
	// NOT ErrUnauthenticated.
	u.Status = store.UserStatusPending
	if err := st.Users().Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	_, err := a.ResolveInvokeCookie(req, fn.ID, req.Host)
	if !errors.Is(err, ErrInvokeForbidden) {
		t.Fatalf("ResolveInvokeCookie(pending user, valid cookie) = %v, want ErrInvokeForbidden", err)
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Fatal("ResolveInvokeCookie(pending user, valid cookie) also satisfies ErrUnauthenticated -- these must stay distinguishable, or the redirect-loop guard in invoke.go's authorize() has nothing to switch on")
	}

	// No cookie at all is the ordinary case, and must stay ErrUnauthenticated.
	noCookie := httptest.NewRequest(http.MethodGet, "http://report.run.example.test/items", nil)
	if _, err := a.ResolveInvokeCookie(noCookie, fn.ID, noCookie.Host); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ResolveInvokeCookie(no cookie) = %v, want ErrUnauthenticated", err)
	}
}

// TestHandleInvokeStart_CallbackTargetPreservesControlURLPort covers a real
// server bug: with FUNCBOX_CONTROL_URL carrying an explicit listener port
// (e.g. http://localhost:18080), handleInvokeStart's redirect Location to
// the function host's own /.funcbox/auth/callback dropped that port,
// sending a real browser to the function host's default port (80) instead
// of the actual listener -- ERR_CONNECTION_REFUSED. Function hosts are
// served by the exact same listener as the control origin, so the
// generated callback target must carry the same explicit port.
func TestHandleInvokeStart_CallbackTargetPreservesControlURLPort(t *testing.T) {
	st := newTestStore(t)
	u := &store.User{ID: store.NewID(), Provider: store.ProviderGoogle, ProviderSubject: "invoke-sub", Email: "invoke@example.com", Name: "Invoke"}
	if err := st.BootstrapFirstUser(context.Background(), u, "Test"); err != nil {
		t.Fatal(err)
	}
	if err := st.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{{
		Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow,
	}}); err != nil {
		t.Fatal(err)
	}
	fn := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: u.ID, Name: "vinext"}
	if err := st.Functions().Create(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Mode: ModeDev, BaseURL: "http://localhost:18080", ControlOrigin: "http://localhost:18080",
		FunctionDomain: "fn.localhost", ListenAddr: "127.0.0.1:18080", SessionSecret: "invoke-port-test-secret"}, st)
	if err != nil {
		t.Fatal(err)
	}

	// Log the user in directly (bypassing the OIDC round trip, which is
	// exercised elsewhere) by minting a session and setting its cookie the
	// same way a real login would.
	_, rawToken, err := a.createSession(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:18080/auth/invoke?function=vinext&host=vinext.fn.localhost&return_to=%2F", nil)
	req.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: rawToken})
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /auth/invoke status = %d, body = %q, want 303", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	const want = "http://vinext.fn.localhost:18080/.funcbox/auth/callback?code="
	if !strings.HasPrefix(loc, want) {
		t.Fatalf("Location = %q, want prefix %q (the control listener's port must be preserved)", loc, want)
	}
}

func TestValidLocalReturnTo(t *testing.T) {
	for _, good := range []string{"/", "/items?q=1", "/owner/fn/sub?x=1&y=2"} {
		if !validLocalReturnTo(good) {
			t.Errorf("rejected %q", good)
		}
	}
	for _, bad := range []string{
		"",
		"https://evil.test/",
		"HTTPS://evil.test/", // mixed/upper-case scheme -- still an absolute URL
		"HtTpS://evil.test/", // mixed-case scheme, different casing pattern
		"http://evil.test",   // no trailing slash
		"//evil.test/",       // protocol-relative
		"///evil.test/",      // triple slash, still protocol-relative in browsers
		"/\\evil.test/",      // backslash normalizes to "//" in real browsers
		"\\/evil.test/",      // leading backslash
		"/x\r\nLocation: x",  // CRLF header injection
		"/x\ny",              // bare LF
		"/" + strings.Repeat("a", maxReturnToLength), // one over the cap
	} {
		if validLocalReturnTo(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	// Exactly at the cap must still be accepted.
	if atCap := "/" + strings.Repeat("a", maxReturnToLength-1); !validLocalReturnTo(atCap) {
		t.Errorf("rejected return_to at exactly the %d-byte cap", maxReturnToLength)
	}
}
