package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

func newInvokeSSOAuth(t *testing.T) (*Auth, store.Store, *store.User, *store.Function) {
	t.Helper()
	st := newTestStore(t)
	u := &store.User{ID: store.NewID(), GoogleSub: "invoke-sub", Email: "invoke@example.com", Name: "Invoke"}
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
		if c.Name == invokeCookieName {
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

func TestValidLocalReturnTo(t *testing.T) {
	for _, good := range []string{"/", "/items?q=1"} {
		if !validLocalReturnTo(good) {
			t.Errorf("rejected %q", good)
		}
	}
	for _, bad := range []string{"", "https://evil.test/", "//evil.test/", "/\\evil.test/", "/x\r\nLocation: x"} {
		if validLocalReturnTo(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
