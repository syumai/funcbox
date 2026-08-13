package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

const (
	invokeCallbackPath   = "/.funcbox/auth/callback"
	invokeCookieName     = "__Host-fbx_invoke"
	invokeCodeLifetime   = 60 * time.Second
	invokeCookieLifetime = 8 * time.Hour
)

type invokeCookieClaims struct {
	UserID, FunctionID, Host string
	ExpiresAt                int64
}

func validLocalReturnTo(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\\r\n") {
		return false
	}
	u, err := url.ParseRequestURI(s)
	return err == nil && u.IsAbs() == false && u.Host == ""
}

func normalizedHost(hostport string) (string, bool) {
	if hostport == "" || strings.ContainsAny(hostport, "\\/@ \t\r\n") {
		return "", false
	}
	if u, err := url.Parse("//" + hostport); err == nil && u.Port() != "" {
		hostport = u.Hostname()
	} else if strings.Contains(hostport, ":") {
		return "", false
	}
	h := strings.ToLower(strings.TrimSuffix(hostport, "."))
	return h, h != ""
}

func (a *Auth) managedFunctionHost(name string) string {
	return strings.ToLower(name + "." + strings.TrimSuffix(a.cfg.FunctionDomain, "."))
}

// InvokeLoginURL creates a control-plane URL for an unauthenticated HTML
// navigation. No credential is placed in this URL.
func (a *Auth) InvokeLoginURL(fn *store.Function, host, returnTo string) string {
	q := url.Values{"function": {fn.Name}, "host": {host}, "return_to": {returnTo}}
	return strings.TrimSuffix(a.cfg.ControlOrigin, "/") + "/auth/invoke?" + q.Encode()
}

func (a *Auth) handleInvokeStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	actor, err := a.AuthenticateSessionCookie(r)
	if err != nil {
		http.Redirect(w, r, LoginURL(r.URL.RequestURI()), http.StatusFound)
		return
	}
	name := r.URL.Query().Get("function")
	fn, err := a.store.Functions().ByName(r.Context(), name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	host, ok := normalizedHost(r.URL.Query().Get("host"))
	if !ok || a.cfg.FunctionDomain == "" || host != a.managedFunctionHost(fn.Name) {
		http.Error(w, "invalid function host", http.StatusBadRequest)
		return
	}
	returnTo := r.URL.Query().Get("return_to")
	if !validLocalReturnTo(returnTo) || strings.HasPrefix(returnTo, "/.funcbox/") {
		http.Error(w, "invalid return path", http.StatusBadRequest)
		return
	}
	raw := randomURLToken(32)
	code := &store.InvokeAuthCode{ID: hashInvokeValue(raw), UserID: actor.User.ID,
		FunctionID: fn.ID, Host: host, ReturnTo: returnTo, ExpiresAt: time.Now().Add(invokeCodeLifetime)}
	if err := a.store.InvokeAuthCodes().Create(r.Context(), code); err != nil {
		http.Error(w, "authentication is not available", http.StatusInternalServerError)
		return
	}
	scheme := "https"
	if strings.HasPrefix(a.cfg.BaseURL, "http://") {
		scheme = "http"
	}
	target := scheme + "://" + host + invokeCallbackPath + "?code=" + url.QueryEscape(raw)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// HandleInvokeCallback consumes a browser SSO code before guest dispatch.
func (a *Auth) HandleInvokeCallback(w http.ResponseWriter, r *http.Request, fn *store.Function, host string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	host, ok := normalizedHost(host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	raw := r.URL.Query().Get("code")
	if raw == "" {
		http.Error(w, "invalid authentication code", http.StatusBadRequest)
		return
	}
	code, err := a.store.InvokeAuthCodes().Consume(r.Context(), hashInvokeValue(raw), fn.ID, host, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "invalid or expired authentication code", http.StatusBadRequest)
			return
		}
		http.Error(w, "authentication is not available", http.StatusInternalServerError)
		return
	}
	claims := invokeCookieClaims{UserID: code.UserID, FunctionID: fn.ID, Host: host, ExpiresAt: time.Now().Add(invokeCookieLifetime).Unix()}
	token, err := a.signInvokeCookie(claims)
	if err != nil {
		http.Error(w, "authentication is not available", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: invokeCookieName, Value: token, Path: "/", HttpOnly: true,
		Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: int(invokeCookieLifetime.Seconds())})
	http.Redirect(w, r, code.ReturnTo, http.StatusSeeOther)
}

func hashInvokeValue(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (a *Auth) signInvokeCookie(c invokeCookieClaims) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, a.invokeKey)
	_, _ = m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func (a *Auth) parseInvokeCookie(raw, functionID, host string) (*invokeCookieClaims, error) {
	p, sig, ok := strings.Cut(raw, ".")
	if !ok {
		return nil, ErrUnauthenticated
	}
	m := hmac.New(sha256.New, a.invokeKey)
	_, _ = m.Write([]byte(p))
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, m.Sum(nil)) {
		return nil, ErrUnauthenticated
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var c invokeCookieClaims
	if json.Unmarshal(b, &c) != nil || c.FunctionID != functionID || c.Host != host || time.Now().Unix() >= c.ExpiresAt {
		return nil, ErrUnauthenticated
	}
	return &c, nil
}

// ResolveInvokeCookie validates a function-host credential and rechecks
// the user and login rules on every invocation.
func (a *Auth) ResolveInvokeCookie(r *http.Request, functionID, host string) (*store.User, error) {
	c, err := r.Cookie(invokeCookieName)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	host, ok := normalizedHost(host)
	if !ok {
		return nil, ErrUnauthenticated
	}
	claims, err := a.parseInvokeCookie(c.Value, functionID, host)
	if err != nil {
		return nil, err
	}
	u, err := a.store.Users().ByID(r.Context(), claims.UserID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return a.validateActiveUser(r.Context(), u)
}
