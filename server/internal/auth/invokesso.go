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
	invokeCallbackPath = "/.funcbox/auth/callback"
	// invokeCookieName / invokeCookieNameInsecure: see sessionCookieName's
	// doc comment in session.go for why there are two names and how
	// (*Auth).invokeCookieName picks between them.
	invokeCookieName         = "__Host-fbx_invoke"
	invokeCookieNameInsecure = "fbx_invoke_insecure"
	invokeCodeLifetime       = 60 * time.Second
	invokeCookieLifetime     = 8 * time.Hour

	// maxReturnToLength caps every next/return_to value this package
	// accepts (this function, and login.go's sanitizeReturnTo, which
	// delegates to it). There's no legitimate reason a same-origin path
	// needs to be long; capping it keeps a malformed or adversarial value
	// from bloating the signed OAuth state cookie (login.go) or a
	// Location: response header.
	maxReturnToLength = 2048
)

type invokeCookieClaims struct {
	UserID, FunctionID, Host string
	ExpiresAt                int64
}

// invokeCookieName returns the name this deployment uses for the browser
// SSO invoke cookie; see sessionCookieName's doc comment in session.go.
func (a *Auth) invokeCookieName() string {
	if a.secureCookies() {
		return invokeCookieName
	}
	return invokeCookieNameInsecure
}

// validLocalReturnTo is the single open-redirect guard shared by every
// next/return_to consumer in this package (14.3's "同一オリジンの相対パス
// のみ許可"): the /auth/login and /auth/invoke query params, the OAuth
// state cookie's ReturnTo (revalidated at the callback in login.go, since
// this same function gates what it's allowed to hold in the first place),
// and the invoke SSO round trip's stored InvokeAuthCode.ReturnTo
// (revalidated in HandleInvokeCallback below). It accepts ONLY a path that
// starts with exactly one '/', rejecting:
//   - a protocol-relative "//host" URL ("//evil.example");
//   - a backslash anywhere -- browsers normalize "/\evil.example" to
//     "//evil.example" before navigating, the same open-redirect trick
//     wearing a different byte;
//   - any CR/LF (which could inject extra header lines into a raw
//     Location: response) or other control character;
//   - anything longer than maxReturnToLength;
//   - anything url.ParseRequestURI parses as absolute or carrying a Host
//     (this is what actually rules out "https://evil.example",
//     "HTTPS://evil.example", etc. -- their scheme prefix already fails
//     the leading-"/" check above, so this is a second, independent line
//     of defense against any value that somehow slipped past it).
func validLocalReturnTo(s string) bool {
	if s == "" || len(s) > maxReturnToLength {
		return false
	}
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return false
	}
	if strings.ContainsAny(s, "\\\r\n") {
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

// SameOriginInvokeHost reports whether host (an incoming invoke request's
// r.Host) is this deployment's own control-plane origin rather than a
// distinct managed-function host. It's the mode switch every invoke-path
// caller in this file and in server/internal/invoke needs: in path-based
// mode (FUNCBOX_FUNCTION_DOMAIN unset -- the README quick-start's
// BASE_URL/{owner}/{name} deployment), a function is always invoked on the
// SAME origin as the dashboard/API/login, so this is unconditionally true
// and the browser's ordinary session cookie is a valid same-origin
// credential; the cross-origin browser SSO handoff (handleInvokeStart /
// HandleInvokeCallback / the invoke cookie) only makes sense, and is only
// reachable at all, once FunctionDomain actually separates function hosts
// from the control origin -- see config.validateHosting, which refuses to
// start a deployment where a managed function host could ever collide with
// the control host.
func (a *Auth) SameOriginInvokeHost(host string) bool {
	if a.cfg.FunctionDomain == "" {
		return true
	}
	h, ok := normalizedHost(host)
	return ok && h == a.controlHost
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
	// This endpoint only exists to hand a credential from the control
	// origin off to a DISTINCT managed function host (FunctionDomain
	// configured, host != the control origin itself) -- see
	// SameOriginInvokeHost's doc comment. Reached any other way (no
	// FunctionDomain at all, or host happens to equal the control origin --
	// a stale bookmark/link left over from a config change, since a
	// same-origin invoke never generates one of these URLs anymore, see
	// invoke.go's authorize) there is nothing to hand off: the session
	// cookie the caller already just proved they have IS a valid same-origin
	// credential for host already, so degrade to a plain same-origin
	// redirect back to where they were headed instead of a confusing 400.
	if a.cfg.FunctionDomain == "" || (ok && host == a.controlHost) {
		returnTo := r.URL.Query().Get("return_to")
		if !validLocalReturnTo(returnTo) || strings.HasPrefix(returnTo, "/.funcbox/") {
			returnTo = defaultReturnTo
		}
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}
	if !ok || host != a.managedFunctionHost(fn.Name) {
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
	http.SetCookie(w, &http.Cookie{Name: a.invokeCookieName(), Value: token, Path: "/", HttpOnly: true,
		Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: int(invokeCookieLifetime.Seconds())})
	// code.ReturnTo was already validated (validLocalReturnTo) before being
	// stored, back in handleInvokeStart -- this re-check is defense in
	// depth, not load-bearing, so every next/return_to VALUE this package
	// ever redirects to has gone through the exact same guard right before
	// use, not just at the point it was first accepted.
	returnTo := code.ReturnTo
	if !validLocalReturnTo(returnTo) {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// resolveInvokeSessionCookie resolves a same-origin invoke caller directly
// from the dashboard's own session cookie (never a bearer token) -- the
// path-based/same-origin mode's counterpart to ResolveInvokeCookie's
// cross-origin SSO cookie (see SameOriginInvokeHost, its caller's mode
// switch). It's read-only: unlike authenticateSession (session.go), it
// deliberately does NOT call Sessions().Refresh -- an invoke request is not
// a dashboard visit, and refreshing the session's sliding expiry on every
// function call would extend it far past what a user's actual dashboard
// activity implies.
//
// It applies the same strict active-user check every other invoke
// caller-resolution path does (validateActiveUser, not the dashboard/API's
// lenient validateAuthenticatable): a pending user must resolve as
// not-a-member for invocation purposes, exactly like a disabled one.
func (a *Auth) resolveInvokeSessionCookie(r *http.Request) (*store.User, error) {
	c, err := r.Cookie(a.sessionCookieName())
	if err != nil {
		return nil, ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	sess, err := a.store.Sessions().Get(r.Context(), sha256Hex(raw), time.Now())
	if err != nil {
		return nil, ErrUnauthenticated
	}
	u, err := a.store.Users().ByID(r.Context(), sess.UserID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return a.validateActiveUser(r.Context(), u)
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
// the user and login rules on every invocation. It returns ErrUnauthenticated
// when there's no usable cookie at all (missing, malformed, expired, wrong
// function/host, or naming a since-deleted user) and ErrInvokeForbidden
// when the cookie DOES resolve to a real, current user who simply isn't
// (or is no longer) authorized -- see ErrInvokeForbidden's doc comment for
// why callers (invoke.go's authorize) must treat those two differently.
func (a *Auth) ResolveInvokeCookie(r *http.Request, functionID, host string) (*store.User, error) {
	c, err := r.Cookie(a.invokeCookieName())
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
