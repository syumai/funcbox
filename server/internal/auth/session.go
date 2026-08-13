package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

const (
	sessionCookieName       = "__Host-fbx_session"
	csrfCookieName          = "__Host-fbx_csrf"
	legacySessionCookieName = "fbx_session"
	legacyCSRFCookieName    = "fbx_csrf"
	csrfHeaderName          = "X-CSRF-Token"
)

// ErrUnauthenticated is returned by Authenticate when the request carries
// no usable credential: no session cookie or bearer token, an expired or
// unknown one, a disabled user, or a user no longer permitted to sign in
// "ルール変更で既存ユーザーが対象外になった場合、次回のセッション検証時
// にアクセス拒否となる"). It intentionally doesn't distinguish these
// cases in its error message, mirroring how store.SessionRepo.Get folds
// "unknown" and "expired" together -- a caller shouldn't be able to
// fingerprint *why* a credential was rejected.
var ErrUnauthenticated = errors.New("auth: unauthenticated")

// Authenticate resolves the request's actor from either the session
// cookie or an "Authorization: Bearer fbx_..." API token
// credential -- there is no "anonymous but let the handler decide" mode
// for the management API.
func (a *Auth) Authenticate(r *http.Request) (*Actor, error) {
	ctx := r.Context()

	if hdr := r.Header.Get("Authorization"); hdr != "" {
		raw, ok := strings.CutPrefix(hdr, "Bearer ")
		if !ok || !strings.HasPrefix(raw, TokenPrefix) {
			return nil, ErrUnauthenticated
		}
		return a.authenticateToken(ctx, raw)
	}

	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	csrfCookie := ""
	if cc, err := r.Cookie(csrfCookieName); err == nil {
		csrfCookie = cc.Value
	}
	return a.authenticateSession(ctx, c.Value, csrfCookie)
}

func (a *Auth) authenticateToken(ctx context.Context, raw string) (*Actor, error) {
	tok, err := a.store.Tokens().ByHash(ctx, HashToken(raw))
	if err != nil {
		return nil, ErrUnauthenticated
	}
	if !tok.ExpiresAt.After(time.Now()) {
		return nil, ErrUnauthenticated
	}
	user, err := a.loadActiveUser(ctx, tok.UserID)
	if err != nil {
		return nil, err
	}
	return &Actor{User: user, Method: MethodToken}, nil
}

func (a *Auth) authenticateSession(ctx context.Context, rawCookie, csrfCookie string) (*Actor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(rawCookie)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	hash := sha256Hex(raw)

	now := time.Now()
	sess, err := a.store.Sessions().Get(ctx, hash, now)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	user, err := a.loadActiveUser(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}

	// successful use of the session pushes its expiry back out. Errors
	// here are deliberately non-fatal to the request -- a Refresh that
	// races a concurrent Delete (e.g. this same user logging out from
	// another tab) shouldn't turn an otherwise-valid request into a 401.
	_ = a.store.Sessions().Refresh(ctx, sess.ID, now.Add(a.sessionDuration(ctx)))

	return &Actor{User: user, Method: MethodSession, csrfCookie: csrfCookie}, nil
}

// loadActiveUser loads userID and applies the checks common to every
// authentication path in this package (dashboard session, API token, and
// the invoke path's caller resolution in idtoken.go): the user must not
// be disabled, and must still be permitted to sign in under the
// organization's CURRENT login rules (re-evaluated on every request, not
// just at login time, so a rule change takes effect immediately per
func (a *Auth) loadActiveUser(ctx context.Context, userID string) (*store.User, error) {
	u, err := a.store.Users().ByID(ctx, userID)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return a.validateActiveUser(ctx, u)
}

// loadActiveUserByEmail is loadActiveUser's email-keyed counterpart, used
// by the invoke path (idtoken.go) where an ID token yields an email, not a
// user ID.
func (a *Auth) loadActiveUserByEmail(ctx context.Context, email string) (*store.User, error) {
	u, err := a.store.Users().ByEmail(ctx, email)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return a.validateActiveUser(ctx, u)
}

func (a *Auth) validateActiveUser(ctx context.Context, u *store.User) (*store.User, error) {
	// pending is treated the same as disabled for now: approval isn't
	// implemented yet (tmp/13-public-mode.md §13.3), so only "active" may
	// proceed here.
	if u.Status != store.UserStatusActive {
		return nil, ErrUnauthenticated
	}
	allowed, err := a.checkLoginRules(ctx, u.Email)
	if err != nil {
		return nil, fmt.Errorf("auth: evaluate login rules: %w", err)
	}
	if !allowed {
		return nil, ErrUnauthenticated
	}
	return u, nil
}

// AuthenticateSessionCookie resolves the request's actor from the session
// cookie ONLY (never a bearer token), for callers -- the invoke path's
// distinguish "was there a valid session" from Authenticate's broader
// "was there any valid credential".
func (a *Auth) AuthenticateSessionCookie(r *http.Request) (*Actor, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	csrfCookie := ""
	if cc, err := r.Cookie(csrfCookieName); err == nil {
		csrfCookie = cc.Value
	}
	return a.authenticateSession(r.Context(), c.Value, csrfCookie)
}

// LoginURL builds the /auth/login URL for redirecting an unauthenticated
// browser request, carrying returnTo through so the login flow lands the
// "ログインフローへ誘導").
func LoginURL(returnTo string) string {
	u := authLoginPath
	if returnTo != "" {
		u += "?return_to=" + url.QueryEscape(returnTo)
	}
	return u
}

func (a *Auth) checkLoginRules(ctx context.Context, email string) (bool, error) {
	rules, err := a.store.Organizations().ListLoginRules(ctx)
	if err != nil {
		return false, err
	}
	return EvaluateLoginRules(rules, email), nil
}

// sessionDuration returns the organization's configured sliding session
// duration, falling back to DefaultSessionDuration if unset or the
// organization/settings can't be loaded (fail open on duration only --
// never on the authentication decision itself).
func (a *Auth) sessionDuration(ctx context.Context) time.Duration {
	org, err := a.store.Organizations().Get(ctx)
	if err != nil {
		return DefaultSessionDuration
	}
	s, err := settings.ParseOrg(org.Settings)
	if err != nil || s.SessionDurationSeconds <= 0 {
		return DefaultSessionDuration
	}
	return time.Duration(s.SessionDurationSeconds) * time.Second
}

// createSession creates a new server-side session for userID and returns
// it along with the raw (unhashed) token to set in the cookie.
func (a *Auth) createSession(ctx context.Context, userID string) (*store.Session, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("auth: generate session token: %w", err)
	}
	rawStr := base64.RawURLEncoding.EncodeToString(raw)

	s := &store.Session{
		ID:        sha256Hex(raw),
		UserID:    userID,
		ExpiresAt: time.Now().Add(a.sessionDuration(ctx)),
	}
	if err := a.store.Sessions().Create(ctx, s); err != nil {
		return nil, "", err
	}
	return s, rawStr, nil
}

// setSessionCookies writes the HttpOnly session cookie and the readable
// CSRF double-submit cookie together, since both are minted at login and
// share the same lifetime.
func (a *Auth) setSessionCookies(w http.ResponseWriter, rawSessionToken string, maxAge time.Duration) {
	secure := a.secureCookies()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: rawSessionToken, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(maxAge.Seconds()),
	})

	csrfToken := randomURLToken(16)
	http.SetCookie(w, &http.Cookie{
		// Deliberately NOT HttpOnly: dashboard JS must be able to read
		// this value to echo it back in the X-CSRF-Token header (the
		// double-submit pattern's whole mechanism).
		Name: csrfCookieName, Value: csrfToken, Path: "/",
		HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(maxAge.Seconds()),
	})
	// Remove legacy unprefixed cookies. They could be shadowed from a
	// sibling function origin via Domain= and are never accepted again.
	for _, name := range [...]string{legacySessionCookieName, legacyCSRFCookieName} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == legacySessionCookieName, Secure: secure, SameSite: http.SameSiteLaxMode})
	}
}

// clearSessionCookies expires both cookies set by setSessionCookies, for
// logout.
func (a *Auth) clearSessionCookies(w http.ResponseWriter) {
	secure := a.secureCookies()
	for _, name := range [...]string{sessionCookieName, csrfCookieName, legacySessionCookieName, legacyCSRFCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == sessionCookieName || name == legacySessionCookieName, Secure: secure, SameSite: http.SameSiteLaxMode,
		})
	}
}

// Middleware resolves the request's Actor via Authenticate and attaches it
// to the request context, rejecting the request with 401 if
// authentication fails. Mount it in front of every /api/v1/* route
// authentication).
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, err := a.Authenticate(r)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	})
}

// RequireCSRF enforces the double-submit CSRF token on mutating requests
// "Cookie 利用時の書き込み系は CSRF トークン（double submit）必須").
// Bearer-token requests are exempt: a browser never attaches a custom
// Authorization header automatically the way it does a cookie, so a
// forged cross-site request can't carry one, and requiring CSRF there
// would break every non-browser API client for no security benefit. Must
// run after Middleware (it reads the Actor from context).
func (a *Auth) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		actor := ActorFromContext(r.Context())
		if actor == nil || actor.Method != MethodSession {
			next.ServeHTTP(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin == "" || origin == "null" || origin != a.cfg.ControlOrigin {
			writeAuthError(w, http.StatusForbidden, "origin_failed", "request Origin is not the configured control origin")
			return
		}
		header := r.Header.Get(csrfHeaderName)
		if header == "" || actor.csrfCookie == "" || !constantTimeEqual(header, actor.csrfCookie) {
			writeAuthError(w, http.StatusForbidden, "csrf_failed", "missing or invalid "+csrfHeaderName+" header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// randomURLToken returns a base64url-encoded random token of n raw bytes.
func randomURLToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read failing means the platform's CSPRNG is broken;
		// there is no safe fallback.
		panic(fmt.Sprintf("auth: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// writeAuthError writes the standard {"error":{code,message}} envelope
// here rather than imported from internal/api to avoid an import cycle
// (internal/api imports internal/auth, not the other way around).
func writeAuthError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}
	body.Error.Code = code
	body.Error.Message = message
	_ = json.NewEncoder(w).Encode(body)
}

// hmacHex is a small helper used by the OAuth state cookie's integrity
// check (login.go).
func hmacHex(key []byte, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
