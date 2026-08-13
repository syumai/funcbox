// login.go implements the /auth/* HTTP handlers: the Authorization Code +
// PKCE login flow (tmp/05-auth-and-permissions.md §5.1) against whichever
// OIDC issuer Auth is configured for (Google, or the dev stub -- see
// provider.go/devidp.go for why the same code runs either way).
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/syumai/funcbox/server/internal/store"
)

const (
	authLoginPath    = "/auth/login"
	authCallbackPath = "/auth/callback"
	authLogoutPath   = "/auth/logout"

	oauthStateCookieName = "fbx_oauth_state"
	oauthStateMaxAge     = 10 * time.Minute

	defaultReturnTo = "/dashboard"
)

// ErrLoginDenied is returned (internally) when a login succeeds at the
// identity provider but the resulting email is not permitted to sign in
// under the organization's current login rules.
var ErrLoginDenied = errors.New("auth: login denied by organization login rules")

// oauthState is what's stashed, HMAC-signed, in the short-lived
// oauthStateCookieName cookie across the redirect to the identity provider
// and back -- there is no server-side storage for it, since it only needs
// to survive one browser round trip.
type oauthState struct {
	State    string `json:"state"`    // echoed back as the OAuth "state" query param
	Nonce    string `json:"nonce"`    // echoed back inside the verified ID token
	Verifier string `json:"verifier"` // PKCE code_verifier
	ReturnTo string `json:"return_to,omitempty"`
	IssuedAt int64  `json:"iat"`
}

// Routes returns the http.Handler serving /auth/login, /auth/callback, and
// /auth/logout. Mount it at "/" (its patterns already carry the "/auth/"
// prefix) in front of every other route.
func (a *Auth) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+authLoginPath, a.handleLogin)
	mux.HandleFunc("GET "+authCallbackPath, a.handleCallback)
	mux.HandleFunc("GET "+authLogoutPath, a.handleLogout)
	mux.HandleFunc("POST "+authLogoutPath, a.handleLogout)
	return mux
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oauthCfg, err := a.oauth2Config(ctx)
	if err != nil {
		http.Error(w, "authentication is not available", http.StatusInternalServerError)
		return
	}

	st := oauthState{
		State:    randomURLToken(16),
		Nonce:    randomURLToken(16),
		Verifier: oauth2.GenerateVerifier(),
		ReturnTo: sanitizeReturnTo(r.URL.Query().Get("return_to")),
		IssuedAt: time.Now().Unix(),
	}
	cookieVal, err := a.signState(st)
	if err != nil {
		http.Error(w, "authentication is not available", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookieName, Value: cookieVal, Path: "/auth",
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode,
		MaxAge: int(oauthStateMaxAge.Seconds()),
	})

	authURL := oauthCfg.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *Auth) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie, cookieErr := r.Cookie(oauthStateCookieName)
	http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookieName, Value: "", Path: "/auth", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
	if cookieErr != nil {
		a.loginFailed(w, r, "missing OAuth state cookie (it may have expired -- try logging in again)")
		return
	}
	st, err := a.parseState(cookie.Value)
	if err != nil {
		a.loginFailed(w, r, "invalid or expired OAuth state")
		return
	}

	if providerErr := r.URL.Query().Get("error"); providerErr != "" {
		a.loginFailed(w, r, "identity provider returned an error: "+providerErr)
		return
	}
	if r.URL.Query().Get("state") != st.State {
		a.loginFailed(w, r, "OAuth state mismatch")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.loginFailed(w, r, "missing authorization code")
		return
	}

	oauthCfg, err := a.oauth2Config(ctx)
	if err != nil {
		a.loginFailed(w, r, "authentication is not available")
		return
	}
	token, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		a.loginFailed(w, r, "token exchange failed")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		a.loginFailed(w, r, "identity provider response had no id_token")
		return
	}

	verifier, err := a.verifier(ctx)
	if err != nil {
		a.loginFailed(w, r, "authentication is not available")
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		a.loginFailed(w, r, "id token verification failed")
		return
	}
	if idToken.Nonce != st.Nonce {
		a.loginFailed(w, r, "id token nonce mismatch")
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		a.loginFailed(w, r, "failed to decode id token claims")
		return
	}
	if claims.Email == "" || !claims.EmailVerified {
		a.loginFailed(w, r, "email address is not verified by the identity provider")
		return
	}

	user, err := a.upsertUser(ctx, idToken.Subject, claims.Email, claims.Name)
	if err != nil {
		if errors.Is(err, ErrLoginDenied) {
			a.loginFailed(w, r, "this email address is not permitted to sign in")
			return
		}
		a.loginFailed(w, r, "failed to complete sign-in")
		return
	}

	_, rawSessionToken, err := a.createSession(ctx, user.ID)
	if err != nil {
		a.loginFailed(w, r, "failed to create session")
		return
	}
	a.setSessionCookies(w, rawSessionToken, a.sessionDuration(ctx))

	_ = Audit(ctx, a.store, user.ID, "user.login", "user:"+user.ID, map[string]string{"email": user.Email})

	returnTo := st.ReturnTo
	if returnTo == "" {
		returnTo = defaultReturnTo
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil {
			_ = a.store.Sessions().Delete(r.Context(), sha256Hex(raw))
		}
	}
	a.clearSessionCookies(w)
	http.Redirect(w, r, defaultReturnTo, http.StatusFound)
}

// loginFailed redirects to the dashboard's login-error landing page rather
// than rendering an error page itself, since /auth/* has no HTML templates
// of its own (that's the dashboard's job in Phase 3). The message is
// carried as a query parameter for the dashboard to display.
func (a *Auth) loginFailed(w http.ResponseWriter, r *http.Request, message string) {
	u := defaultReturnTo + "?login_error=" + url.QueryEscape(message)
	http.Redirect(w, r, u, http.StatusFound)
}

// sanitizeReturnTo only allows an absolute path (no scheme/host) so
// return_to can't be abused as an open redirect.
func sanitizeReturnTo(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return ""
	}
	return s
}

// signState HMAC-signs st (keyed by a.csrfKey; state-cookie tampering has
// the same practical impact as CSRF-token tampering, so reusing that
// subkey is fine -- both exist purely to prove "this value came from a
// cookie we set", not to keep anything secret) and encodes it for use as a
// cookie value.
func (a *Auth) signState(st oauthState) (string, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	sig := hmacHex(a.csrfKey, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sig, nil
}

func (a *Auth) parseState(cookieVal string) (oauthState, error) {
	payloadB64, sig, ok := strings.Cut(cookieVal, ".")
	if !ok {
		return oauthState{}, fmt.Errorf("auth: malformed state cookie")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return oauthState{}, fmt.Errorf("auth: malformed state cookie: %w", err)
	}
	if !constantTimeEqual(hmacHex(a.csrfKey, payload), sig) {
		return oauthState{}, fmt.Errorf("auth: state cookie signature mismatch")
	}
	var st oauthState
	if err := json.Unmarshal(payload, &st); err != nil {
		return oauthState{}, fmt.Errorf("auth: malformed state cookie payload: %w", err)
	}
	if time.Since(time.Unix(st.IssuedAt, 0)) > oauthStateMaxAge {
		return oauthState{}, fmt.Errorf("auth: state cookie expired")
	}
	return st, nil
}

// upsertUser resolves an OIDC identity (sub, email, name) to a store.User,
// implementing tmp/05-auth-and-permissions.md §5.1's first-login bootstrap
// and §5.4's per-login-rule gating for every login after that.
func (a *Auth) upsertUser(ctx context.Context, sub, email, name string) (*store.User, error) {
	if u, err := a.store.Users().ByGoogleSub(ctx, sub); err == nil {
		if u.Disabled {
			return nil, ErrLoginDenied
		}
		allowed, err := a.checkLoginRules(ctx, email)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrLoginDenied
		}
		if u.Email != email || (name != "" && u.Name != name) {
			u.Email = email
			if name != "" {
				u.Name = name
			}
			if err := a.store.Users().Update(ctx, u); err != nil {
				return nil, err
			}
		}
		return u, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// New identity. If the organization has no users yet, this is the
	// bootstrap login: it always succeeds (login rules don't apply yet --
	// there'd be nobody able to configure them) and the new user becomes
	// org admin.
	existing, err := a.store.Users().List(ctx)
	if err != nil {
		return nil, err
	}
	if len(existing) == 0 {
		u := &store.User{GoogleSub: sub, Email: email, Name: name}
		err := a.store.BootstrapFirstUser(ctx, u, "funcbox")
		switch {
		case err == nil:
			if err := a.claimHandle(ctx, u); err != nil {
				return nil, err
			}
			if err := a.seedBootstrapLoginRule(ctx, email); err != nil {
				return nil, err
			}
			return u, nil
		case errors.Is(err, store.ErrConflict):
			// Lost the race to bootstrap (a concurrent first login won).
			// Fall through to the normal, rule-gated path below.
		default:
			return nil, err
		}
	}

	allowed, err := a.checkLoginRules(ctx, email)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrLoginDenied
	}

	u := &store.User{GoogleSub: sub, Email: email, Name: name, Role: store.RoleMember}
	if err := a.store.Users().Create(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Another request just created the same user (e.g. a
			// double-submitted callback); look it up and treat it as a
			// normal login rather than failing.
			if existing, lookupErr := a.store.Users().ByGoogleSub(ctx, sub); lookupErr == nil {
				return existing, nil
			}
		}
		return nil, err
	}
	if err := a.claimHandle(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// seedBootstrapLoginRule installs a login rule set for a freshly
// bootstrapped organization: allow the new admin's own exact email
// address, deny everyone else by default.
//
// This is a deliberate addition beyond tmp/05-auth-and-permissions.md
// §5.4's literal text ("初期値は deny + 初回ユーザーのみ例外" describes
// the empty-rule-set behavior, not what gets written after bootstrap).
// Login rules are re-evaluated on every session/token validation, not
// just at login (see loadActiveUser) -- so leaving the rule set empty
// after bootstrap would lock the brand-new admin out of their own very
// next request, since an empty rule set denies everyone unconditionally.
//
// The rule is deliberately email_exact, NOT email_domain: seeding an
// allow rule for the admin's whole domain would silently open the
// organization to every user of that domain, which is catastrophic when
// the admin signed up with a public email provider (gmail.com,
// outlook.com, yahoo.co.jp, ...) -- anyone else with a @gmail.com address
// would then be able to join. email_exact is the smallest rule that
// avoids the session-lockout footgun without introducing that hole; the
// admin can deliberately widen it to their domain (or add teammates)
// via PUT /api/v1/org/login-rules once they've reviewed it.
func (a *Auth) seedBootstrapLoginRule(ctx context.Context, email string) error {
	return a.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: email, Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	})
}

func (a *Auth) claimHandle(ctx context.Context, u *store.User) error {
	handle, err := DeriveHandle(ctx, a.store, u.Email)
	if err != nil {
		return err
	}
	return a.store.Handles().Create(ctx, &store.Handle{
		Handle: handle, OwnerType: store.OwnerTypeUser, OwnerID: u.ID,
	})
}
