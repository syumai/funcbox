// login.go implements the /auth/* HTTP handlers: the Authorization Code +
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

	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/webpage"
)

const (
	authLoginPath    = "/auth/login"
	authCallbackPath = "/auth/callback"
	authLogoutPath   = "/auth/logout"

	// oauthStateCookieName / oauthStateCookieNameInsecure: see
	// sessionCookieName's doc comment in session.go for why there are two
	// names and how (*Auth).oauthStateCookieName picks between them. This
	// cookie has the identical "__Host-" over-plain-http bug the others
	// do -- it is not one of the three the design doc for this fix names
	// explicitly, but it gates the very first hop of every login (both
	// OIDC/dev and GitHub share setOAuthStateCookie/consumeOAuthStateCookie
	// below), so leaving it unfixed would still make login impossible over
	// plain http even after the session/CSRF/invoke cookies were fixed.
	oauthStateCookieName         = "__Host-fbx_oauth_state"
	oauthStateCookieNameInsecure = "fbx_oauth_state_insecure"
	legacyOAuthStateCookieName   = "fbx_oauth_state"
	oauthStateMaxAge             = 10 * time.Minute

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
	mux.HandleFunc("GET /auth/invoke", a.handleInvokeStart)
	mux.HandleFunc("GET /auth/link/confirm", a.handleLinkConfirmForm)
	mux.HandleFunc("POST /auth/link/confirm", a.handleLinkConfirmSubmit)
	return mux
}

// oauthStateCookieNamePrefix returns the name this deployment uses as the
// BASE of the OAuth state cookie name; see sessionCookieName's doc comment
// in session.go for the secure/insecure split this picks between.
//
// Each login start gets its OWN cookie, named
// "<prefix>-<state>" (oauthStateCookieName below) -- not one shared cookie
// -- so that two overlapping login attempts from the same browser (e.g.
// `funcbox login` both auto-opening a browser tab AND printing the URL, so
// a user who follows both ends up with two /auth/login starts in the same
// cookie jar) don't clobber each other. Before this, a second start's
// Set-Cookie silently overwrote the first's single pending-state cookie,
// so completing the FIRST start's form failed at the callback with "OAuth
// state mismatch" even though nothing about that attempt was wrong.
//
// Per-state cookie names (rather than one cookie holding a bounded list of
// pending states) is the simpler of the two designs that support this:
// there is no shared value to size-cap or prune server-side at all -- every
// cookie already carries oauthStateMaxAge and a real browser (or
// net/http/cookiejar) discards it on its own once that elapses, exactly
// like the single-state cookie did before. The state itself (a 128-bit
// random token from randomURLToken, already sent as a public, non-secret
// URL query parameter to the identity provider and back) is safe to use
// directly as the cookie-name suffix: it's base64url, so every character
// is already a legal HTTP cookie-name token character, and collisions are
// astronomically unlikely.
func (a *Auth) oauthStateCookieNamePrefix() string {
	if a.secureCookies() {
		return oauthStateCookieName
	}
	return oauthStateCookieNameInsecure
}

// oauthStateCookieName returns the full per-login-start cookie name for
// state -- see oauthStateCookieNamePrefix's doc comment.
func (a *Auth) oauthStateCookieName(state string) string {
	return a.oauthStateCookieNamePrefix() + "-" + state
}

// setOAuthStateCookie writes the signed, per-login-start OAuth state
// cookie (named after state -- see oauthStateCookieName's doc comment) and
// clears the legacy unprefixed one, shared by both the OIDC (Google/dev)
// and GitHub login-start handlers.
func (a *Auth) setOAuthStateCookie(w http.ResponseWriter, state, cookieVal string) {
	http.SetCookie(w, &http.Cookie{
		Name: a.oauthStateCookieName(state), Value: cookieVal, Path: "/",
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode,
		MaxAge: int(oauthStateMaxAge.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: legacyOAuthStateCookieName, Value: "", Path: "/auth", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
}

// consumeOAuthStateCookie reads and clears the OAuth state cookie
// belonging to queryState (the "state" query parameter the identity
// provider echoed back to the callback -- see oauthStateCookieName's doc
// comment for why each login start owns a distinctly-named cookie rather
// than sharing one), and parses/verifies its signed payload. Shared by both
// the OIDC (Google/dev) and GitHub callback handlers. On failure it has
// already written the loginFailed redirect; callers must return
// immediately when ok is false.
//
// A queryState no cookie exists for (never issued, already consumed by an
// earlier callback, or expired and dropped by the browser) is exactly the
// existing "OAuth state mismatch" family of failures -- there is nothing
// to distinguish it from tampering, so it gets the same generic message as
// before.
func (a *Auth) consumeOAuthStateCookie(w http.ResponseWriter, r *http.Request, queryState string) (st oauthState, ok bool) {
	cookieName := a.oauthStateCookieName(queryState)
	cookie, cookieErr := r.Cookie(cookieName)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: legacyOAuthStateCookieName, Value: "", Path: "/auth", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
	if cookieErr != nil {
		a.loginFailed(w, r, "missing OAuth state cookie (it may have expired -- try logging in again)")
		return oauthState{}, false
	}
	st, err := a.parseState(cookie.Value)
	if err != nil {
		a.loginFailed(w, r, "invalid or expired OAuth state")
		return oauthState{}, false
	}
	if st.State != queryState {
		// Defense in depth: this should be unreachable since the cookie
		// name is itself derived from queryState, but the signed payload's
		// own State field is checked too rather than trusting the cookie
		// name alone.
		a.loginFailed(w, r, "OAuth state mismatch")
		return oauthState{}, false
	}
	return st, true
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == ModeGitHub {
		a.handleGitHubLogin(w, r)
		return
	}

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
	a.setOAuthStateCookie(w, st.State, cookieVal)

	authURL := oauthCfg.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *Auth) handleCallback(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Mode == ModeGitHub {
		a.handleGitHubCallback(w, r)
		return
	}

	ctx := r.Context()

	// The query state param identifies WHICH per-login-start cookie to
	// consume (oauthStateCookieName's doc comment) -- read it before
	// consuming, not after, since consumeOAuthStateCookie needs it to find
	// the right cookie in the first place.
	st, ok := a.consumeOAuthStateCookie(w, r, r.URL.Query().Get("state"))
	if !ok {
		return
	}

	if providerErr := r.URL.Query().Get("error"); providerErr != "" {
		a.loginFailed(w, r, "identity provider returned an error: "+providerErr)
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

	// Defense in depth: st.ReturnTo was already sanitized (sanitizeReturnTo)
	// before it went into the signed, HMAC-protected state cookie back in
	// handleLogin, so this SHOULD always pass -- but §14.3 wants every
	// next/return_to consumer, this callback included, to re-check right
	// before use rather than trust that an earlier check was never bypassed
	// (e.g. by a future code path that starts writing oauthState.ReturnTo
	// some other way).
	returnTo := st.ReturnTo
	if returnTo != "" && !validLocalReturnTo(returnTo) {
		returnTo = ""
	}
	a.completeLogin(w, r, user, returnTo)
}

// completeLogin creates a session for user, sets the session/CSRF cookies,
// audit-logs the login, and redirects to returnTo (falling back to
// defaultReturnTo when empty). It's the common tail of every login path
// once an identity has resolved to a store.User: the OIDC (Google/dev)
// callback above, the GitHub callback, and the GitHub account-link
// confirmation submit handler (github.go).
func (a *Auth) completeLogin(w http.ResponseWriter, r *http.Request, user *store.User, returnTo string) {
	ctx := r.Context()

	_, rawSessionToken, err := a.createSession(ctx, user.ID)
	if err != nil {
		a.loginFailed(w, r, "failed to create session")
		return
	}
	a.setSessionCookies(w, rawSessionToken, a.sessionDuration(ctx))

	_ = Audit(ctx, a.store, user.ID, "user.login", "user:"+user.ID, map[string]string{"email": user.Email})

	if returnTo == "" {
		returnTo = defaultReturnTo
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// DashboardURL returns the control-plane dashboard's absolute URL
// (ControlOrigin + defaultReturnTo). It exists for callers OUTSIDE this
// package that need to point a browser at the dashboard directly rather
// than via a same-origin relative redirect -- namely
// server/internal/invoke's browser-facing "access denied" page (§14.3
// item 3), which is served from a function's own host and so can't just
// redirect to a relative "/dashboard" path the way this package's own
// handlers do.
func (a *Auth) DashboardURL() string {
	return strings.TrimSuffix(a.cfg.ControlOrigin, "/") + defaultReturnTo
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.sessionCookieName()); err == nil {
		if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil {
			_ = a.store.Sessions().Delete(r.Context(), sha256Hex(raw))
		}
	}
	a.clearSessionCookies(w)
	http.Redirect(w, r, defaultReturnTo, http.StatusFound)
}

// loginFailed redirects to the dashboard's login-error landing page rather
// than rendering an error page itself, since /auth/* has no HTML templates
// carried as a query parameter for the dashboard to display.
func (a *Auth) loginFailed(w http.ResponseWriter, r *http.Request, message string) {
	u := defaultReturnTo + "?login_error=" + url.QueryEscape(message)
	http.Redirect(w, r, u, http.StatusFound)
}

// sanitizeReturnTo only allows a same-origin relative path so return_to
// can't be abused as an open redirect -- it's login.go's entry point into
// invokesso.go's
// validLocalReturnTo, the single validator every next/return_to consumer
// in this package shares; see that function's doc comment for the exact
// rules and why they live in one place.
func sanitizeReturnTo(s string) string {
	if !validLocalReturnTo(s) {
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
// and §5.4's per-login-rule gating for every login after that.
func (a *Auth) upsertUser(ctx context.Context, sub, email, name string) (*store.User, error) {
	if u, err := a.store.Users().ByProviderSubject(ctx, store.ProviderGoogle, sub); err == nil {
		// Only a disabled account is denied at login. A pending one (§13.3)
		// still logs in successfully -- completeLogin issues a session
		// regardless of status; it's the dashboard/API layers that
		// recognize UserStatusPending and restrict what it can reach.
		if u.Status == store.UserStatusDisabled {
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
		u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: sub, Email: email, Name: name}
		err := a.store.BootstrapFirstUser(ctx, u, "funcbox")
		switch {
		case err == nil:
			if err := a.claimUserID(ctx, u); err != nil {
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

	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: sub, Email: email, Name: name, Role: store.RoleMember, Status: a.initialUserStatus(ctx)}
	if err := a.store.Users().Create(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Another request just created the same user (e.g. a
			// double-submitted callback); look it up and treat it as a
			// normal login rather than failing.
			if existing, lookupErr := a.store.Users().ByProviderSubject(ctx, store.ProviderGoogle, sub); lookupErr == nil {
				return existing, nil
			}
		}
		return nil, err
	}
	if err := a.claimUserID(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// seedBootstrapLoginRule installs a login rule set for a freshly
// bootstrapped organization, and writes the organization's open_mode
// setting when a.cfg.OpenMode requested it at
// process startup.
//
// Normal mode: allow the new admin's own exact email address, deny
// everyone else by default.
//
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
//
// Open mode (a.cfg.OpenMode, FUNCBOX_OPEN_MODE=1): §13.1 explicitly wants
// registration open to everyone, so the seed rule set is a single
// default-allow rule instead. Nothing here forbids an admin from
// tightening it later (e.g. to a domain allowlist) via the same PUT
// endpoint -- "組織設定は適用される" continues to hold in open mode.
func (a *Auth) seedBootstrapLoginRule(ctx context.Context, email string) error {
	if a.cfg.OpenMode {
		if err := a.applyBootstrapOpenMode(ctx); err != nil {
			return err
		}
		return a.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
			{Ord: 0, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionAllow},
		})
	}
	return a.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: email, Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	})
}

// applyBootstrapOpenMode flips the freshly-created organization's
// open_mode setting to true. It runs as a follow-up store write right
// after BootstrapFirstUser's own transaction commits, the same pattern
// seedBootstrapLoginRule's caller already uses for ReplaceLoginRules --
// BootstrapFirstUser itself only knows how to create the organization row
// with empty ("{}") settings, since it has no dependency on this
// package's settings.Org shape.
func (a *Auth) applyBootstrapOpenMode(ctx context.Context) error {
	org, err := a.store.Organizations().Get(ctx)
	if err != nil {
		return err
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return err
	}
	orgSet.OpenMode = true
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	return a.store.Organizations().Update(ctx, org)
}

// requireApprovalEnabled reports the organization's current
// require_approval setting, failing closed (false, i.e. no approval
// required) if the organization or its settings
// can't be loaded -- there is no organization row yet only during the
// bootstrap login, which never consults this (BootstrapFirstUser always
// forces UserStatusActive on its own).
func (a *Auth) requireApprovalEnabled(ctx context.Context) bool {
	org, err := a.store.Organizations().Get(ctx)
	if err != nil {
		return false
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return false
	}
	return orgSet.RequireApproval
}

// OrgLanguage resolves the organization's default dashboard language for
// this package's own Go-rendered pages (the sign-in-failed page below and
// GitHub's account-link confirmation page, github.go) and for the two
// sibling packages (dashboard, invoke) that hold onto an *Auth precisely to
// reach it -- see webpage.OrgLanguage's doc comment for why these pages use
// only the organization default, never a per-user preference.
func (a *Auth) OrgLanguage(ctx context.Context) webpage.Lang {
	return webpage.OrgLanguage(ctx, a.store)
}

// initialUserStatus resolves the status assigned to a brand-new
// (non-bootstrap, non-account-link) user at registration time -- both the
// Google/dev upsertUser path above and GitHub's resolveGitHubLogin
// (github.go) call this for their respective "brand new identity"
// branches. An account link (github.go's completeGitHubLink) deliberately
// does NOT call this: linking to an EXISTING account keeps that account's
// current status unchanged.
func (a *Auth) initialUserStatus(ctx context.Context) store.UserStatus {
	if a.requireApprovalEnabled(ctx) {
		return store.UserStatusPending
	}
	return store.UserStatusActive
}

func (a *Auth) claimUserID(ctx context.Context, u *store.User) error {
	userID, err := DeriveUserID(ctx, a.store, u.Email)
	if err != nil {
		return err
	}
	return a.store.PublicUserIDs().Create(ctx, &store.PublicUserID{
		UserID: userID, InternalUserID: u.ID,
	})
}
