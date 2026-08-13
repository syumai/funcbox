// github.go implements the GitHub identity provider (tmp/13-public-mode.md
// §13.2): plain OAuth2 Authorization Code + GitHub's REST API, since GitHub
// has no OIDC issuer for provider.go's discovery/ID-token machinery to
// target. It reuses login.go's oauthState cookie (State/ReturnTo only --
// GitHub's OAuth Apps flow has no ID token nonce and no PKCE) and
// login.go's completeLogin (session creation, audit, redirect) once an
// identity has been resolved to a store.User.
//
// The account-linking confirmation page (handleLinkConfirmForm/Submit)
// lives here too: it's GitHub-specific because only GitHub's fixed
// handle-equals-username rule can force a handle (and therefore function
// URL) change on link, which is what the confirmation warns about.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/syumai/funcbox/manifest"
	"github.com/syumai/funcbox/server/internal/store"
)

// linkStateMaxAge bounds how long an account-link confirmation token
// (issued at the end of a GitHub callback that found an email match under
// a different provider/subject) stays valid. Mirrors oauthStateMaxAge's
// role for the OAuth state cookie -- both exist purely to survive one more
// browser round trip, not as a long-lived credential.
const linkStateMaxAge = 10 * time.Minute

// ErrGitHubHandleTaken is returned when the lowercased GitHub username a
// login would claim as its funcbox handle is already claimed by a
// different funcbox account (tmp/13-public-mode.md §13.2's handle-fixed
// rule leaves no fallback like DeriveUserID's "-2" suffixing -- the handle
// MUST equal the GitHub username, so a collision is a hard failure rather
// than something to work around).
var ErrGitHubHandleTaken = errors.New("auth: github handle already claimed by a different funcbox account")

// githubOAuth2Config builds the golang.org/x/oauth2 client config for the
// GitHub login flow. Unlike oauth2Config (provider.go), this does not
// perform OIDC discovery -- GitHub's authorize/token endpoints are fixed
// (or, in tests, pointed at an httptest fake via Config's unexported
// githubAuthorizeURL/githubTokenURL).
func (a *Auth) githubOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.cfg.GitHubClientID,
		ClientSecret: a.cfg.GitHubClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  a.cfg.githubAuthorizeURL,
			TokenURL: a.cfg.githubTokenURL,
		},
		RedirectURL: strings.TrimSuffix(a.cfg.BaseURL, "/") + authCallbackPath,
		// read:user + user:email is exactly what tmp/13-public-mode.md
		// §13.2 specifies: enough to read the profile (login, numeric id)
		// and the full email list (including a verified-but-private
		// primary email) without requesting anything broader.
		Scopes: []string{"read:user", "user:email"},
	}
}

// githubUserResponse is the subset of GET /user's response body this
// package needs.
type githubUserResponse struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

// githubEmailResponse is one entry of GET /user/emails's response body.
type githubEmailResponse struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// githubGet performs an authenticated GET against the GitHub REST API and
// decodes the JSON response body into a T. GitHub requires a User-Agent
// header on every API request (unauthenticated-looking requests without
// one are rejected) and recommends the versioned Accept header this sets.
func githubGet[T any](ctx context.Context, apiBaseURL, path string, token *oauth2.Token) (T, error) {
	var zero T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBaseURL+path, nil)
	if err != nil {
		return zero, fmt.Errorf("auth: build GitHub API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "funcbox")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return zero, fmt.Errorf("auth: GitHub API request %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return zero, fmt.Errorf("auth: read GitHub API response %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("auth: GitHub API request %s returned status %d", path, resp.StatusCode)
	}
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		return zero, fmt.Errorf("auth: decode GitHub API response %s: %w", path, err)
	}
	return out, nil
}

func (a *Auth) fetchGitHubUser(ctx context.Context, token *oauth2.Token) (*githubUserResponse, error) {
	u, err := githubGet[githubUserResponse](ctx, a.cfg.githubAPIBaseURL, "/user", token)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (a *Auth) fetchGitHubEmails(ctx context.Context, token *oauth2.Token) ([]githubEmailResponse, error) {
	return githubGet[[]githubEmailResponse](ctx, a.cfg.githubAPIBaseURL, "/user/emails", token)
}

// selectVerifiedPrimaryEmail implements tmp/13-public-mode.md §13.2's
// email selection rule: "verified な primary email を取得し、email 非公開
// 設定のユーザーにも対応する。verified email が1つもない場合はログイン
// 拒否". GET /user/emails (granted by the user:email scope) always
// includes the primary address, including for accounts with "keep my
// email address private" enabled, so this never needs to fall back to
// GET /user's public-or-null email field.
//
// Only the entry marked primary is considered, and it must also be marked
// verified. A non-primary verified address is deliberately NOT used as a
// fallback: the spec's wording ties the decision to "the" primary email,
// and silently substituting a different address the user hasn't
// designated primary would be a surprising identity to sign in as.
func selectVerifiedPrimaryEmail(emails []githubEmailResponse) (string, bool) {
	for _, e := range emails {
		if e.Primary {
			if e.Verified && e.Email != "" {
				return e.Email, true
			}
			return "", false
		}
	}
	return "", false
}

// githubHandleFromLogin derives the candidate funcbox handle from a raw
// GitHub username: lowercase, since GitHub usernames are
// case-insensitively unique (tmp/13-public-mode.md §13.2: "GitHub username
// は...大文字小文字を区別せず一意なので、小文字化すれば funcbox の handle
// 形式（DNS ラベル）とそのまま互換").
func githubHandleFromLogin(login string) string {
	return strings.ToLower(login)
}

// validateGitHubHandle validates a candidate handle against funcbox's
// DNS-label-plus-reserved-name rules -- the same check every other handle
// (manifest.ValidateUserID) is subject to. Factored out as its own
// function purely so tests can exercise the (lowercase, validate) pair
// directly without going through a full callback round trip.
func validateGitHubHandle(handle string) error {
	return manifest.ValidateUserID(handle)
}

func (a *Auth) handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	st := oauthState{
		State:    randomURLToken(16),
		ReturnTo: sanitizeReturnTo(r.URL.Query().Get("return_to")),
		IssuedAt: time.Now().Unix(),
	}
	cookieVal, err := a.signState(st)
	if err != nil {
		http.Error(w, "authentication is not available", http.StatusInternalServerError)
		return
	}
	a.setOAuthStateCookie(w, cookieVal)

	authURL := a.githubOAuth2Config().AuthCodeURL(st.State)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *Auth) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	st, ok := a.consumeOAuthStateCookie(w, r)
	if !ok {
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

	token, err := a.githubOAuth2Config().Exchange(ctx, code)
	if err != nil {
		a.loginFailed(w, r, "token exchange failed")
		return
	}

	ghUser, err := a.fetchGitHubUser(ctx, token)
	if err != nil {
		a.loginFailed(w, r, "failed to fetch GitHub profile")
		return
	}
	emails, err := a.fetchGitHubEmails(ctx, token)
	if err != nil {
		a.loginFailed(w, r, "failed to fetch GitHub email addresses")
		return
	}
	email, ok := selectVerifiedPrimaryEmail(emails)
	if !ok {
		a.loginFailed(w, r, "this GitHub account has no verified primary email address")
		return
	}

	handle := githubHandleFromLogin(ghUser.Login)
	if err := validateGitHubHandle(handle); err != nil {
		a.loginFailed(w, r, "this GitHub username cannot be used as a funcbox handle: "+err.Error())
		return
	}
	subject := strconv.FormatInt(ghUser.ID, 10)

	result, err := a.resolveGitHubLogin(ctx, subject, email, ghUser.Login, handle)
	if err != nil {
		switch {
		case errors.Is(err, ErrLoginDenied):
			a.loginFailed(w, r, "this email address is not permitted to sign in")
		case errors.Is(err, ErrGitHubHandleTaken):
			a.loginFailed(w, r, "the funcbox handle matching this GitHub username is already in use by another account")
		default:
			a.loginFailed(w, r, "failed to complete sign-in")
		}
		return
	}

	if result.needsConfirmation {
		linkSt := linkState{
			Subject:        subject,
			Email:          email,
			Login:          ghUser.Login,
			NewHandle:      handle,
			ExistingUserID: result.existingUserID,
			ReturnTo:       st.ReturnTo,
			IssuedAt:       time.Now().Unix(),
		}
		token, err := a.signLinkState(linkSt)
		if err != nil {
			a.loginFailed(w, r, "failed to prepare account link confirmation")
			return
		}
		http.Redirect(w, r, "/auth/link/confirm?token="+url.QueryEscape(token), http.StatusFound)
		return
	}

	a.completeLogin(w, r, result.user, st.ReturnTo)
}

// githubLoginResult is resolveGitHubLogin's outcome: either a resolved user
// ready for completeLogin, or a pending account link that needs the user's
// explicit confirmation (via the /auth/link/confirm page) before it's
// applied, since it may change their handle and function URLs.
type githubLoginResult struct {
	user              *store.User
	needsConfirmation bool
	existingUserID    string
}

// resolveGitHubLogin resolves a verified GitHub identity to a funcbox
// user, implementing tmp/13-public-mode.md §13.2's three-way decision:
//
//  1. (provider=github, subject) already matches a user -> ordinary login.
//  2. No subject match, but `email` matches an existing user (registered
//     under a different provider, or -- vanishingly unlikely -- a stale
//     GitHub subject) -> an account link, gated on the caller rendering
//     the /auth/link/confirm warning before it takes effect (handle may
//     change).
//  3. Neither matches -> a brand new user, with handle fixed to the
//     GitHub username rather than derived from the email local part.
func (a *Auth) resolveGitHubLogin(ctx context.Context, subject, email, ghLogin, handle string) (*githubLoginResult, error) {
	if u, err := a.store.Users().ByProviderSubject(ctx, store.ProviderGitHub, subject); err == nil {
		// Only a disabled account is denied here; a pending one (§13.3)
		// still logs in successfully -- see login.go's upsertUser for the
		// identical rule on the Google/dev path.
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
		// The handle is fixed at registration and does NOT track GitHub
		// username renames (tmp/13-public-mode.md §13.2: "GitHub 側で
		// username を変更しても追従しない"); only email is refreshed here.
		if u.Email != email {
			u.Email = email
			if err := a.store.Users().Update(ctx, u); err != nil {
				return nil, err
			}
		}
		return &githubLoginResult{user: u}, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// handleOwnerID is the internal user ID currently holding `handle`
	// (empty if unclaimed), checked once up front since both the link and
	// brand-new-user paths below need it.
	handleOwnerID := ""
	if pid, err := a.store.PublicUserIDs().ByUserID(ctx, handle); err == nil {
		handleOwnerID = pid.InternalUserID
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	if existing, err := a.store.Users().ByEmail(ctx, email); err == nil {
		if existing.Status == store.UserStatusDisabled {
			return nil, ErrLoginDenied
		}
		allowed, err := a.checkLoginRules(ctx, email)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrLoginDenied
		}
		if handleOwnerID != "" && handleOwnerID != existing.ID {
			return nil, ErrGitHubHandleTaken
		}
		return &githubLoginResult{needsConfirmation: true, existingUserID: existing.ID}, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// Brand new identity. handleOwnerID must be empty here: a not-yet-
	// existing user can't already own a handle.
	if handleOwnerID != "" {
		return nil, ErrGitHubHandleTaken
	}

	existingUsers, err := a.store.Users().List(ctx)
	if err != nil {
		return nil, err
	}
	if len(existingUsers) == 0 {
		u := &store.User{Provider: store.ProviderGitHub, ProviderSubject: subject, Email: email, Name: ghLogin}
		err := a.store.BootstrapFirstUser(ctx, u, "funcbox")
		switch {
		case err == nil:
			if err := a.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: handle, InternalUserID: u.ID}); err != nil {
				return nil, err
			}
			if err := a.seedBootstrapLoginRule(ctx, email); err != nil {
				return nil, err
			}
			return &githubLoginResult{user: u}, nil
		case errors.Is(err, store.ErrConflict):
			// Lost the race to bootstrap; fall through to the normal,
			// rule-gated path below.
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

	u := &store.User{Provider: store.ProviderGitHub, ProviderSubject: subject, Email: email, Name: ghLogin, Role: store.RoleMember, Status: a.initialUserStatus(ctx)}
	if err := a.store.Users().Create(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			if existing, lookupErr := a.store.Users().ByProviderSubject(ctx, store.ProviderGitHub, subject); lookupErr == nil {
				return &githubLoginResult{user: existing}, nil
			}
		}
		return nil, err
	}
	if err := a.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: handle, InternalUserID: u.ID}); err != nil {
		return nil, err
	}
	return &githubLoginResult{user: u}, nil
}

// linkState is what's carried, HMAC-signed, in the /auth/link/confirm
// token across the confirmation page round trip -- there is no session to
// stash it in server-side, since the whole point of the page is that
// completing the login is exactly what's still pending confirmation.
type linkState struct {
	Subject        string `json:"subject"`
	Email          string `json:"email"`
	Login          string `json:"login"` // the raw (not lowercased) GitHub username, for display
	NewHandle      string `json:"new_handle"`
	ExistingUserID string `json:"existing_user_id"`
	ReturnTo       string `json:"return_to,omitempty"`
	IssuedAt       int64  `json:"iat"`
}

func (a *Auth) signLinkState(st linkState) (string, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	sig := hmacHex(a.csrfKey, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sig, nil
}

func (a *Auth) parseLinkState(token string) (linkState, error) {
	payloadB64, sig, ok := strings.Cut(token, ".")
	if !ok {
		return linkState{}, fmt.Errorf("auth: malformed link token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return linkState{}, fmt.Errorf("auth: malformed link token: %w", err)
	}
	if !constantTimeEqual(hmacHex(a.csrfKey, payload), sig) {
		return linkState{}, fmt.Errorf("auth: link token signature mismatch")
	}
	var st linkState
	if err := json.Unmarshal(payload, &st); err != nil {
		return linkState{}, fmt.Errorf("auth: malformed link token payload: %w", err)
	}
	if time.Since(time.Unix(st.IssuedAt, 0)) > linkStateMaxAge {
		return linkState{}, fmt.Errorf("auth: link token expired")
	}
	return st, nil
}

// handleLinkConfirmForm renders the warning page tmp/13-public-mode.md
// §13.2 requires before an account link that changes the handle (and
// therefore function URLs) takes effect.
func (a *Auth) handleLinkConfirmForm(w http.ResponseWriter, r *http.Request) {
	st, err := a.parseLinkState(r.URL.Query().Get("token"))
	if err != nil {
		a.loginFailed(w, r, "this account link confirmation is invalid or has expired -- please sign in again")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Argument order must match linkConfirmPageHTML's %s placeholders in
	// document order: email, new handle (warning paragraph), token
	// (hidden form field), new handle (button label).
	fmt.Fprintf(w, linkConfirmPageHTML,
		html.EscapeString(st.Email),
		html.EscapeString(st.NewHandle),
		html.EscapeString(r.URL.Query().Get("token")),
		html.EscapeString(st.NewHandle),
	)
}

const linkConfirmPageHTML = `<!doctype html>
<html><head><title>funcbox -- confirm account link</title></head>
<body>
<h1>Link your GitHub account?</h1>
<p>An existing funcbox account for <strong>%s</strong> will be linked to
this GitHub identity.</p>
<p><strong>Warning:</strong> on GitHub, your funcbox handle is fixed to
your GitHub username. Completing this link will change your handle to
<strong>%s</strong>, and any function URLs under your previous handle will
stop working (no redirect is put in place).</p>
<form method="POST" action="/auth/link/confirm">
<input type="hidden" name="token" value="%s">
<button type="submit">Confirm and link account (handle becomes %s)</button>
</form>
<p><a href="/auth/login">Cancel</a></p>
</body></html>`

// handleLinkConfirmSubmit completes an account link the user has just
// confirmed via handleLinkConfirmForm's page: re-validates the token,
// re-checks the target account is still eligible, then applies the
// provider/subject/handle change and signs the caller in.
func (a *Auth) handleLinkConfirmSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.loginFailed(w, r, "invalid confirmation request")
		return
	}
	st, err := a.parseLinkState(r.FormValue("token"))
	if err != nil {
		a.loginFailed(w, r, "this account link confirmation is invalid or has expired -- please sign in again")
		return
	}

	user, err := a.completeGitHubLink(r.Context(), st)
	if err != nil {
		if errors.Is(err, ErrLoginDenied) {
			a.loginFailed(w, r, "this email address is not permitted to sign in")
			return
		}
		a.loginFailed(w, r, "failed to complete account link")
		return
	}

	a.completeLogin(w, r, user, st.ReturnTo)
}

// completeGitHubLink applies a confirmed link: re-point the target
// account's provider/subject at the incoming GitHub identity, rename (or
// claim) its public handle to the GitHub username, and audit-log the
// change (tmp/13-public-mode.md §13.2: "リンクは audit ログに記録する").
func (a *Auth) completeGitHubLink(ctx context.Context, st linkState) (*store.User, error) {
	u, err := a.store.Users().ByID(ctx, st.ExistingUserID)
	if err != nil {
		return nil, err
	}
	if u.Status == store.UserStatusDisabled {
		return nil, ErrLoginDenied
	}
	// Deliberately does NOT touch u.Status otherwise: linking to an
	// existing account keeps that account's current status unchanged
	// (tmp/13-public-mode.md §13.3's decision table), including pending --
	// this link only re-points provider/subject/handle, see below.
	allowed, err := a.checkLoginRules(ctx, st.Email)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrLoginDenied
	}

	oldProvider, oldSubject := u.Provider, u.ProviderSubject
	oldHandle := ""
	if pid, err := a.store.PublicUserIDs().ByOwner(ctx, u.ID); err == nil {
		oldHandle = pid.UserID
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	u.Provider = store.ProviderGitHub
	u.ProviderSubject = st.Subject
	u.Email = st.Email
	if err := a.store.Users().Update(ctx, u); err != nil {
		return nil, err
	}

	switch {
	case oldHandle == st.NewHandle:
		// No-op: already exactly the target handle.
	case oldHandle == "":
		if err := a.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: st.NewHandle, InternalUserID: u.ID}); err != nil {
			return nil, err
		}
	default:
		if err := a.store.PublicUserIDs().Rename(ctx, oldHandle, st.NewHandle); err != nil {
			return nil, err
		}
	}

	_ = Audit(ctx, a.store, u.ID, "user.provider.link", "user:"+u.ID, map[string]any{
		"old_provider": string(oldProvider),
		"old_subject":  oldSubject,
		"old_handle":   oldHandle,
		"new_provider": string(store.ProviderGitHub),
		"new_subject":  st.Subject,
		"new_handle":   st.NewHandle,
	})
	return u, nil
}
