// authorize.go implements GET/POST /oauth/authorize: the authorization
// endpoint. GET validates the request and either redirects an
// unauthenticated browser into funcbox's existing login flow (returning
// here once signed in, exactly like server/internal/auth's own
// handleInvokeStart does for the browser-SSO invoke handoff) or renders a
// consent page; POST handles that page's "Approve" decision (see
// consent.go for the CSRF-bearing state token the two legs share --
// "Cancel" needs no POST at all, see renderConsentPage).
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"time"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/webpage"
)

// oauthAuthCodeLifetime bounds how long an approved authorization waits to
// be redeemed at POST /oauth/token -- "single-use, expiry ~10min" per this
// step's spec.
const oauthAuthCodeLifetime = 10 * time.Minute

func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")

	// client_id/redirect_uri are validated FIRST, and their failure
	// reported directly (never via redirect): until redirect_uri is
	// confirmed to belong to a registered client, it cannot be trusted as
	// a place to send an error (RFC 6749 §4.1.2.1's "if the redirect_uri
	// is missing, invalid, ... MUST NOT redirect").
	if clientID == "" {
		http.Error(w, "oauth: missing client_id", http.StatusBadRequest)
		return
	}
	client, err := h.store.OAuthClients().ByID(r.Context(), clientID)
	if err != nil {
		http.Error(w, "oauth: unknown client_id", http.StatusBadRequest)
		return
	}
	if redirectURI == "" || !redirectRegistered(client, redirectURI) {
		http.Error(w, "oauth: redirect_uri does not exactly match a redirect URI registered for this client", http.StatusBadRequest)
		return
	}

	// Every failure from here on redirects back to redirect_uri with an
	// OAuth error, per RFC 6749 §4.1.2.1.
	state := q.Get("state")
	if q.Get("response_type") != "code" {
		redirectOAuthError(w, r, redirectURI, state, errUnsupportedResponseType, `response_type must be "code"`)
		return
	}
	if q.Get("code_challenge_method") != "S256" {
		redirectOAuthError(w, r, redirectURI, state, errInvalidRequest, `code_challenge_method must be "S256"`)
		return
	}
	challenge := q.Get("code_challenge")
	if !auth.ValidPKCEChallenge(challenge) {
		redirectOAuthError(w, r, redirectURI, state, errInvalidRequest, "code_challenge is missing or malformed (expected base64url(sha256(verifier)))")
		return
	}
	// RFC 8707 resource indicator: this authorization server only ever
	// issues tokens for a single protected resource (ControlOrigin +
	// "/mcp" -- see protectedResource's doc comment and the doc comment
	// on this package's Config.ControlOrigin), so a present "resource"
	// MUST equal that exactly, and MUST NOT be repeated (a client sending
	// several conflicting values gets no principled way to pick one).
	// Absent is allowed -- the MCP Authorization spec (following RFC 8707
	// §2's own "MAY" on including resource at all) still requires access
	// tokens be resource-scoped, but since this server has only ever the
	// one resource, "which resource" is unambiguous even when the client
	// doesn't ask, and every access token this package mints already
	// carries that single resource's audience unconditionally (aud=
	// auth.AudienceMCP) -- see token.go for the enforcement half of this.
	if len(q["resource"]) > 1 {
		redirectOAuthError(w, r, redirectURI, state, errInvalidTarget, "resource must not be specified more than once")
		return
	}
	resource := q.Get("resource")
	if resource != "" && resource != h.protectedResource() {
		redirectOAuthError(w, r, redirectURI, state, errInvalidTarget,
			"resource must exactly equal this server's protected resource identifier ("+h.protectedResource()+")")
		return
	}

	actor, err := h.auth.AuthenticateSessionCookie(r)
	if err != nil {
		// No usable session: hand off to funcbox's existing login flow,
		// carrying this exact request (query string included) as
		// return_to so it lands right back here once signed in --
		// identical in shape to handleInvokeStart's unauthenticated
		// browser-SSO handoff.
		http.Redirect(w, r, auth.LoginURL(r.URL.RequestURI()), http.StatusFound)
		return
	}

	st := consentState{
		ClientID: clientID, RedirectURI: redirectURI, Challenge: challenge,
		OAuthState: state, Resource: resource, UserID: actor.User.ID, IssuedAt: time.Now().Unix(),
	}
	token, err := h.signConsentState(st)
	if err != nil {
		http.Error(w, "oauth: authorization is not available", http.StatusInternalServerError)
		return
	}

	h.renderConsentPage(w, r, client, actor.User, token, redirectURI, state)
}

func (h *Handler) handleAuthorizeDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "oauth: invalid request", http.StatusBadRequest)
		return
	}
	st, err := h.parseConsentState(r.FormValue("state_token"))
	if err != nil {
		http.Error(w, "oauth: this authorization request is invalid or has expired -- please try connecting again", http.StatusBadRequest)
		return
	}

	// The session approving this request must be the SAME one the
	// consent page was rendered for -- otherwise a stale/leaked
	// state_token could let a different signed-in browser silently
	// approve an authorization on someone else's behalf.
	actor, err := h.auth.AuthenticateSessionCookie(r)
	if err != nil || actor.User.ID != st.UserID {
		http.Error(w, "oauth: session mismatch -- please try connecting again", http.StatusForbidden)
		return
	}

	// Re-validate right before use, defense in depth: the client or its
	// redirect URI could in principle have changed between GET's render
	// and this POST (mirrors internal/auth/login.go's own re-check of
	// returnTo right before use).
	client, err := h.store.OAuthClients().ByID(r.Context(), st.ClientID)
	if err != nil || !redirectRegistered(client, st.RedirectURI) {
		http.Error(w, "oauth: this authorization request is no longer valid", http.StatusBadRequest)
		return
	}

	raw := randomURLToken(32)
	code := &store.OAuthAuthCode{
		ID: sha256Hex(raw), UserID: actor.User.ID, ClientID: st.ClientID,
		RedirectURI: st.RedirectURI, Challenge: st.Challenge, Resource: st.Resource,
		ExpiresAt: time.Now().Add(oauthAuthCodeLifetime),
	}
	if err := h.store.OAuthAuthCodes().Create(r.Context(), code); err != nil {
		http.Error(w, "oauth: authorization is not available", http.StatusInternalServerError)
		return
	}
	_ = auth.Audit(r.Context(), h.store, actor.User.ID, "oauth.authorize.approve", "oauth_client:"+st.ClientID,
		map[string]any{"resource": st.Resource})

	target, err := buildRedirectURL(st.RedirectURI, map[string]string{"code": raw, "state": st.OAuthState})
	if err != nil {
		http.Error(w, "oauth: authorization is not available", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// renderConsentPage renders the funcbox-styled consent screen: the
// requesting client's name and the acting user, an Approve form (POSTs
// the CSRF-bearing state token) and a Cancel link. Cancel needs no server
// round trip at all -- nothing has been created yet at this point, so it's
// simply a link straight to redirect_uri with error=access_denied, built
// with the same already-validated redirect_uri GET just confirmed.
func (h *Handler) renderConsentPage(w http.ResponseWriter, r *http.Request, client *store.OAuthClient, user *store.User, stateToken, redirectURI, oauthState string) {
	msg := consentMessages[webpage.OrgLanguage(r.Context(), h.store)]
	clientName := client.Name
	if clientName == "" {
		clientName = client.ID
	}

	cancelURL, err := buildRedirectURL(redirectURI, map[string]string{"error": errAccessDenied, "state": oauthState})
	if err != nil {
		http.Error(w, "oauth: authorization is not available", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := fmt.Sprintf(`<h1>%s</h1>
<p>%s</p>
<p>%s</p>
<form method="POST" action="/oauth/authorize">
<input type="hidden" name="state_token" value="%s">
<button type="submit" class="wp-btn">%s</button>
<a href="%s" class="wp-btn wp-btn-ghost" style="margin-left:8px">%s</a>
</form>`,
		msg.heading,
		fmt.Sprintf(msg.clientParaFmt, html.EscapeString(clientName)),
		fmt.Sprintf(msg.userParaFmt, html.EscapeString(user.Email)),
		html.EscapeString(stateToken),
		msg.approve,
		html.EscapeString(cancelURL),
		msg.cancel,
	)
	fmt.Fprint(w, webpage.Page(msg.title, body))
}

type consentMessage struct {
	title, heading, clientParaFmt, userParaFmt, approve, cancel string
}

var consentMessages = map[webpage.Lang]consentMessage{
	webpage.LangEN: {
		title:         "funcbox -- authorize application",
		heading:       "Authorize this application?",
		clientParaFmt: `<strong>%s</strong> is requesting access to your funcbox account.`,
		userParaFmt:   `You are signed in as <strong>%s</strong>.`,
		approve:       "Approve",
		cancel:        "Cancel",
	},
	webpage.LangJA: {
		title:         "funcbox -- アプリケーションの認可",
		heading:       "このアプリケーションを認可しますか？",
		clientParaFmt: `<strong>%s</strong> があなたの funcbox アカウントへのアクセスを要求しています。`,
		userParaFmt:   `<strong>%s</strong> としてサインインしています。`,
		approve:       "許可する",
		cancel:        "キャンセル",
	},
}

// redirectRegistered reports whether redirectURI exactly matches one of
// client's registered redirect URIs (RFC 6749 §3.1.2.3 "Exact Match").
func redirectRegistered(client *store.OAuthClient, redirectURI string) bool {
	if client == nil {
		return false
	}
	for _, u := range client.RedirectURIs {
		if u == redirectURI {
			return true
		}
	}
	return false
}

// redirectOAuthError redirects the browser back to redirectURI carrying a
// standard OAuth authorization-endpoint error (RFC 6749 §4.1.2.1):
// error/error_description query parameters, plus state echoed back
// verbatim (omitted if the client never sent one).
func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	target, err := buildRedirectURL(redirectURI, map[string]string{
		"error": code, "error_description": description, "state": state,
	})
	if err != nil {
		http.Error(w, description, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// buildRedirectURL merges params into base's existing query string
// (params win on key collision), skipping any param with an empty value
// -- so an absent "state" is omitted from the result rather than encoded
// as "state=".
func buildRedirectURL(base string, params map[string]string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		if v == "" {
			continue
		}
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// randomURLToken returns a base64url-encoded random token of n raw bytes
// (mirrors internal/auth's own randomURLToken -- see this package's doc
// comment on why small utilities like this are duplicated rather than
// exported across the package boundary).
func randomURLToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("oauth: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
