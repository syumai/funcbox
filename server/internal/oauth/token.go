// token.go implements POST /oauth/token: the token endpoint, handling both
// grant types this authorization server supports --
// "authorization_code" (redeeming a GET/POST /oauth/authorize consent
// decision) and "refresh_token" (renewing an access token from a
// previously issued oauth_grants row without another round trip through
// consent). Every access token minted here reuses funcbox's existing
// "fbxa_..." format (auth.IssueAccessTokenForAudience) with
// "aud":"mcp" (auth.AudienceMCP).
//
// Unlike cli_credentials (which slides its secret's 90-day window
// indefinitely, never rotating it -- see that type's doc comment), every
// refresh_token grant here ROTATES: each successful use retires the
// presented "fbxr_..." secret and mints a brand new one backing the SAME
// store.OAuthGrant row (store.OAuthGrant.PrevSecretHash tracks the one it
// just retired), and presenting an already-retired secret again is treated
// as theft -- see store.OAuthGrantRepo.Rotate/RevokeIfPreviousSecret's doc
// comments for the full mechanism, and oauthGrantMaxLifetime below for the
// absolute cap layered on top of the sliding window.
package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/store"
)

// refreshTokenPrefix marks a bearer credential as a funcbox OAuth refresh
// token, mirroring the "fbxc_"/"fbxa_" naming convention internal/auth's
// CLI login credential and access token already use.
const refreshTokenPrefix = "fbxr_"

// oauthGrantSlidingWindow is oauth_grants' sliding-expiry window, mirroring
// internal/auth's CLICredentialSlidingWindow exactly (same 90-day figure,
// same "measured from LastUsedAt, or CreatedAt before first use" rule) --
// duplicated here rather than imported since CLICredentialSlidingWindow is
// unexported and the two entities, while structurally identical, are
// deliberately distinct store types (see store.OAuthGrant's doc comment).
//
// oauthGrantMaxLifetime is the hard cap layered on top of that sliding
// window: a grant reused often enough to keep sliding forever would
// otherwise never expire, so no OAuth grant here survives past
// CreatedAt+oauthGrantMaxLifetime regardless of how recently it was used
// (oauthGrantActive enforces both). 180 days (double the sliding window)
// gives a long-lived, actively-used MCP client integration a generous
// runway before it's forced back through consent, while still bounding
// worst-case credential lifetime for a client that's compromised early and
// kept alive by an attacker's own steady refresh traffic.
const (
	oauthGrantSlidingWindow = 90 * 24 * time.Hour
	oauthGrantMaxLifetime   = 180 * 24 * time.Hour
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "request body must be application/x-www-form-urlencoded")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	case "":
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "missing grant_type")
	default:
		writeOAuthError(w, http.StatusBadRequest, errUnsupportedGrantType, `grant_type must be "authorization_code" or "refresh_token"`)
	}
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	rawCode := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	if rawCode == "" || verifier == "" || redirectURI == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest,
			"code, code_verifier, redirect_uri, and client_id are all required")
		return
	}

	// Consume (single-use) BEFORE checking client_id/redirect_uri/PKCE
	// match, exactly like internal/auth's ExchangeCLICode: a code is
	// burned by any redemption attempt, matching or not, so a stolen code
	// can't be probed for the right client_id/redirect_uri/verifier
	// combination across multiple tries.
	code, err := h.store.OAuthAuthCodes().Consume(r.Context(), sha256Hex(rawCode), time.Now())
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the authorization code is invalid, expired, or already used")
		return
	}
	if code.ClientID != clientID || code.RedirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "client_id or redirect_uri does not match the authorization request")
		return
	}
	if !constantTimeEqual(auth.PKCEChallengeFromVerifier(verifier), code.Challenge) {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "code_verifier does not match the authorization's code_challenge")
		return
	}
	// Re-validate the resource indicator right before use, defense in
	// depth (mirrors this handler's own client_id/redirect_uri/PKCE
	// re-checks above): authorize.go already rejects anything but the
	// single protected resource before a code is ever minted, so this
	// should be unreachable in practice, but never trust that an
	// already-persisted row still reflects this package's CURRENT
	// validation rules.
	if code.Resource != "" && code.Resource != h.protectedResource() {
		writeOAuthError(w, http.StatusBadRequest, errInvalidTarget, "the authorization's resource is no longer valid for this server")
		return
	}

	h.issueTokenPair(w, r, code.UserID, code.ClientID)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("refresh_token")
	if !strings.HasPrefix(raw, refreshTokenPrefix) {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "refresh_token is missing or malformed")
		return
	}
	// client_id is REQUIRED here (unlike the authorization_code grant's
	// client_id, which RFC 6749 also requires but which arrives alongside
	// PKCE proof of possession): a refresh token is a long-lived, directly
	// reusable bearer secret with no separate proof-of-possession check of
	// its own, so binding it to a caller-asserted client_id at least
	// requires an attacker who obtained the secret to also know which
	// client it was issued to before they can use it.
	clientID := r.FormValue("client_id")
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "client_id is required")
		return
	}

	oldHash := sha256Hex(raw)
	grant, err := h.store.OAuthGrants().ByHash(r.Context(), oldHash)
	if err != nil {
		// Not the CURRENT secret of any grant. Before giving up, check
		// whether it's a THEFT signal instead: a secret that WAS a grant's
		// active refresh token before a legitimate rotation superseded it
		// (see store.OAuthGrantRepo.RevokeIfPreviousSecret's doc comment).
		// If so, the entire grant is revoked as a side effect -- the
		// caller still just sees the same generic invalid_grant, since
		// distinguishing "unknown" from "reused" in the response would
		// hand an attacker a free confirmation that the secret they're
		// holding used to be valid.
		if _, rerr := h.store.OAuthGrants().RevokeIfPreviousSecret(r.Context(), oldHash); rerr != nil {
			writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to process refresh token")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token is invalid, revoked, or unknown")
		return
	}
	if clientID != grant.ClientID {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "client_id does not match the refresh token's grant")
		return
	}
	now := time.Now()
	if !oauthGrantActive(grant, now) {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token has expired -- authorization is required again")
		return
	}

	user, err := h.auth.LoadAuthenticatableUser(r.Context(), grant.UserID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the authorizing user is no longer permitted to sign in")
		return
	}

	newRaw, newHash, err := generateRefreshToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to mint refresh token")
		return
	}
	// Rotate: the atomic CAS keyed on (grant.ID, oldHash) below is what
	// makes a concurrent double-refresh of this SAME still-current secret
	// resolve to exactly one winner -- the loser's Rotate call observes
	// oldHash no longer current (the winner already changed it) and
	// returns ErrConflict, mapped to the same invalid_grant every other
	// rejection in this handler uses.
	if _, err := h.store.OAuthGrants().Rotate(r.Context(), grant.ID, oldHash, newHash, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token was already used")
			return
		}
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to refresh grant")
		return
	}

	accessToken, expiresAt, err := h.auth.IssueAccessTokenForAudience(r.Context(), user.ID, 0, auth.AudienceMCP)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to mint access token")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: accessToken, TokenType: "Bearer",
		ExpiresIn: int64(time.Until(expiresAt).Seconds()), RefreshToken: newRaw,
	})
}

// issueTokenPair mints a fresh access+refresh token pair for userID/
// clientID -- the authorization_code grant's tail.
func (h *Handler) issueTokenPair(w http.ResponseWriter, r *http.Request, userID, clientID string) {
	user, err := h.auth.LoadAuthenticatableUser(r.Context(), userID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the authorizing user is no longer permitted to sign in")
		return
	}
	accessToken, expiresAt, err := h.auth.IssueAccessTokenForAudience(r.Context(), user.ID, 0, auth.AudienceMCP)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to mint access token")
		return
	}
	rawRefresh, hash, err := generateRefreshToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to mint refresh token")
		return
	}
	grant := &store.OAuthGrant{UserID: user.ID, ClientID: clientID, SecretHash: hash}
	if err := h.store.OAuthGrants().Create(r.Context(), grant); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to persist refresh grant")
		return
	}
	_ = auth.Audit(r.Context(), h.store, user.ID, "oauth.token.issue", "oauth_client:"+clientID, nil)

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: accessToken, TokenType: "Bearer",
		ExpiresIn: int64(time.Until(expiresAt).Seconds()), RefreshToken: rawRefresh,
	})
}

// generateRefreshToken returns a new random refresh token: plaintext
// (returned to the client exactly once) and its SHA-256 hex digest (the
// only form persisted, in oauth_grants.secret_hash) -- mirrors
// internal/auth's GenerateCLICredential.
func generateRefreshToken() (plaintext, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	plaintext = refreshTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, sha256Hex(plaintext), nil
}

// oauthGrantActive reports whether g is still within its sliding 90-day
// expiry window (mirrors internal/auth's credentialActive) AND has not
// passed its absolute oauthGrantMaxLifetime cap measured from CreatedAt --
// unlike the sliding window, the absolute cap is never pushed forward by
// activity, so it is checked independently and short-circuits the sliding
// check entirely once passed.
func oauthGrantActive(g *store.OAuthGrant, now time.Time) bool {
	if !now.Before(g.CreatedAt.Add(oauthGrantMaxLifetime)) {
		return false
	}
	ref := g.LastUsedAt
	if ref.IsZero() {
		ref = g.CreatedAt
	}
	return now.Before(ref.Add(oauthGrantSlidingWindow))
}
