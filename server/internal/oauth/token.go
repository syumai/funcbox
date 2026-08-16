// token.go implements POST /oauth/token: the token endpoint, handling both
// grant types this authorization server supports --
// "authorization_code" (redeeming a GET/POST /oauth/authorize consent
// decision) and "refresh_token" (renewing an access token from a
// previously issued oauth_grants row without another round trip through
// consent). Every access token minted here reuses funcbox's existing
// "fbxa_..." format (auth.IssueAccessTokenForAudience) with
// "aud":"mcp" (auth.AudienceMCP); every refresh token is a new
// "fbxr_..." secret backing a store.OAuthGrant, deliberately mirroring
// cli_credentials' sliding-90-day-expiry shape (see that type's doc
// comment) rather than rotating on each use.
package oauth

import (
	"crypto/rand"
	"encoding/base64"
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
const oauthGrantSlidingWindow = 90 * 24 * time.Hour

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

	h.issueTokenPair(w, r, code.UserID, code.ClientID)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("refresh_token")
	if !strings.HasPrefix(raw, refreshTokenPrefix) {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "refresh_token is missing or malformed")
		return
	}
	grant, err := h.store.OAuthGrants().ByHash(r.Context(), sha256Hex(raw))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "the refresh token is invalid, revoked, or unknown")
		return
	}
	if clientID := r.FormValue("client_id"); clientID != "" && clientID != grant.ClientID {
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
	// Slide the grant's expiry window forward on every successful use,
	// exactly like CLICredentials().Touch on every access-token mint.
	if err := h.store.OAuthGrants().Touch(r.Context(), grant.ID, now); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to refresh grant")
		return
	}

	accessToken, expiresAt, err := h.auth.IssueAccessTokenForAudience(r.Context(), user.ID, 0, auth.AudienceMCP)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "failed to mint access token")
		return
	}
	// No refresh_token in the response: this grant is not rotated (see
	// this file's doc comment) -- the client keeps using the same
	// refresh_token it already holds.
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(time.Until(expiresAt).Seconds()),
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

// oauthGrantActive reports whether g is still within its sliding
// 90-day expiry window as of now -- mirrors internal/auth's
// credentialActive.
func oauthGrantActive(g *store.OAuthGrant, now time.Time) bool {
	ref := g.LastUsedAt
	if ref.IsZero() {
		ref = g.CreatedAt
	}
	return now.Before(ref.Add(oauthGrantSlidingWindow))
}
