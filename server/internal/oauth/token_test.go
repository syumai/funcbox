package oauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/auth"
)

// postToken POSTs form-encoded values to /oauth/token with no cookie jar
// (the token endpoint is a plain, unauthenticated-by-cookie public-client
// endpoint -- client_id/code_verifier/refresh_token are its only proof of
// anything).
func (env *testEnv) postToken(t *testing.T, form url.Values) *http.Response {
	t.Helper()
	resp, err := http.PostForm(env.server.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("POST /oauth/token: %v", err)
	}
	return resp
}

// exchangeCode drives the authorization_code grant to completion and
// returns the parsed token response, failing the test on any error.
func (env *testEnv) exchangeCode(t *testing.T, clientID, redirectURI, code, verifier string) tokenResponse {
	t.Helper()
	resp := env.postToken(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {redirectURI}, "client_id": {clientID},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/token status = %d", resp.StatusCode)
	}
	var tok tokenResponse
	if err := decodeJSON(resp.Body, &tok); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return tok
}

func assertOAuthError(t *testing.T, resp *http.Response, wantStatus int, wantCode string) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
	var oe oauthError
	if err := decodeJSON(resp.Body, &oe); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if oe.Error != wantCode {
		t.Errorf("error = %q, want %q", oe.Error, wantCode)
	}
}

// fullFlowTokens drives register -> login -> authorize -> approve ->
// exchange to a fresh token pair, for tests that only care about the
// refresh grant from here on.
func (env *testEnv) fullFlowTokens(t *testing.T, email string) (tok tokenResponse, clientID string) {
	t.Helper()
	f := env.driveToConsent(t, email, "https://client.example.com/callback", "s", "")
	loc := f.approve(t)
	redirLoc, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse approve redirect: %v", err)
	}
	tok = env.exchangeCode(t, f.clientID, f.redirectURI, redirLoc.Query().Get("code"), f.verifier)
	return tok, f.clientID
}

func TestToken_RefreshGrant_IssuesFreshAccessTokenWithMCPAudienceAndNoRotatedRefreshToken(t *testing.T) {
	env := newTestEnv(t)
	tok, clientID := env.fullFlowTokens(t, "alice@example.com")

	resp := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var refreshed tokenResponse
	if err := decodeJSON(resp.Body, &refreshed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(refreshed.AccessToken, "fbxa_") {
		t.Errorf("access_token = %q", refreshed.AccessToken)
	}
	// NOT asserting refreshed.AccessToken != tok.AccessToken: the access
	// token format (accesstoken.go's accessTokenClaims) has no per-mint
	// nonce, so two tokens minted for the same user/aud/TTL within the
	// same second are legitimately byte-identical -- this test only
	// needs to confirm the refresh grant successfully MINTS a new,
	// valid, correctly-audienced token, not that it differs bit-for-bit
	// from the one before it.
	if refreshed.RefreshToken != "" {
		t.Errorf("refresh_token = %q, want empty (this grant is not rotated)", refreshed.RefreshToken)
	}
	aud, ok := env.auth.AccessTokenAudience(refreshed.AccessToken)
	if !ok || aud != auth.AudienceMCP {
		t.Errorf("AccessTokenAudience = (%q, %v), want (%q, true)", aud, ok, auth.AudienceMCP)
	}
}

func TestToken_RefreshGrant_WithoutClientIDStillWorks(t *testing.T) {
	env := newTestEnv(t)
	tok, _ := env.fullFlowTokens(t, "alice@example.com")

	resp := env.postToken(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (client_id is optional for a public client's refresh grant)", resp.StatusCode)
	}
}

func TestToken_RefreshGrant_WrongClientIDRejected(t *testing.T) {
	env := newTestEnv(t)
	tok, _ := env.fullFlowTokens(t, "alice@example.com")

	resp := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {"some-other-client"},
	})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
}

func TestToken_RefreshGrant_UnknownTokenRejected(t *testing.T) {
	env := newTestEnv(t)
	resp := env.postToken(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"fbxr_totally-unknown-token"}})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
}

func TestToken_RefreshGrant_RevokedGrantRejected(t *testing.T) {
	env := newTestEnv(t)
	tok, _ := env.fullFlowTokens(t, "alice@example.com")

	grants, err := env.store.OAuthGrants().ListByUser(t.Context(), mustUserID(t, env, "alice@example.com"))
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("len(grants) = %d, want 1", len(grants))
	}
	if err := env.store.OAuthGrants().Delete(t.Context(), grants[0].ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	resp := env.postToken(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
}

func TestToken_RefreshGrant_ExpiredGrantRejected(t *testing.T) {
	env := newTestEnv(t)
	tok, _ := env.fullFlowTokens(t, "alice@example.com")

	grants, err := env.store.OAuthGrants().ListByUser(t.Context(), mustUserID(t, env, "alice@example.com"))
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("len(grants) = %d, want 1", len(grants))
	}
	// Push the grant's sliding-expiry reference point far enough into the
	// past that it's now outside oauthGrantSlidingWindow -- Touch's now
	// parameter IS that reference point (LastUsedAt), so this simulates
	// "hasn't been used in 90+ days" without needing a dedicated store
	// method or a real clock wait.
	longAgo := time.Now().Add(-oauthGrantSlidingWindow - time.Hour)
	if err := env.store.OAuthGrants().Touch(t.Context(), grants[0].ID, longAgo); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	resp := env.postToken(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
}

func TestToken_MissingGrantType(t *testing.T) {
	env := newTestEnv(t)
	resp := env.postToken(t, url.Values{})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidRequest)
}

func TestToken_UnsupportedGrantType(t *testing.T) {
	env := newTestEnv(t)
	resp := env.postToken(t, url.Values{"grant_type": {"client_credentials"}})
	assertOAuthError(t, resp, http.StatusBadRequest, errUnsupportedGrantType)
}

func mustUserID(t *testing.T, env *testEnv, email string) string {
	t.Helper()
	u, err := env.store.Users().ByEmail(t.Context(), email)
	if err != nil {
		t.Fatalf("Users().ByEmail(%q): %v", email, err)
	}
	return u.ID
}
