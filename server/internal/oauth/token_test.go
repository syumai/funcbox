package oauth

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/store"
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

func TestToken_RefreshGrant_IssuesFreshAccessTokenWithMCPAudienceAndRotatesRefreshToken(t *testing.T) {
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
	if !strings.HasPrefix(refreshed.RefreshToken, "fbxr_") {
		t.Fatalf("refresh_token = %q, want a fresh fbxr_ token (this grant now rotates)", refreshed.RefreshToken)
	}
	if refreshed.RefreshToken == tok.RefreshToken {
		t.Error("refresh_token did not change -- rotation must mint a NEW secret")
	}
	aud, ok := env.auth.AccessTokenAudience(refreshed.AccessToken)
	if !ok || aud != auth.AudienceMCP {
		t.Errorf("AccessTokenAudience = (%q, %v), want (%q, true)", aud, ok, auth.AudienceMCP)
	}

	// The NEW refresh token must work (checked FIRST, before touching the
	// old one below -- presenting the old, already-consumed token is
	// reuse, which by design revokes the entire family INCLUDING this new
	// token; see TestToken_RefreshGrant_ReusingConsumedTokenRevokesFamily
	// for that half of the contract, kept as a separate test so the two
	// don't step on each other's fixture).
	again := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}, "client_id": {clientID},
	})
	if again.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(again.Body)
		again.Body.Close()
		t.Fatalf("refreshing with the newly-rotated token: status = %d, body = %s", again.StatusCode, b)
	}
	again.Body.Close()

	// The OLD refresh token must no longer work at all -- it's been
	// consumed by rotation.
	reuse := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID},
	})
	assertOAuthError(t, reuse, http.StatusBadRequest, errInvalidGrant)
}

func TestToken_RefreshGrant_ReusingConsumedTokenRevokesFamily(t *testing.T) {
	env := newTestEnv(t)
	tok, clientID := env.fullFlowTokens(t, "alice@example.com")

	first := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID},
	})
	if first.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(first.Body)
		first.Body.Close()
		t.Fatalf("first refresh status = %d, body = %s", first.StatusCode, b)
	}
	var rotated tokenResponse
	if err := decodeJSON(first.Body, &rotated); err != nil {
		t.Fatalf("decode: %v", err)
	}
	first.Body.Close()

	// Present the OLD (now-consumed) refresh token again: this is reuse
	// of an already-rotated secret, treated as theft -- the whole grant
	// (including the token `rotated` above just received) is revoked.
	reuse := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID},
	})
	assertOAuthError(t, reuse, http.StatusBadRequest, errInvalidGrant)

	// The NEW token (from the legitimate rotation) must ALSO now be
	// dead, since reuse detection revokes the entire family.
	afterRevoke := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rotated.RefreshToken}, "client_id": {clientID},
	})
	assertOAuthError(t, afterRevoke, http.StatusBadRequest, errInvalidGrant)
}

func TestToken_RefreshGrant_ConcurrentDoubleRefreshOnlyOneWins(t *testing.T) {
	env := newTestEnv(t)
	tok, clientID := env.fullFlowTokens(t, "alice@example.com")

	// Deliberately not using the postToken/t.Fatalf-based helpers inside
	// these goroutines: testing.T.FailNow (which Fatalf calls) must only
	// ever be called from the goroutine running the test itself, not from
	// goroutines the test spawns -- so failures here are collected and
	// reported back on the main goroutine instead.
	const attempts = 10
	var wg sync.WaitGroup
	statuses := make([]int, attempts)
	errs := make([]error, attempts)
	form := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID},
	}
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.PostForm(env.server.URL+"/oauth/token", form)
			if err != nil {
				errs[i] = err
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	oks, others := 0, 0
	for i, s := range statuses {
		if errs[i] != nil {
			t.Fatalf("POST /oauth/token (attempt %d): %v", i, errs[i])
		}
		if s == http.StatusOK {
			oks++
		} else {
			others++
		}
	}
	if oks != 1 {
		t.Errorf("concurrent double-refresh: %d of %d attempts got 200, want exactly 1", oks, attempts)
	}
	if others != attempts-1 {
		t.Errorf("concurrent double-refresh: %d attempts got a non-200 status, want %d", others, attempts-1)
	}
}

func TestToken_RefreshGrant_MissingClientIDRejected(t *testing.T) {
	env := newTestEnv(t)
	tok, _ := env.fullFlowTokens(t, "alice@example.com")

	resp := env.postToken(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}})
	assertOAuthError(t, resp, http.StatusBadRequest, errInvalidGrant)
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

// TestOAuthGrantActive_AbsoluteLifetimeCap unit-tests oauthGrantActive
// directly (rather than end-to-end through a real store) since
// OAuthGrantRepo.Create always stamps CreatedAt to the real current time --
// there is no store-level way to construct a grant already past its
// absolute cap without bypassing the store abstraction, whereas
// oauthGrantActive is the exact, sole predicate handleRefreshTokenGrant
// calls, so testing it directly against a hand-built *store.OAuthGrant
// covers the real behavior precisely.
func TestOAuthGrantActive_AbsoluteLifetimeCap(t *testing.T) {
	now := time.Now()

	t.Run("PastAbsoluteCapEvenIfRecentlyUsed", func(t *testing.T) {
		g := &store.OAuthGrant{
			CreatedAt:  now.Add(-oauthGrantMaxLifetime - time.Hour),
			LastUsedAt: now, // sliding window alone would allow this
		}
		if oauthGrantActive(g, now) {
			t.Error("grant past its absolute lifetime cap must not be active, even when recently used")
		}
	})

	t.Run("UnderAbsoluteCapSlidingWindowStillApplies", func(t *testing.T) {
		g := &store.OAuthGrant{
			CreatedAt:  now.Add(-oauthGrantMaxLifetime + 24*time.Hour), // just under the cap
			LastUsedAt: now,
		}
		if !oauthGrantActive(g, now) {
			t.Error("grant under its absolute lifetime cap and recently used must be active")
		}
	})

	t.Run("UnderAbsoluteCapButSlidingWindowExpired", func(t *testing.T) {
		g := &store.OAuthGrant{
			CreatedAt:  now.Add(-oauthGrantMaxLifetime + 24*time.Hour), // well under the cap
			LastUsedAt: now.Add(-oauthGrantSlidingWindow - time.Hour),  // but stale
		}
		if oauthGrantActive(g, now) {
			t.Error("grant under its absolute cap but outside its sliding window must not be active")
		}
	})

	t.Run("NeverUsedFallsBackToCreatedAt", func(t *testing.T) {
		g := &store.OAuthGrant{CreatedAt: now.Add(-oauthGrantSlidingWindow + time.Hour)}
		if !oauthGrantActive(g, now) {
			t.Error("a never-used grant within its sliding window (measured from CreatedAt) must be active")
		}
	})
}

func TestToken_RefreshGrant_ResourceValidatedAtAuthorizeStillWorksAfterRefresh(t *testing.T) {
	env := newTestEnv(t)
	f := env.driveToConsent(t, "alice@example.com", "https://client.example.com/callback", "s", env.server.URL+"/mcp")
	loc := f.approve(t)
	redirLoc, _ := url.Parse(loc)
	tok := env.exchangeCode(t, f.clientID, f.redirectURI, redirLoc.Query().Get("code"), f.verifier)

	resp := env.postToken(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {f.clientID},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var refreshed tokenResponse
	if err := decodeJSON(resp.Body, &refreshed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	aud, ok := env.auth.AccessTokenAudience(refreshed.AccessToken)
	if !ok || aud != auth.AudienceMCP {
		t.Errorf("AccessTokenAudience = (%q, %v), want (%q, true)", aud, ok, auth.AudienceMCP)
	}
}

func mustUserID(t *testing.T, env *testEnv, email string) string {
	t.Helper()
	u, err := env.store.Users().ByEmail(t.Context(), email)
	if err != nil {
		t.Fatalf("Users().ByEmail(%q): %v", email, err)
	}
	return u.ID
}
