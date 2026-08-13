package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

// newPKCEPair returns a random RFC 7636 code_verifier and its S256
// challenge, exactly as the CLI's loopback login would generate them.
func newPKCEPair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	return verifier, pkceChallengeFromVerifier(verifier)
}

const validLoopbackRedirect = "http://127.0.0.1:54321/callback"

func TestValidCLILoopbackRedirect(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"127.0.0.1 with port", "http://127.0.0.1:54321/callback", true},
		{"localhost with port", "http://localhost:1/callback", true},
		{"IPv6 loopback", "http://[::1]:8080/callback", true},
		{"https rejected", "https://127.0.0.1:54321/callback", false},
		{"non-loopback host rejected", "http://evil.example:54321/callback", false},
		{"wrong path rejected", "http://127.0.0.1:54321/other", false},
		{"missing port rejected", "http://127.0.0.1/callback", false},
		{"userinfo rejected", "http://user@127.0.0.1:54321/callback", false},
		{"garbage rejected", "not-a-url", false},
		{"open redirect via // rejected", "http://127.0.0.1:1//evil.example/callback", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validCLILoopbackRedirect(tt.in); got != tt.want {
				t.Errorf("validCLILoopbackRedirect(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidPKCEChallenge(t *testing.T) {
	_, challenge := newPKCEPair(t)
	if !validPKCEChallenge(challenge) {
		t.Errorf("a freshly generated challenge should be valid: %q", challenge)
	}
	if validPKCEChallenge("too-short") {
		t.Error("a too-short challenge should be invalid")
	}
	if validPKCEChallenge(challenge + "x") {
		t.Error("a wrong-length challenge should be invalid")
	}
	if validPKCEChallenge("not base64url at all!!!!!!!!!!!!!!!!!!!!!!!") {
		t.Error("a non-base64url challenge should be invalid")
	}
}

func cliTestUser(t *testing.T, a *Auth, email string) *store.User {
	t.Helper()
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-" + email, Email: email, Name: email, Role: store.RoleMember, Status: store.UserStatusActive}
	if err := a.store.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	return u
}

// TestCLILoginFullFlow drives the whole §14.4/§14.5 pipeline purely
// against the Auth service (no HTTP): approve -> issue code -> exchange
// for a credential -> mint an access token from it -> that access token
// authenticates the management API.
func TestCLILoginFullFlow(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "device-owner@example.com")

	verifier, challenge := newPKCEPair(t)
	rawCode, err := a.IssueCLIAuthCode(t.Context(), u.ID, "  My Laptop \x07 ", validLoopbackRedirect, challenge)
	if err != nil {
		t.Fatalf("IssueCLIAuthCode: %v", err)
	}
	if rawCode == "" {
		t.Fatal("IssueCLIAuthCode returned an empty code")
	}

	plaintext, cred, err := a.ExchangeCLICode(t.Context(), rawCode, verifier)
	if err != nil {
		t.Fatalf("ExchangeCLICode: %v", err)
	}
	if cred.UserID != u.ID {
		t.Fatalf("cred.UserID = %q, want %q", cred.UserID, u.ID)
	}
	if cred.Name != "My Laptop" {
		t.Fatalf("cred.Name = %q, want sanitized %q", cred.Name, "My Laptop")
	}

	token, expiresAt, err := a.MintAccessTokenFromCredential(t.Context(), plaintext, 15*time.Minute)
	if err != nil {
		t.Fatalf("MintAccessTokenFromCredential: %v", err)
	}
	if !expiresAt.After(time.Now()) {
		t.Fatal("access token should not be already-expired")
	}
	claims, err := a.verifyAccessToken(token)
	if err != nil || claims.Sub != u.ID {
		t.Fatalf("verifyAccessToken(minted token) = %+v, %v", claims, err)
	}

	// LastUsedAt should have advanced (sliding expiry renewal).
	stored, err := a.store.CLICredentials().ByHash(t.Context(), hashSecret(plaintext))
	if err != nil {
		t.Fatalf("CLICredentials().ByHash: %v", err)
	}
	if stored.LastUsedAt.IsZero() {
		t.Fatal("LastUsedAt should be set after minting an access token")
	}
}

func TestExchangeCLICode_SingleUse(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "single-use@example.com")

	verifier, challenge := newPKCEPair(t)
	rawCode, err := a.IssueCLIAuthCode(t.Context(), u.ID, "laptop", validLoopbackRedirect, challenge)
	if err != nil {
		t.Fatalf("IssueCLIAuthCode: %v", err)
	}
	if _, _, err := a.ExchangeCLICode(t.Context(), rawCode, verifier); err != nil {
		t.Fatalf("first ExchangeCLICode: %v", err)
	}
	if _, _, err := a.ExchangeCLICode(t.Context(), rawCode, verifier); !errors.Is(err, ErrCLIAuthCodeInvalid) {
		t.Fatalf("replayed ExchangeCLICode error = %v, want ErrCLIAuthCodeInvalid", err)
	}
}

func TestExchangeCLICode_PKCEMismatchRejected(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "pkce-mismatch@example.com")

	_, challenge := newPKCEPair(t)
	rawCode, err := a.IssueCLIAuthCode(t.Context(), u.ID, "laptop", validLoopbackRedirect, challenge)
	if err != nil {
		t.Fatalf("IssueCLIAuthCode: %v", err)
	}
	wrongVerifier, _ := newPKCEPair(t)
	if _, _, err := a.ExchangeCLICode(t.Context(), rawCode, wrongVerifier); !errors.Is(err, ErrPKCEMismatch) {
		t.Fatalf("ExchangeCLICode with wrong verifier error = %v, want ErrPKCEMismatch", err)
	}
	// The code must still be consumed (single-use) even on a failed PKCE
	// check, so a stolen code can't be retried against guessed verifiers.
	if _, _, err := a.ExchangeCLICode(t.Context(), rawCode, wrongVerifier); !errors.Is(err, ErrCLIAuthCodeInvalid) {
		t.Fatalf("retry after PKCE mismatch error = %v, want ErrCLIAuthCodeInvalid", err)
	}
}

func TestExchangeCLICode_UnknownOrGarbageRejected(t *testing.T) {
	a := testAuth(t)
	verifier, _ := newPKCEPair(t)
	if _, _, err := a.ExchangeCLICode(t.Context(), "no-such-code", verifier); !errors.Is(err, ErrCLIAuthCodeInvalid) {
		t.Fatalf("unknown code error = %v, want ErrCLIAuthCodeInvalid", err)
	}
	if _, _, err := a.ExchangeCLICode(t.Context(), "", ""); !errors.Is(err, ErrCLIAuthCodeInvalid) {
		t.Fatalf("empty code/verifier error = %v, want ErrCLIAuthCodeInvalid", err)
	}
}

func TestExchangeCLICode_ExpiredCodeRejected(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "expired-code@example.com")
	verifier, challenge := newPKCEPair(t)

	raw := randomURLToken(32)
	code := &store.CLIAuthCode{ID: hashSecret(raw), UserID: u.ID, Name: "laptop", Challenge: challenge, ExpiresAt: time.Now().Add(-time.Second)}
	if err := a.store.CLIAuthCodes().Create(t.Context(), code); err != nil {
		t.Fatalf("CLIAuthCodes().Create: %v", err)
	}
	if _, _, err := a.ExchangeCLICode(t.Context(), raw, verifier); !errors.Is(err, ErrCLIAuthCodeInvalid) {
		t.Fatalf("expired code error = %v, want ErrCLIAuthCodeInvalid", err)
	}
}

func TestIssueCLIAuthCode_RejectsInvalidRequest(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "invalid-request@example.com")
	_, challenge := newPKCEPair(t)

	if _, err := a.IssueCLIAuthCode(t.Context(), u.ID, "laptop", "https://evil.example/callback", challenge); !errors.Is(err, ErrCLIAuthInvalidRequest) {
		t.Fatalf("bad redirect error = %v, want ErrCLIAuthInvalidRequest", err)
	}
	if _, err := a.IssueCLIAuthCode(t.Context(), u.ID, "laptop", validLoopbackRedirect, "short"); !errors.Is(err, ErrCLIAuthInvalidRequest) {
		t.Fatalf("bad challenge error = %v, want ErrCLIAuthInvalidRequest", err)
	}
}

func TestMintAccessTokenFromCredential_RevokedRejected(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "revoked@example.com")
	verifier, challenge := newPKCEPair(t)
	rawCode, err := a.IssueCLIAuthCode(t.Context(), u.ID, "laptop", validLoopbackRedirect, challenge)
	if err != nil {
		t.Fatalf("IssueCLIAuthCode: %v", err)
	}
	plaintext, cred, err := a.ExchangeCLICode(t.Context(), rawCode, verifier)
	if err != nil {
		t.Fatalf("ExchangeCLICode: %v", err)
	}

	if err := a.store.CLICredentials().Delete(t.Context(), cred.ID); err != nil {
		t.Fatalf("CLICredentials().Delete: %v", err)
	}
	if _, _, err := a.MintAccessTokenFromCredential(t.Context(), plaintext, 0); !errors.Is(err, ErrCLICredentialInvalid) {
		t.Fatalf("mint after revoke error = %v, want ErrCLICredentialInvalid", err)
	}
}

func TestMintAccessTokenFromCredential_ExpiredSlidingWindowRejected(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "stale-cred@example.com")

	cred := &store.CLICredential{UserID: u.ID, Name: "laptop", SecretHash: hashSecret("fbxc_teststale")}
	if err := a.store.CLICredentials().Create(t.Context(), cred); err != nil {
		t.Fatalf("CLICredentials().Create: %v", err)
	}
	// Back-date the credential past the sliding window by touching it into
	// the past directly (simulating "hasn't been used in 91 days").
	if err := a.store.CLICredentials().Touch(t.Context(), cred.ID, time.Now().Add(-91*24*time.Hour)); err != nil {
		t.Fatalf("CLICredentials().Touch: %v", err)
	}

	if _, _, err := a.MintAccessTokenFromCredential(t.Context(), "fbxc_teststale", 0); !errors.Is(err, ErrCLICredentialInvalid) {
		t.Fatalf("mint with stale credential error = %v, want ErrCLICredentialInvalid", err)
	}
}

func TestMintAccessTokenFromCredential_GarbageOrWrongPrefixRejected(t *testing.T) {
	a := testAuth(t)
	if _, _, err := a.MintAccessTokenFromCredential(t.Context(), "fbxa_not-a-credential", 0); !errors.Is(err, ErrCLICredentialInvalid) {
		t.Fatalf("wrong-prefix error = %v, want ErrCLICredentialInvalid", err)
	}
	if _, _, err := a.MintAccessTokenFromCredential(t.Context(), "fbxc_unknown-secret", 0); !errors.Is(err, ErrCLICredentialInvalid) {
		t.Fatalf("unknown secret error = %v, want ErrCLICredentialInvalid", err)
	}
}

func TestMintAccessTokenFromCredential_DisabledUserRejected(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "disabled-device-owner@example.com")
	verifier, challenge := newPKCEPair(t)
	rawCode, err := a.IssueCLIAuthCode(t.Context(), u.ID, "laptop", validLoopbackRedirect, challenge)
	if err != nil {
		t.Fatalf("IssueCLIAuthCode: %v", err)
	}
	plaintext, _, err := a.ExchangeCLICode(t.Context(), rawCode, verifier)
	if err != nil {
		t.Fatalf("ExchangeCLICode: %v", err)
	}

	u.Status = store.UserStatusDisabled
	if err := a.store.Users().Update(t.Context(), u); err != nil {
		t.Fatalf("Users().Update: %v", err)
	}
	if _, _, err := a.MintAccessTokenFromCredential(t.Context(), plaintext, 0); !errors.Is(err, ErrCLICredentialInvalid) {
		t.Fatalf("mint for disabled user error = %v, want ErrCLICredentialInvalid", err)
	}
}

// TestMintAccessTokenFromCredential_PendingUserAllowed mirrors
// validateAuthenticatable's documented behavior (a pending user can still
// authenticate; it's the API's requirePendingApproved middleware /
// dashboard pending page that block them), consistent with every other
// bearer credential this package accepts.
func TestMintAccessTokenFromCredential_PendingUserAllowed(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := cliTestUser(t, a, "pending-device-owner@example.com")
	verifier, challenge := newPKCEPair(t)
	rawCode, err := a.IssueCLIAuthCode(t.Context(), u.ID, "laptop", validLoopbackRedirect, challenge)
	if err != nil {
		t.Fatalf("IssueCLIAuthCode: %v", err)
	}
	plaintext, _, err := a.ExchangeCLICode(t.Context(), rawCode, verifier)
	if err != nil {
		t.Fatalf("ExchangeCLICode: %v", err)
	}

	u.Status = store.UserStatusPending
	if err := a.store.Users().Update(t.Context(), u); err != nil {
		t.Fatalf("Users().Update: %v", err)
	}
	if _, _, err := a.MintAccessTokenFromCredential(t.Context(), plaintext, 0); err != nil {
		t.Fatalf("mint for pending user should succeed (blocked later, at the API layer): %v", err)
	}
}
