package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

func TestClampAccessTokenTTL(t *testing.T) {
	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero defaults", 0, DefaultAccessTokenTTL},
		{"negative defaults", -time.Minute, DefaultAccessTokenTTL},
		{"within range unchanged", 30 * time.Minute, 30 * time.Minute},
		{"exactly max unchanged", MaxAccessTokenTTL, MaxAccessTokenTTL},
		{"over max clamps", 2 * time.Hour, MaxAccessTokenTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClampAccessTokenTTL(tt.in); got != tt.want {
				t.Errorf("ClampAccessTokenTTL(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestIssueAndVerifyAccessToken_RoundTrip(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-at", Email: "at@example.com", Name: "AT", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := a.store.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	token, expiresAt, err := a.IssueAccessToken(t.Context(), u.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if !strings.HasPrefix(token, AccessTokenPrefix) {
		t.Fatalf("token = %q, want prefix %q", token, AccessTokenPrefix)
	}
	if !expiresAt.After(time.Now()) || expiresAt.After(time.Now().Add(16*time.Minute)) {
		t.Fatalf("expiresAt = %v, want ~15 minutes from now", expiresAt)
	}

	claims, err := a.verifyAccessToken(token)
	if err != nil {
		t.Fatalf("verifyAccessToken: %v", err)
	}
	if claims.Sub != u.ID || claims.Email != u.Email || claims.Kind != accessTokenKind {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestVerifyAccessToken_RejectsTamperedAndExpired(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-at2", Email: "at2@example.com", Name: "AT2", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := a.store.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	token, _, err := a.IssueAccessToken(t.Context(), u.ID, time.Minute)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if _, err := a.verifyAccessToken(token + "x"); err == nil {
		t.Fatal("tampered token should be rejected")
	}
	if _, err := a.verifyAccessToken("not-even-close-to-a-token"); err == nil {
		t.Fatal("garbage token should be rejected")
	}
	if _, err := a.verifyAccessToken(""); err == nil {
		t.Fatal("empty token should be rejected")
	}

	// A signature-valid but already-expired claim set must be rejected.
	expired, err := a.signAccessToken(accessTokenClaims{
		Sub: u.ID, Email: u.Email, Kind: accessTokenKind,
		IAT: time.Now().Add(-time.Hour).Unix(), EXP: time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("signAccessToken: %v", err)
	}
	if _, err := a.verifyAccessToken(expired); err == nil {
		t.Fatal("expired token should be rejected")
	}

	// A different Auth instance (different SessionSecret, so a different
	// derived key) must not accept this Auth's tokens.
	other, err := New(Config{
		Mode: ModeDev, BaseURL: "http://127.0.0.1:8080", ListenAddr: "127.0.0.1:8080",
		SessionSecret: "a-completely-different-secret-value",
	}, a.store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := other.verifyAccessToken(token); err == nil {
		t.Fatal("token signed by a different key should be rejected")
	}
}

func TestAccessToken_AcceptedAsBearerForManagementAPI(t *testing.T) {
	a := testAuth(t)
	seedAllowAllLoginRule(t, a.store)
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-at3", Email: "at3@example.com", Name: "AT3", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := a.store.Users().Create(t.Context(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	token, _, err := a.IssueAccessToken(t.Context(), u.ID, 0)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	actor, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if actor.User.ID != u.ID || actor.Method != MethodAccessToken {
		t.Fatalf("actor = %+v", actor)
	}

	// A CLI credential (fbxc_...) must never be accepted directly.
	credReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	credReq.Header.Set("Authorization", "Bearer "+CLICredentialPrefix+"whatever")
	if _, err := a.Authenticate(credReq); err == nil {
		t.Fatal("a raw CLI credential should never authenticate the management API")
	}
}
