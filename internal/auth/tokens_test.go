package auth

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	plaintext, hash, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(plaintext, TokenPrefix) {
		t.Fatalf("plaintext = %q, want prefix %q", plaintext, TokenPrefix)
	}
	if hash != HashToken(plaintext) {
		t.Fatalf("hash = %q, want HashToken(plaintext) = %q", hash, HashToken(plaintext))
	}
	if hash == plaintext {
		t.Fatal("hash should differ from plaintext")
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	p1, h1, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	p2, h2, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if p1 == p2 || h1 == h2 {
		t.Fatal("two calls to GenerateToken produced the same token")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	if HashToken("fbx_abc") != HashToken("fbx_abc") {
		t.Fatal("HashToken is not deterministic")
	}
	if HashToken("fbx_abc") == HashToken("fbx_abd") {
		t.Fatal("HashToken collided for different inputs")
	}
}

func TestValidateTokenTTL(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		expiresAt time.Time
		wantErr   bool
	}{
		{"1 day", now.Add(24 * time.Hour), false},
		{"exactly 90 days", now.Add(MaxTokenTTL), false},
		{"91 days", now.Add(91 * 24 * time.Hour), true},
		{"in the past", now.Add(-1 * time.Hour), true},
		{"equal to now", now, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenTTL(now, tt.expiresAt)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTokenTTL(now, %v) error = %v, wantErr %v", tt.expiresAt, err, tt.wantErr)
			}
		})
	}
}
