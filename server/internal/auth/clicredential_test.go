package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

func TestGenerateCLICredential(t *testing.T) {
	plaintext, hash, err := GenerateCLICredential()
	if err != nil {
		t.Fatalf("GenerateCLICredential: %v", err)
	}
	if !strings.HasPrefix(plaintext, CLICredentialPrefix) {
		t.Fatalf("plaintext = %q, want prefix %q", plaintext, CLICredentialPrefix)
	}
	if hash != hashSecret(plaintext) {
		t.Fatalf("hash = %q, want hashSecret(plaintext) = %q", hash, hashSecret(plaintext))
	}
	if hash == plaintext {
		t.Fatal("hash should differ from plaintext")
	}
}

func TestGenerateCLICredential_Unique(t *testing.T) {
	p1, h1, err := GenerateCLICredential()
	if err != nil {
		t.Fatalf("GenerateCLICredential: %v", err)
	}
	p2, h2, err := GenerateCLICredential()
	if err != nil {
		t.Fatalf("GenerateCLICredential: %v", err)
	}
	if p1 == p2 || h1 == h2 {
		t.Fatal("two calls to GenerateCLICredential produced the same secret")
	}
}

func TestCredentialActive_SlidingWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		cred *store.CLICredential
		want bool
	}{
		{"never used, within window since creation", &store.CLICredential{CreatedAt: now.Add(-89 * 24 * time.Hour)}, true},
		{"never used, past window since creation", &store.CLICredential{CreatedAt: now.Add(-91 * 24 * time.Hour)}, false},
		{"used recently", &store.CLICredential{CreatedAt: now.Add(-200 * 24 * time.Hour), LastUsedAt: now.Add(-1 * time.Hour)}, true},
		{"used, but 90 days ago", &store.CLICredential{CreatedAt: now.Add(-200 * 24 * time.Hour), LastUsedAt: now.Add(-91 * 24 * time.Hour)}, false},
		{"exactly at the boundary is expired (After, not After-or-equal)", &store.CLICredential{CreatedAt: now.Add(-CLICredentialSlidingWindow)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := credentialActive(tt.cred, now); got != tt.want {
				t.Errorf("credentialActive() = %v, want %v", got, tt.want)
			}
		})
	}
}
