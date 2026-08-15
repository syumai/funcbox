// clicredential.go implements the CLI login credential: the long-lived
// "fbxc_..." secret
// funcbox login saves after completing the loopback+PKCE browser flow. A
// CLICredential carries no direct management-API access -- see
// accesstoken.go for the short-lived tokens it mints on demand -- and
// replaces the abolished fbx_ API-key mechanism entirely.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

// CLICredentialPrefix identifies a CLI login credential
// ("Authorization: Bearer fbxc_..." is deliberately NEVER accepted --
// Authenticate only recognizes AccessTokenPrefix; a credential must first
// be exchanged for an access token via POST /api/v1/cli/access-token).
const CLICredentialPrefix = "fbxc_"

// CLICredentialSlidingWindow is how long a CLI credential remains valid
// after its last use (or, before its first use, its creation) -- §14.4's
// "スライディング有効期限 90 日".
const CLICredentialSlidingWindow = 90 * 24 * time.Hour

// GenerateCLICredential returns a new random CLI credential: plaintext
// (shown to the CLI exactly once, saved into its config file) and its
// SHA-256 hex digest (the only form persisted, in
// cli_credentials.secret_hash).
func GenerateCLICredential() (plaintext, hash string, err error) {
	buf := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: generate CLI credential: %w", err)
	}
	plaintext = CLICredentialPrefix + base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, hashSecret(plaintext), nil
}

// hashSecret returns the SHA-256 hex digest of a plaintext secret --
// shared by CLI credentials and CLI auth codes (cliauth.go), matching how
// every other bearer-style secret in this package is hashed at rest
// (sha256Hex in session.go).
func hashSecret(plaintext string) string {
	return sha256Hex([]byte(plaintext))
}

// credentialActive reports whether cred is still within its sliding
// 90-day expiry window as of now: measured from LastUsedAt, or CreatedAt
// before the credential has ever been used.
func credentialActive(cred *store.CLICredential, now time.Time) bool {
	ref := cred.LastUsedAt
	if ref.IsZero() {
		ref = cred.CreatedAt
	}
	return now.Before(ref.Add(CLICredentialSlidingWindow))
}
