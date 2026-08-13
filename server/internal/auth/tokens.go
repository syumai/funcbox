package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// §5.1: "Authorization: Bearer fbx_...").
const TokenPrefix = "fbx_"

// MaxTokenTTL is the longest expiry an API token may be issued with
const MaxTokenTTL = 90 * 24 * time.Hour

// ErrTokenTTLInvalid is returned when a requested token expiry is missing,
// zero/negative, or exceeds MaxTokenTTL.
var ErrTokenTTLInvalid = errors.New("auth: token expiry is required and must be between 1 second and 90 days from now")

// GenerateToken returns a new random API token: plaintext (shown to the
// caller exactly once, in the POST /api/v1/me/tokens response body) and
// its SHA-256 hex digest (the only form persisted, in
// api_tokens.token_hash).
func GenerateToken() (plaintext, hash string, err error) {
	buf := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: generate token: %w", err)
	}
	plaintext = TokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, HashToken(plaintext), nil
}

// HashToken returns the SHA-256 hex digest of a plaintext token, matching
// how GenerateToken's hash and every token lookup are computed.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// ValidateTokenTTL reports whether expiresAt is an acceptable API token
// expiry relative to now: strictly in the future and no further out than
// MaxTokenTTL.
func ValidateTokenTTL(now, expiresAt time.Time) error {
	if !expiresAt.After(now) {
		return ErrTokenTTLInvalid
	}
	if expiresAt.After(now.Add(MaxTokenTTL)) {
		return ErrTokenTTLInvalid
	}
	return nil
}
