// Package crypto implements the AES-256-GCM at-rest encryption used for
// function environment variables (tmp/06-data-model.md's
// "env_vars.value_enc"), and the HKDF key derivation that produces that
// AES key -- and other independent subkeys, like the CSRF HMAC key used by
// internal/auth -- from the single operator-supplied FUNCBOX_SESSION_SECRET
// (tmp/05-auth-and-permissions.md §5.1's config table: "FUNCBOX_SESSION_SECRET
// も AES-GCM 鍵導出に使う").
//
// Key rotation: FUNCBOX_SESSION_SECRET is not versioned. Rotating it
// invalidates every session cookie currently outstanding indirectly (see
// internal/auth: sessions are looked up by an unrelated random ID, but the
// CSRF subkey rotates too, which breaks any in-flight cookie-authenticated
// form) and, more importantly, makes every previously-encrypted
// env_vars.value_enc row permanently undecryptable, since the AES key is
// deterministically re-derived from the secret on every process start.
// Operators must treat a session-secret rotation as "every function's env
// vars need to be re-set"; a future phase could add a key-version column to
// env_vars to support in-place re-encryption instead.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KeySize is the AES-256-GCM key size in bytes.
const KeySize = 32

// ErrCiphertextTooShort is returned by Decrypt when data is shorter than
// the GCM nonce, so it cannot possibly be valid ciphertext produced by
// Encrypt.
var ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")

// DeriveKey derives a KeySize-byte key from secret using HKDF-SHA256, with
// info as a domain-separation label (e.g. "funcbox:env-vars",
// "funcbox:csrf"). Distinct info strings yield cryptographically
// independent subkeys from the same top-level secret, which is how a
// single FUNCBOX_SESSION_SECRET env var backs multiple independent uses
// without one use's key material leaking into another's.
func DeriveKey(secret, info string) ([]byte, error) {
	if secret == "" {
		return nil, errors.New("crypto: empty secret")
	}
	key := make([]byte, KeySize)
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte(info))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("crypto: derive key: %w", err)
	}
	return key, nil
}

// Encrypt seals plaintext with AES-256-GCM under key (which must be
// KeySize bytes, e.g. from DeriveKey), returning nonce||ciphertext||tag as
// a single byte slice suitable for storing directly in a BLOB column.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt: it splits data into its leading nonce and
// trailing ciphertext||tag, then opens it under key. It returns an error
// (never panics) for a wrong key, corrupted data, or truncated input.
func Decrypt(key, data []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new GCM: %w", err)
	}
	return gcm, nil
}
