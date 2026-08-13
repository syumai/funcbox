package crypto_test

import (
	"testing"

	"github.com/syumai/funcbox/server/internal/crypto"
)

func TestDeriveKey_DeterministicAndLengthCorrect(t *testing.T) {
	k1, err := crypto.DeriveKey("secret", "info-a")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if len(k1) != crypto.KeySize {
		t.Fatalf("len(key) = %d, want %d", len(k1), crypto.KeySize)
	}
	k2, err := crypto.DeriveKey("secret", "info-a")
	if err != nil {
		t.Fatalf("DeriveKey (again): %v", err)
	}
	if string(k1) != string(k2) {
		t.Fatal("DeriveKey is not deterministic for the same secret+info")
	}
}

func TestDeriveKey_DifferentInfoYieldsDifferentKeys(t *testing.T) {
	k1, _ := crypto.DeriveKey("secret", "info-a")
	k2, _ := crypto.DeriveKey("secret", "info-b")
	if string(k1) == string(k2) {
		t.Fatal("different info strings produced the same key")
	}
}

func TestDeriveKey_DifferentSecretYieldsDifferentKeys(t *testing.T) {
	k1, _ := crypto.DeriveKey("secret-1", "info")
	k2, _ := crypto.DeriveKey("secret-2", "info")
	if string(k1) == string(k2) {
		t.Fatal("different secrets produced the same key")
	}
}

func TestDeriveKey_EmptySecretErrors(t *testing.T) {
	if _, err := crypto.DeriveKey("", "info"); err == nil {
		t.Fatal("DeriveKey(\"\", ...) = nil error, want an error")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key, err := crypto.DeriveKey("s3cr3t", "funcbox:env-vars")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	plaintext := []byte("super secret value")

	ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ciphertext) == string(plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	got, err := crypto.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestEncrypt_Nondeterministic(t *testing.T) {
	key, _ := crypto.DeriveKey("s3cr3t", "info")
	c1, _ := crypto.Encrypt(key, []byte("hello"))
	c2, _ := crypto.Encrypt(key, []byte("hello"))
	if string(c1) == string(c2) {
		t.Fatal("Encrypt produced identical ciphertext twice (nonce reuse)")
	}
}

func TestDecrypt_WrongKeyFails(t *testing.T) {
	key1, _ := crypto.DeriveKey("secret-1", "info")
	key2, _ := crypto.DeriveKey("secret-2", "info")
	ciphertext, err := crypto.Encrypt(key1, []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := crypto.Decrypt(key2, ciphertext); err == nil {
		t.Fatal("Decrypt with wrong key succeeded, want error")
	}
}

func TestDecrypt_TooShortFails(t *testing.T) {
	key, _ := crypto.DeriveKey("secret", "info")
	if _, err := crypto.Decrypt(key, []byte("x")); err == nil {
		t.Fatal("Decrypt(too short) = nil error, want error")
	}
}

func TestDecrypt_TamperedFails(t *testing.T) {
	key, _ := crypto.DeriveKey("secret", "info")
	ciphertext, err := crypto.Encrypt(key, []byte("hello world"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := crypto.Decrypt(key, tampered); err == nil {
		t.Fatal("Decrypt(tampered) = nil error, want error")
	}
}
