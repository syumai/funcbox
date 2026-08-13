package dashboard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/syumai/funcbox/internal/store"
)

// callerTokenKeyInfo is the HKDF domain-separation label
// (fcrypto.DeriveKey's "info" parameter) this package's caller-token HMAC
// subkey is derived under, from the same FUNCBOX_SESSION_SECRET every
// other funcbox subkey (CSRF, env-var encryption) derives from -- see
// internal/crypto's package doc.
const callerTokenKeyInfo = "funcbox:dashboard-caller-token"

// callerTokenTTL bounds how long a signed caller token stays valid after
// issuance. It only needs to outlive ONE HTTP request's handling (the Go
// hosting layer mints a fresh token per request -- see server.go's
// ServeHTTP), so this is deliberately short; it exists purely so a token
// captured by something logging request headers can't be replayed
// indefinitely, not to model any real session lifetime.
const callerTokenTTL = 5 * time.Minute

// callerClaims is what a signed caller token asserts about the dashboard
// user on whose behalf an env.INTERNAL_API call is being made. It is
// deliberately minimal: just enough for internal/api's handlers to build
// an *auth.Actor (see internalapi.go) without a second store round trip.
type callerClaims struct {
	UserID   string `json:"uid"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	IssuedAt int64  `json:"iat"`
}

// signCallerToken produces the opaque string funcbox's Go dashboard hosting
// layer hands the guest as the X-Funcbox-Caller-Token request header (see
// server.go), and that the dashboard's client-side code (dashboard/src/api.ts)
// threads back unchanged as every env.INTERNAL_API call's callerToken
// argument. Format: base64url(JSON claims) + "." + hex(HMAC-SHA256(key,
// JSON claims)) -- deliberately mirroring internal/auth's own oauthState
// cookie signing scheme (login.go's signState/parseState), the same
// "sign a JSON payload, don't encrypt it" pattern for a value that only
// needs tamper-evidence, not confidentiality (the claims -- user id, email,
// name, role -- are not secret; a forged SIGNATURE is what must be
// impossible).
func signCallerToken(key []byte, c callerClaims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("dashboard: marshal caller claims: %w", err)
	}
	sig := hmacHex(key, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sig, nil
}

// verifyCallerToken is signCallerToken's inverse, and the ONE place this
// package enforces "is this identity claim genuinely from funcbox's own Go
// host" -- called from inside the INTERNAL_API binding (internalapi.go) on
// EVERY call, not just once per pool instance, because bindings are fixed
// per pooled instance while identity varies per request (see doc.go).
// verifyCallerToken deliberately fails closed on any malformed input,
// signature mismatch, or staleness rather than trying to recover a partial
// identity.
func verifyCallerToken(key []byte, token string) (callerClaims, error) {
	payloadB64, sig, ok := strings.Cut(token, ".")
	if !ok {
		return callerClaims{}, errors.New("dashboard: malformed caller token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return callerClaims{}, fmt.Errorf("dashboard: malformed caller token: %w", err)
	}
	if !hmac.Equal([]byte(hmacHex(key, payload)), []byte(sig)) {
		return callerClaims{}, errors.New("dashboard: caller token signature mismatch")
	}
	var c callerClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return callerClaims{}, fmt.Errorf("dashboard: malformed caller token payload: %w", err)
	}
	if c.UserID == "" {
		return callerClaims{}, errors.New("dashboard: caller token missing uid")
	}
	if time.Since(time.Unix(c.IssuedAt, 0)) > callerTokenTTL {
		return callerClaims{}, errors.New("dashboard: caller token expired")
	}
	return c, nil
}

// actor converts verified claims into the *auth.Actor internal/api's
// handlers expect (see internal/api's Handler.ServeInternal), constructing
// a store.User directly from the signed claims rather than re-loading one
// from the store -- the claims already ARE the authoritative identity
// funcbox's Go host resolved from the real session cookie moments earlier
// (see server.go's ServeHTTP), and re-deriving it here would just be an
// extra round trip to confirm what the signature already guarantees.
func (c callerClaims) storeUser() *store.User {
	return &store.User{ID: c.UserID, Email: c.Email, Name: c.Name, Role: store.Role(c.Role)}
}

func hmacHex(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}
