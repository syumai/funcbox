// accesstoken.go implements funcbox's short-lived access token (§14.5 of
// tmp/14-auth-and-pool-improvements.md): an HMAC-signed, compact claim set
// minted from a CLI credential (clicredential.go) via
// POST /api/v1/cli/access-token. It is the sole replacement for the
// abolished fbx_ API key, accepted in two places: the management API's
// "Authorization: Bearer" (session.go's Authenticate) and function
// invocation's org/workspace visibility check (idtoken.go's
// ResolveInvokeCaller), alongside Google/GitHub ID tokens and the session
// cookie.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// AccessTokenPrefix marks a bearer credential as a funcbox-signed access
// token, distinguishing it from a Google/GitHub OIDC ID token (a bare
// three-segment JWT with no such prefix) wherever both are accepted.
const AccessTokenPrefix = "fbxa_"

// DefaultAccessTokenTTL is used when print-access-token/POST
// /api/v1/cli/access-token is not given an explicit --ttl.
const DefaultAccessTokenTTL = 15 * time.Minute

// MaxAccessTokenTTL is the longest an access token may live: the server
// clamps any requested TTL to this, it never trusts the caller's value
// outright.
const MaxAccessTokenTTL = time.Hour

// accessTokenKeyInfo is the HKDF domain-separation label deriving
// Auth.accessKey from FUNCBOX_SESSION_SECRET (config.go's New), the same
// mechanism invokesso.go uses for its own cookie-signing subkey.
const accessTokenKeyInfo = "funcbox:access-token"

// accessTokenKind is accessTokenClaims.Kind's only valid value -- present
// so a signature-valid but structurally different funcbox token (there are
// none today, but the field exists for forward compatibility) is never
// mistaken for an access token.
const accessTokenKind = "access"

// accessTokenClaims is the JSON payload signed into an access token.
type accessTokenClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	IAT   int64  `json:"iat"`
	EXP   int64  `json:"exp"`
	Kind  string `json:"kind"`
}

// ErrAccessTokenTTLTooLong is returned when a caller's requested TTL
// exceeds MaxAccessTokenTTL. Server callers generally clamp instead of
// rejecting (see ClampAccessTokenTTL); this is exposed for callers that
// want to surface an explicit error instead.
var ErrAccessTokenTTLTooLong = errors.New("auth: access token ttl exceeds the 1 hour maximum")

// ClampAccessTokenTTL resolves a requested access-token TTL: zero/negative
// falls back to DefaultAccessTokenTTL, and anything past MaxAccessTokenTTL
// is capped to it -- "TTL とサーバー側上限の min" (§14.5).
func ClampAccessTokenTTL(requested time.Duration) time.Duration {
	if requested <= 0 {
		return DefaultAccessTokenTTL
	}
	if requested > MaxAccessTokenTTL {
		return MaxAccessTokenTTL
	}
	return requested
}

// IssueAccessToken signs a new access token for userID, valid for
// ClampAccessTokenTTL(ttl). It loads the user to populate the email claim
// and, per §14.5, does NOT re-validate status/login rules itself -- callers
// that mint from an untrusted credential (cliauth.go's
// MintAccessTokenFromCredential, the POST /api/v1/cli/access-token
// handler's implementation) are responsible for that check beforehand;
// this method is also used directly by trusted internal callers (tests,
// ServeInternal-adjacent shortcuts) that have already resolved a valid
// actor.
func (a *Auth) IssueAccessToken(ctx context.Context, userID string, ttl time.Duration) (string, time.Time, error) {
	u, err := a.store.Users().ByID(ctx, userID)
	if err != nil {
		return "", time.Time{}, ErrUnauthenticated
	}
	now := time.Now()
	exp := now.Add(ClampAccessTokenTTL(ttl))
	claims := accessTokenClaims{Sub: u.ID, Email: u.Email, IAT: now.Unix(), EXP: exp.Unix(), Kind: accessTokenKind}
	token, err := a.signAccessToken(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func (a *Auth) signAccessToken(c accessTokenClaims) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, a.accessKey)
	_, _ = m.Write([]byte(p))
	sig := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	return AccessTokenPrefix + p + "." + sig, nil
}

// verifyAccessToken checks raw's HMAC signature, kind, and expiry, and
// returns its claims. It does NOT reload or revalidate the user -- callers
// (authenticateAccessToken below, ResolveInvokeCaller) do that via
// loadActiveUser/loadActiveUserByEmail exactly like every other credential
// this package accepts, so a login-rule change or account disable takes
// effect on the token's very next use, same as a session cookie.
func (a *Auth) verifyAccessToken(raw string) (*accessTokenClaims, error) {
	body, ok := strings.CutPrefix(raw, AccessTokenPrefix)
	if !ok {
		return nil, ErrUnauthenticated
	}
	p, sig, ok := strings.Cut(body, ".")
	if !ok {
		return nil, ErrUnauthenticated
	}
	m := hmac.New(sha256.New, a.accessKey)
	_, _ = m.Write([]byte(p))
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, m.Sum(nil)) {
		return nil, ErrUnauthenticated
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var c accessTokenClaims
	if json.Unmarshal(b, &c) != nil || c.Kind != accessTokenKind || c.Sub == "" {
		return nil, ErrUnauthenticated
	}
	if time.Now().Unix() >= c.EXP {
		return nil, ErrUnauthenticated
	}
	return &c, nil
}

// authenticateAccessToken resolves the management-API Actor for a verified
// access token, mirroring the retired authenticateToken's shape (load,
// validateAuthenticatable, MethodAccessToken).
func (a *Auth) authenticateAccessToken(ctx context.Context, raw string) (*Actor, error) {
	claims, err := a.verifyAccessToken(raw)
	if err != nil {
		return nil, err
	}
	user, err := a.loadActiveUser(ctx, claims.Sub)
	if err != nil {
		return nil, err
	}
	return &Actor{User: user, Method: MethodAccessToken}, nil
}
