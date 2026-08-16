// accesstoken.go implements funcbox's short-lived access token: an
// HMAC-signed, compact claim set
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

	"github.com/syumai/funcbox/server/internal/store"
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

// AudienceMCP marks an access token as minted by server/internal/oauth's
// OAuth 2.1 authorization server (RFC 8707 resource indicator) for use
// against the /mcp endpoint -- every token that flow issues carries it,
// since /oauth/token is that flow's only token endpoint. A token with no
// Aud at all (every token minted by IssueAccessToken/print-access-token
// before this field existed, and every one minted by it since) is the
// general-purpose kind, historically accepted everywhere: acceptance
// scoping (rejecting an aud=mcp token outside /mcp, or requiring it there)
// is deliberately NOT enforced by this package -- that's a later step's
// job (mcpserver's /mcp handler and, if ever needed, the management API's
// own middleware). This field only needs to round-trip correctly today.
const AudienceMCP = "mcp"

// accessTokenClaims is the JSON payload signed into an access token.
type accessTokenClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	IAT   int64  `json:"iat"`
	EXP   int64  `json:"exp"`
	Kind  string `json:"kind"`
	// Aud is the RFC 8707 resource-indicator audience this token was
	// minted for (currently only ever AudienceMCP, or empty for a
	// general-purpose token -- see AudienceMCP's doc comment). Omitted
	// from the JSON payload when empty so a general-purpose token's
	// signed bytes are byte-for-byte identical to what this package
	// produced before this field existed -- no forced re-issuance of any
	// outstanding token.
	Aud string `json:"aud,omitempty"`
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
	return a.issueAccessToken(ctx, userID, ttl, "")
}

// IssueAccessTokenForAudience is IssueAccessToken, plus an RFC 8707
// resource-indicator audience claim (aud) embedded in the minted token --
// used by server/internal/oauth's /oauth/token endpoint to mint tokens
// scoped to AudienceMCP. See AudienceMCP's doc comment for why this is a
// distinct method rather than an extra parameter on IssueAccessToken
// itself: every existing caller of IssueAccessToken keeps minting the
// exact same aud-less token it always has.
func (a *Auth) IssueAccessTokenForAudience(ctx context.Context, userID string, ttl time.Duration, aud string) (string, time.Time, error) {
	return a.issueAccessToken(ctx, userID, ttl, aud)
}

func (a *Auth) issueAccessToken(ctx context.Context, userID string, ttl time.Duration, aud string) (string, time.Time, error) {
	u, err := a.store.Users().ByID(ctx, userID)
	if err != nil {
		return "", time.Time{}, ErrUnauthenticated
	}
	now := time.Now()
	exp := now.Add(ClampAccessTokenTTL(ttl))
	claims := accessTokenClaims{Sub: u.ID, Email: u.Email, IAT: now.Unix(), EXP: exp.Unix(), Kind: accessTokenKind, Aud: aud}
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

// AuthenticateAccessToken resolves the management-API Actor for a verified
// access token, exactly like authenticateAccessToken below, but WITHOUT
// this package's own audience restriction (session.go's Authenticate only
// accepts an aud-less token, reserving aud=mcp for /mcp -- see
// AudienceMCP's doc comment). Exported for server/internal/mcpserver,
// which accepts both aud-less and aud=mcp tokens at /mcp and enforces that
// (wider) acceptance rule itself before calling this.
func (a *Auth) AuthenticateAccessToken(ctx context.Context, raw string) (*Actor, error) {
	return a.authenticateAccessToken(ctx, raw)
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

// AccessTokenAudience verifies raw's signature/kind/expiry exactly like
// every other consumer of this token format and, if valid, returns its aud
// claim (AudienceMCP, or "" for a general-purpose token -- see
// AudienceMCP's doc comment) alongside ok=true. ok is false for any
// unverifiable token, matching this package's usual refusal to
// distinguish *why* a credential was rejected. This does NOT reload or
// revalidate the owning user -- callers that need that already have
// LoadAuthenticatableUser.
//
// Exported for server/internal/oauth's own tests (confirming aud round-
// trips through /oauth/token) and for a later step's /mcp acceptance
// scoping; this package itself never branches on the result.
func (a *Auth) AccessTokenAudience(raw string) (aud string, ok bool) {
	claims, err := a.verifyAccessToken(raw)
	if err != nil {
		return "", false
	}
	return claims.Aud, true
}

// LoadAuthenticatableUser resolves and validates userID exactly like the
// session/access-token authentication paths (loadActiveUser): a disabled
// user, or one no longer permitted to sign in under the organization's
// CURRENT login rules, is rejected -- but a pending user is allowed
// through (dashboard/API-token semantics: login succeeds, downstream
// layers react to the pending state). Exported for server/internal/oauth's
// /oauth/token endpoint, which needs this exact check before minting an
// access/refresh token pair from a redeemed authorization code or a
// refresh grant -- mirroring MintAccessTokenFromCredential's own use of
// this check for the CLI login flow's equivalent step.
func (a *Auth) LoadAuthenticatableUser(ctx context.Context, userID string) (*store.User, error) {
	return a.loadActiveUser(ctx, userID)
}
