// cliauth.go implements the loopback+PKCE `funcbox login` flow:
//
//  1. The dashboard's explicit "funcbox CLI login" approval page (a
//     session-authenticated SSR route under server/dashboard, NOT this
//     package -- it reaches this package only through the management
//     API's POST /api/v1/cli/authorize) calls IssueCLIAuthCode once the
//     user clicks Approve, producing a one-time code handed back to the
//     CLI's loopback listener.
//  2. The CLI exchanges that code (+ its PKCE verifier) for a
//     CLICredential via ExchangeCLICode, at the unauthenticated
//     POST /api/v1/cli/token -- the code+verifier pair IS the proof of
//     identity, there is no session/bearer credential on this call.
//  3. Later, MintAccessTokenFromCredential turns a saved CLICredential
//     into a short-lived access token (accesstoken.go) at
//     POST /api/v1/cli/access-token.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

// cliAuthCodeLifetime bounds how long an approved CLI login request waits
// to be redeemed by the loopback callback -- short, since the whole
// exchange happens within the same browser round trip.
const cliAuthCodeLifetime = 5 * time.Minute

// pkceChallengeLength is len(base64.RawURLEncoding.EncodeToString(sha256
// digest)): a well-formed S256 PKCE challenge is always exactly this long.
const pkceChallengeLength = 43 // ceil(32 bytes * 8 / 6), no padding

// maxCLIDeviceNameLength bounds the device name stored on a CLIAuthCode /
// CLICredential (the `name` query parameter is caller-supplied, from the
// CLI's own hostname, and must never be trusted to be well-formed).
const maxCLIDeviceNameLength = 128

var (
	// ErrCLIAuthInvalidRequest is returned by IssueCLIAuthCode when
	// redirect or challenge is malformed -- rejected before any code is
	// ever minted.
	ErrCLIAuthInvalidRequest = errors.New("auth: invalid CLI login request")
	// ErrCLIAuthCodeInvalid is returned by ExchangeCLICode for an unknown,
	// expired, or already-consumed code.
	ErrCLIAuthCodeInvalid = errors.New("auth: CLI authorization code is invalid, expired, or already used")
	// ErrPKCEMismatch is returned by ExchangeCLICode when the presented
	// verifier does not hash to the challenge the code was issued with.
	ErrPKCEMismatch = errors.New("auth: PKCE verifier does not match the authorization's challenge")
	// ErrCLICredentialInvalid is returned by MintAccessTokenFromCredential
	// for an unknown, malformed, revoked, expired, or no-longer-eligible
	// (disabled user / login rules) credential. Deliberately as
	// undifferentiated as ErrUnauthenticated, for the same reason: a
	// caller shouldn't be able to fingerprint *why* a credential was
	// rejected.
	ErrCLICredentialInvalid = errors.New("auth: CLI credential is invalid, revoked, or expired")
)

// sanitizeCLIDeviceName strips control characters and truncates name (the
// caller-supplied `name` query parameter) to a length safe to store and to
// render, unescaped, on the dashboard's approval page and "connected
// devices" list.
func sanitizeCLIDeviceName(name string) string {
	// Strip control characters BEFORE trimming surrounding whitespace: a
	// control character sitting next to trailing/leading spaces would
	// otherwise stop TrimSpace short of the real edge (e.g. "Laptop \x07 "
	// -- TrimSpace alone only removes the outermost space, leaving a
	// dangling one behind once \x07 is later dropped).
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	name = strings.TrimSpace(b.String())
	if len(name) > maxCLIDeviceNameLength {
		name = name[:maxCLIDeviceNameLength]
	}
	if name == "" {
		return "unknown device"
	}
	return name
}

// validCLILoopbackRedirect reports whether redirect is an acceptable
// loopback callback URL for the CLI's local listener: plain HTTP, host
// 127.0.0.1/localhost/::1, an explicit port, no userinfo, and exactly the
// "/callback" path funcbox login always requests -- this is the CLI-login
// flow's own open-redirect guard (mirroring §14.3's next= validation): the
// dashboard must never be tricked into handing a one-time code to an
// arbitrary redirect target.
func validCLILoopbackRedirect(redirect string) bool {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "/callback" {
		return false
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return false
	}
	return u.Port() != ""
}

// validPKCEChallenge reports whether challenge looks like a well-formed
// S256 PKCE challenge: base64url(no padding) of exactly a SHA-256 digest.
func validPKCEChallenge(challenge string) bool {
	if len(challenge) != pkceChallengeLength {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

// pkceChallengeFromVerifier computes the S256 PKCE challenge for verifier,
// matching RFC 7636: base64url(no padding) of SHA-256(verifier).
func pkceChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IssueCLIAuthCode is called by POST /api/v1/cli/authorize (session +
// CSRF-protected, dispatched from the dashboard's explicit approval page
// -- see this file's doc comment) once userID has clicked Approve. It
// validates redirect/challenge, mints a one-time code bound to userID, and
// returns the raw code to hand back to the CLI's loopback listener.
func (a *Auth) IssueCLIAuthCode(ctx context.Context, userID, name, redirect, challenge string) (rawCode string, err error) {
	if !validCLILoopbackRedirect(redirect) || !validPKCEChallenge(challenge) {
		return "", ErrCLIAuthInvalidRequest
	}
	raw := randomURLToken(32)
	code := &store.CLIAuthCode{
		ID: hashSecret(raw), UserID: userID, Name: sanitizeCLIDeviceName(name),
		Challenge: challenge, ExpiresAt: time.Now().Add(cliAuthCodeLifetime),
	}
	if err := a.store.CLIAuthCodes().Create(ctx, code); err != nil {
		return "", err
	}
	return raw, nil
}

// ExchangeCLICode implements the unauthenticated POST /api/v1/cli/token:
// it single-use-consumes rawCode, verifies verifier against the PKCE
// challenge the code was issued with, and mints a brand-new CLICredential
// for the code's user. The code+verifier pair is itself the proof of
// identity -- there is no session or bearer credential on this call.
func (a *Auth) ExchangeCLICode(ctx context.Context, rawCode, verifier string) (plaintext string, cred *store.CLICredential, err error) {
	if rawCode == "" || verifier == "" {
		return "", nil, ErrCLIAuthCodeInvalid
	}
	code, err := a.store.CLIAuthCodes().Consume(ctx, hashSecret(rawCode), time.Now())
	if err != nil {
		return "", nil, ErrCLIAuthCodeInvalid
	}
	if !constantTimeEqual(pkceChallengeFromVerifier(verifier), code.Challenge) {
		return "", nil, ErrPKCEMismatch
	}
	plaintext, hash, err := GenerateCLICredential()
	if err != nil {
		return "", nil, err
	}
	cred = &store.CLICredential{UserID: code.UserID, Name: code.Name, SecretHash: hash}
	if err := a.store.CLICredentials().Create(ctx, cred); err != nil {
		return "", nil, err
	}
	_ = Audit(ctx, a.store, code.UserID, "cli_credential.create", "cli_credential:"+cred.ID, map[string]any{"name": cred.Name})
	return plaintext, cred, nil
}

// MintAccessTokenFromCredential implements the authenticated-by-credential
// POST /api/v1/cli/access-token: it validates rawCredential (prefix, hash
// lookup, the sliding 90-day expiry window, and the owning user's current
// status/login rules -- validateAuthenticatable, exactly like every other
// bearer credential this package accepts), advances the credential's
// sliding-expiry clock (Touch), and mints a fresh access token.
func (a *Auth) MintAccessTokenFromCredential(ctx context.Context, rawCredential string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	if !strings.HasPrefix(rawCredential, CLICredentialPrefix) {
		return "", time.Time{}, ErrCLICredentialInvalid
	}
	cred, err := a.store.CLICredentials().ByHash(ctx, hashSecret(rawCredential))
	if err != nil {
		return "", time.Time{}, ErrCLICredentialInvalid
	}
	now := time.Now()
	if !credentialActive(cred, now) {
		return "", time.Time{}, ErrCLICredentialInvalid
	}
	if _, err := a.loadActiveUser(ctx, cred.UserID); err != nil {
		return "", time.Time{}, ErrCLICredentialInvalid
	}
	if err := a.store.CLICredentials().Touch(ctx, cred.ID, now); err != nil {
		return "", time.Time{}, err
	}
	token, expiresAt, err = a.IssueAccessToken(ctx, cred.UserID, ttl)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}
