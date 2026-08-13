package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/syumai/funcbox/internal/settings"
	"github.com/syumai/funcbox/internal/store"
)

// ErrIDTokenAudienceNotAllowed is returned by VerifyIDToken when the
// token's aud claim matches none of the configured audiences.
var ErrIDTokenAudienceNotAllowed = errors.New("auth: id token audience not allowed")

// ErrIDTokenEmailNotVerified is returned by VerifyIDToken when the token's
// email_verified claim is not true.
var ErrIDTokenEmailNotVerified = errors.New("auth: id token email not verified")

// IDTokenClaims is what VerifyIDToken extracts from a verified caller ID
// token, for the invoke path's org/workspace visibility check
// (tmp/05-auth-and-permissions.md §5.2).
type IDTokenClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// VerifyIDToken verifies rawIDToken (an "Authorization: Bearer <ID Token>"
// presented to a function-invoke request) against the SAME OIDC
// issuer/provider construction the login flow uses (see provider.go), and
// checks that its audience matches one of extraAudiences plus the
// configured OIDC client ID (tmp/05-auth-and-permissions.md §5.2: "aud は
// funcbox の client_id を要求（組織設定で追加の許容 audience を登録可
// 能）"). It additionally requires email_verified == true, mirroring the
// login flow's own check.
func (a *Auth) VerifyIDToken(ctx context.Context, rawIDToken string, extraAudiences []string) (*IDTokenClaims, error) {
	verifier, err := a.verifierAnyAudience(ctx)
	if err != nil {
		return nil, err
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("auth: verify id token: %w", err)
	}

	allowed := append([]string{a.cfg.ClientID}, extraAudiences...)
	if !slices.ContainsFunc(idToken.Audience, func(aud string) bool { return slices.Contains(allowed, aud) }) {
		return nil, ErrIDTokenAudienceNotAllowed
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("auth: decode id token claims: %w", err)
	}
	if !claims.EmailVerified {
		return nil, ErrIDTokenEmailNotVerified
	}

	return &IDTokenClaims{Subject: idToken.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified}, nil
}

// ResolveInvokeCaller resolves the caller of a function-invoke request for
// an org/workspace-visibility function (tmp/05-auth-and-permissions.md
// §5.2): an "Authorization: Bearer <ID Token>" header takes precedence: it
// is verified (VerifyIDToken) against the org's configured audiences and
// mapped to an active user by email. Failing that, for GET/HEAD requests
// only, the session cookie is accepted as a browser convenience fallback
// ("Cookie 認可は同一オリジンの GET/HEAD に限定し、CSRF を避ける" --
// method-restriction plus the cookie's own SameSite=Lax is what confines
// this to safe, top-level navigation).
//
// The returned user is always active (not disabled) and currently
// permitted by the organization's login rules -- same as every other
// authentication path in this package.
func (a *Auth) ResolveInvokeCaller(r *http.Request, extraAudiences []string) (*store.User, error) {
	if hdr := r.Header.Get("Authorization"); hdr != "" {
		raw, ok := strings.CutPrefix(hdr, "Bearer ")
		if !ok || raw == "" {
			return nil, ErrUnauthenticated
		}
		claims, err := a.VerifyIDToken(r.Context(), raw, extraAudiences)
		if err != nil {
			return nil, ErrUnauthenticated
		}
		return a.loadActiveUserByEmail(r.Context(), claims.Email)
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if actor, err := a.AuthenticateSessionCookie(r); err == nil {
			return actor.User, nil
		}
	}
	return nil, ErrUnauthenticated
}

// ExtraInvokeAudiences returns the org's registered extra ID-token
// audiences (tmp/05 §5.2), for callers building the extraAudiences
// argument to ResolveInvokeCaller/VerifyIDToken.
func (a *Auth) ExtraInvokeAudiences(ctx context.Context) []string {
	org, err := a.store.Organizations().Get(ctx)
	if err != nil {
		return nil
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		return nil
	}
	return orgSet.ExtraIDTokenAudiences
}
