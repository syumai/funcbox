package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// ErrIDTokenAudienceNotAllowed is returned by VerifyIDToken when the
// token's aud claim matches none of the configured audiences.
var ErrIDTokenAudienceNotAllowed = errors.New("auth: id token audience not allowed")

// ErrIDTokenEmailNotVerified is returned by VerifyIDToken when the token's
// email_verified claim is not true.
var ErrIDTokenEmailNotVerified = errors.New("auth: id token email not verified")

// IDTokenClaims is what VerifyIDToken extracts from a verified caller ID
// token, for the invoke path's org/workspace visibility check
type IDTokenClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// VerifyIDToken verifies rawIDToken (an "Authorization: Bearer <ID Token>"
// presented to a function-invoke request) against the SAME OIDC
// issuer/provider construction the login flow uses (see provider.go), and
// checks that its audience matches one of extraAudiences plus the
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

// ResolveInvokeCaller resolves a function caller. A bearer ID token takes
// precedence. For GET/HEAD only, a function-ID and exact-host-bound invoke
// cookie issued by the one-time browser handoff is accepted instead.
//
// The returned user is always active (not disabled) and currently
// permitted by the organization's login rules -- same as every other
// authentication path in this package.
func (a *Auth) ResolveInvokeCaller(r *http.Request, extraAudiences []string, functionID, host string) (*store.User, error) {
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
		return a.ResolveInvokeCookie(r, functionID, host)
	}
	return nil, ErrUnauthenticated
}

// ExtraInvokeAudiences returns the org's registered extra ID-token
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
