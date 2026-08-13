package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// provider lazily performs OIDC discovery against a.issuerURL and caches
// the result. It is intentionally lazy (rather than resolved eagerly in
// New) so that, in dev mode, the stub issuer this same process serves
// under /dev/oidc/* (see devidp.go) can be discovered on first login
// attempt -- after the HTTP server has actually started listening --
// instead of racing process startup. Sharing this one lazy path for both
// dev and production is what keeps the verification code identical
// と dev で完全に共通").
func (a *Auth) provider(ctx context.Context) (*oidc.Provider, error) {
	a.providerMu.Lock()
	defer a.providerMu.Unlock()
	if a.providerCached != nil {
		return a.providerCached, nil
	}
	p, err := oidc.NewProvider(ctx, a.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: discover OIDC issuer %q: %w", a.issuerURL, err)
	}
	a.providerCached = p
	return p, nil
}

// verifier returns the ID token verifier configured for a's own OIDC
// client ID -- used for the dashboard login flow, where exactly one
// audience (funcbox itself) is ever valid.
func (a *Auth) verifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	p, err := a.provider(ctx)
	if err != nil {
		return nil, err
	}
	return p.Verifier(&oidc.Config{ClientID: a.cfg.ClientID}), nil
}

// verifierAnyAudience returns a verifier that performs every check
// Verifier's does (signature, issuer, expiry) EXCEPT the audience check,
// which the caller must apply itself against whatever multi-value
// audience list is valid in its context. This is the function-invoke path's
// client_id を要求（組織設定で追加の許容 audience を登録可能）"): the
// same provider/verifier construction as the login flow, just without
// go-oidc's single-ClientID audience check baked in -- see idtoken.go's
// VerifyIDToken for the manual multi-audience check this enables.
func (a *Auth) verifierAnyAudience(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	p, err := a.provider(ctx)
	if err != nil {
		return nil, err
	}
	return p.Verifier(&oidc.Config{SkipClientIDCheck: true}), nil
}

// oauth2Config builds the golang.org/x/oauth2 client config for the login
// flow, using the discovered provider's authorization/token endpoints.
func (a *Auth) oauth2Config(ctx context.Context) (*oauth2.Config, error) {
	p, err := a.provider(ctx)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     a.cfg.ClientID,
		ClientSecret: a.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  strings.TrimSuffix(a.cfg.BaseURL, "/") + authCallbackPath,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
	}, nil
}
