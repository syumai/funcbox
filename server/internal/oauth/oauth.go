package oauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/syumai/funcbox/server/internal/auth"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/store"
)

// consentKeyInfo is the HKDF domain-separation label deriving this
// package's own subkey from Config.SessionSecret (the same
// FUNCBOX_SESSION_SECRET internal/auth derives its csrf/invoke/access-token
// subkeys from), used to sign the consent page's hidden state token (see
// consent.go). A distinct label keeps this key cryptographically
// independent of every other subkey this secret already backs.
const consentKeyInfo = "funcbox:oauth-consent"

// Config is Handler's configuration.
type Config struct {
	// ControlOrigin is the exact scheme+authority this authorization
	// server identifies itself as: RFC 8414's "issuer" and the basis for
	// every endpoint URL this package advertises, and RFC 9728's
	// "resource" (ControlOrigin + "/mcp"). No trailing slash. Required.
	ControlOrigin string

	// SessionSecret (FUNCBOX_SESSION_SECRET) derives this package's own
	// HMAC signing key, via the same internal/crypto.DeriveKey mechanism
	// every other funcbox subkey uses -- see consentKeyInfo. Required.
	SessionSecret string
}

// Handler implements every HTTP endpoint this package's doc comment
// lists. Build one with New and mount Handler.Routes() -- this package
// does not mount itself onto any router.
type Handler struct {
	cfg   Config
	store store.Store
	auth  *auth.Auth

	consentKey []byte

	// registerLimiter guards POST /oauth/register (register.go) against
	// storage-exhaustion abuse from a single source -- see ratelimit.go.
	registerLimiter *ipRateLimiter
}

// New builds a Handler. a is used to authenticate the browser session at
// GET /oauth/authorize (Auth.AuthenticateSessionCookie), to build the
// unauthenticated-browser redirect into the existing login flow
// (auth.LoginURL), and to mint access tokens at POST /oauth/token
// (Auth.IssueAccessTokenForAudience, Auth.LoadAuthenticatableUser). st
// holds this package's own entities (oauth_clients/oauth_auth_codes/
// oauth_grants) alongside every other funcbox entity.
func New(cfg Config, st store.Store, a *auth.Auth) (*Handler, error) {
	if cfg.ControlOrigin == "" {
		return nil, fmt.Errorf("oauth: Config.ControlOrigin is required")
	}
	if cfg.SessionSecret == "" {
		return nil, fmt.Errorf("oauth: Config.SessionSecret is required")
	}
	cfg.ControlOrigin = strings.TrimSuffix(cfg.ControlOrigin, "/")

	consentKey, err := fcrypto.DeriveKey(cfg.SessionSecret, consentKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("oauth: derive consent key: %w", err)
	}

	return &Handler{
		cfg: cfg, store: st, auth: a, consentKey: consentKey,
		registerLimiter: newIPRateLimiter(registerRateBurst, registerRateRefillInterval),
	}, nil
}

// protectedResource is the single RFC 9728 resource identifier this
// authorization server issues tokens for -- the SAME value
// handleProtectedResourceMetadata advertises at
// /.well-known/oauth-protected-resource. authorize.go/token.go validate
// an incoming RFC 8707 "resource" parameter against exactly this string
// (see this package's doc comment on why there is only ever one).
func (h *Handler) protectedResource() string {
	return h.cfg.ControlOrigin + "/mcp"
}

// Routes returns the http.Handler serving every endpoint this package
// implements, at the exact paths the MCP Authorization spec (and RFC
// 8414/9728) require. Mount it at "/" (its patterns already carry their
// own full paths) alongside internal/auth's own Routes() -- a later step
// is responsible for actually doing so, and for gating these paths behind
// the organization's mcp_enabled setting.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.handleAuthorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.handleProtectedResourceMetadata)
	mux.HandleFunc("POST /oauth/register", h.handleRegister)
	mux.HandleFunc("GET /oauth/authorize", h.handleAuthorize)
	mux.HandleFunc("POST /oauth/authorize", h.handleAuthorizeDecision)
	mux.HandleFunc("POST /oauth/token", h.handleToken)
	return mux
}
