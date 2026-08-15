package auth

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/store"
)

// Mode selects which identity provider Auth uses: Google or the dev stub
// use OIDC (provider discovery -> ID token verification, see provider.go);
// ModeGitHub instead speaks plain OAuth2 + REST, since GitHub has no OIDC
// issuer (see github.go). Exactly one of these is active in a given
// process.
type Mode string

const (
	// ModeGoogle is the production default: Google is the OIDC issuer.
	ModeGoogle Mode = "google"
	// ModeGitHub selects GitHub as the OAuth2 identity provider
	// (FUNCBOX_AUTH_PROVIDER=github; see github.go).
	ModeGitHub Mode = "github"
	// ModeDev enables the built-in stub issuer under /dev/oidc/* (see
	// devidp.go). Auth.New refuses to build a dev-mode Auth unless the
	// listen address is also loopback -- see New's doc comment. Dev mode
	// is deliberately provider-independent: it ignores whichever of
	// ModeGoogle/ModeGitHub FUNCBOX_AUTH_PROVIDER would otherwise select.
	ModeDev Mode = "dev"
)

// §5.1: "Google は「デフォルトの issuer 設定」とする").
const googleIssuerURL = "https://accounts.google.com"

// GitHub has no OIDC discovery document, so its OAuth2 authorize/token
// endpoints and REST API base are hardcoded defaults here rather than
// resolved the way provider.go resolves Google's. They're stored on Config
// as unexported fields (githubAuthorizeURL/githubTokenURL/githubAPIBaseURL)
// so this package's own tests can override them to point at an
// httptest fake GitHub -- see github_test.go.
const (
	defaultGitHubAuthorizeURL = "https://github.com/login/oauth/authorize"
	defaultGitHubTokenURL     = "https://github.com/login/oauth/access_token"
	defaultGitHubAPIBaseURL   = "https://api.github.com"
)

// DefaultSessionDuration is the sliding session expiry applied when the
// organization hasn't overridden it via settings.Org.SessionDurationSeconds
// 日（組織設定で変更可）").
const DefaultSessionDuration = 7 * 24 * time.Hour

// Config is Auth's configuration, assembled by the caller (typically from
// internal/config's environment variables) before calling New.
type Config struct {
	// Mode selects the OIDC issuer configuration. Defaults to ModeGoogle
	// if empty.
	Mode Mode

	// BaseURL is the externally reachable base URL (FUNCBOX_BASE_URL),
	// used to build the OAuth redirect_uri and, in dev mode, the stub
	// issuer's own URL. Required.
	BaseURL string
	// ControlOrigin is the exact scheme+authority allowed on
	// session-authenticated management mutations. Defaults to BaseURL.
	ControlOrigin string
	// FunctionDomain is the managed function DNS suffix. It is used only
	// to derive and validate exact browser SSO callback hosts.
	FunctionDomain string

	// ListenAddr is the server's listen address (FUNCBOX_ADDR), checked
	// against loopback as part of dev mode's startup guard. Required when
	// Mode is ModeDev.
	ListenAddr string

	// ClientID / ClientSecret are the OIDC client credentials
	// (FUNCBOX_GOOGLE_CLIENT_ID / FUNCBOX_GOOGLE_CLIENT_SECRET). Required
	// in ModeGoogle; optional in ModeDev, where they default to a fixed
	// placeholder pair (the stub issuer doesn't police them). Unused in
	// ModeGitHub -- see GitHubClientID/GitHubClientSecret.
	ClientID     string
	ClientSecret string

	// GitHubClientID / GitHubClientSecret are the GitHub OAuth App client
	// credentials (FUNCBOX_GITHUB_CLIENT_ID / FUNCBOX_GITHUB_CLIENT_SECRET).
	// Required in ModeGitHub; unused otherwise.
	GitHubClientID     string
	GitHubClientSecret string

	// githubAuthorizeURL / githubTokenURL / githubAPIBaseURL override
	// GitHub's real endpoints, for this package's own tests to point at an
	// httptest fake. Left empty (the normal case), New defaults them to
	// the real github.com / api.github.com endpoints. Unexported: a real
	// deployment (internal/config, cmd/funcbox-server) has no legitimate
	// reason to point GitHub login at anything but GitHub itself.
	githubAuthorizeURL string
	githubTokenURL     string
	githubAPIBaseURL   string

	// SessionSecret (FUNCBOX_SESSION_SECRET) is the single operator secret
	// this package derives its subkeys from: the CSRF HMAC key here, and
	// (via the same derivation, used by internal/api) the env-var
	// encryption key. Required.
	SessionSecret string

	// OpenMode (FUNCBOX_OPEN_MODE=1) seeds the singleton organization's
	// open_mode setting to true at bootstrap ONLY -- see
	// seedBootstrapLoginRule, which both writes settings.Org.OpenMode and
	// chooses the default-allow seed login rule set instead of the normal
	// email_exact(admin)+default-deny pair. It has no effect after the
	// very first organization/user has been
	// created: from then on settings.Org.OpenMode (editable via
	// PATCH /api/v1/org) is authoritative, and this field is never
	// consulted again.
	OpenMode bool
}

const (
	devDefaultClientID     = "funcbox-dev-client"
	devDefaultClientSecret = "funcbox-dev-secret"

	csrfKeyInfo = "funcbox:csrf"
)

// Auth is funcbox's authentication service: the OIDC login flow, session
// management, and (in dev mode) the stub identity provider. Build one with
// New.
type Auth struct {
	cfg   Config
	store store.Store

	issuerURL string
	csrfKey   []byte
	invokeKey []byte
	accessKey []byte

	// controlHost is the normalized (lowercased, no port) hostname of
	// cfg.ControlOrigin, computed once here rather than re-parsed on every
	// request -- see SameOriginInvokeHost, the only consumer.
	controlHost string

	providerMu     sync.Mutex
	providerCached *oidc.Provider

	dev *devIdP // non-nil only in ModeDev
}

// New validates cfg, derives Auth's subkeys, and (in ModeDev) builds the
// in-process stub identity provider. It does NOT perform OIDC discovery --
// that happens lazily on first use (see provider.go) specifically so a
// dev-mode issuer served by this same not-yet-listening process can be
// discovered after the HTTP server actually starts.
//
// build a ModeDev Auth unless cfg.ListenAddr is also a loopback address.
// This is deliberately a runtime check, not a build tag / binary flavor
// split -- per the design doc, "ビルドフレーバー分岐はテスト漏れの温床
// になるため" (build-flavor branching invites untested paths).
func New(cfg Config, st store.Store) (*Auth, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeGoogle
	}
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("auth: BaseURL is required")
	}
	if cfg.SessionSecret == "" {
		return nil, fmt.Errorf("auth: SessionSecret is required")
	}
	if cfg.ControlOrigin == "" {
		cfg.ControlOrigin = strings.TrimSuffix(cfg.BaseURL, "/")
	}

	switch cfg.Mode {
	case ModeGoogle:
		if cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, fmt.Errorf("auth: ClientID and ClientSecret are required in mode %q", ModeGoogle)
		}
	case ModeGitHub:
		if cfg.GitHubClientID == "" || cfg.GitHubClientSecret == "" {
			return nil, fmt.Errorf("auth: GitHubClientID and GitHubClientSecret are required in mode %q", ModeGitHub)
		}
		if cfg.githubAuthorizeURL == "" {
			cfg.githubAuthorizeURL = defaultGitHubAuthorizeURL
		}
		if cfg.githubTokenURL == "" {
			cfg.githubTokenURL = defaultGitHubTokenURL
		}
		if cfg.githubAPIBaseURL == "" {
			cfg.githubAPIBaseURL = defaultGitHubAPIBaseURL
		}
	case ModeDev:
		if !isLoopbackAddr(cfg.ListenAddr) {
			return nil, fmt.Errorf("auth: FUNCBOX_AUTH_MODE=dev requires a loopback FUNCBOX_ADDR (got %q); refusing to start a dev identity provider on a non-loopback listener", cfg.ListenAddr)
		}
		if cfg.ClientID == "" {
			cfg.ClientID = devDefaultClientID
		}
		if cfg.ClientSecret == "" {
			cfg.ClientSecret = devDefaultClientSecret
		}
	default:
		return nil, fmt.Errorf("auth: unknown mode %q", cfg.Mode)
	}

	csrfKey, err := fcrypto.DeriveKey(cfg.SessionSecret, csrfKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("auth: derive CSRF key: %w", err)
	}
	invokeKey, err := fcrypto.DeriveKey(cfg.SessionSecret, "funcbox:invoke-cookie")
	if err != nil {
		return nil, fmt.Errorf("auth: derive invoke-cookie key: %w", err)
	}
	accessKey, err := fcrypto.DeriveKey(cfg.SessionSecret, accessTokenKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("auth: derive access-token key: %w", err)
	}

	controlHost := ""
	if u, err := url.Parse(cfg.ControlOrigin); err == nil {
		controlHost = strings.ToLower(u.Hostname())
	}

	a := &Auth{
		cfg:         cfg,
		store:       st,
		csrfKey:     csrfKey,
		invokeKey:   invokeKey,
		accessKey:   accessKey,
		controlHost: controlHost,
	}

	switch cfg.Mode {
	case ModeDev:
		a.issuerURL = strings.TrimSuffix(cfg.BaseURL, "/") + devOIDCPrefix
		a.dev = newDevIdP(a.issuerURL, st)
	case ModeGoogle:
		a.issuerURL = googleIssuerURL
	case ModeGitHub:
		// GitHub has no OIDC issuer to discover; provider.go's
		// discovery/verifier machinery is never used in this mode (see
		// github.go's own oauth2Config/REST calls instead).
	}

	return a, nil
}

// isLoopbackAddr reports whether addr (a "host:port" listen address, as
// consumed by http.Server.Addr) resolves to a loopback interface only. An
// empty host ("", or a bare ":8080") means "all interfaces" and is
// deliberately NOT loopback -- that's the footgun this guard exists to
// catch.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// secureCookies reports whether cookies this package sets should carry the
// Secure attribute. It's tied to the scheme of BaseURL rather than Mode
// directly, since a dev-mode deployment is still expected to run over
// plain HTTP on loopback (browsers refuse to send Secure cookies back over
// HTTP, which would otherwise break login).
func (a *Auth) secureCookies() bool {
	return !strings.HasPrefix(a.cfg.BaseURL, "http://")
}
