package auth

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/store"
)

// Mode selects which OIDC issuer configuration Auth uses.
type Mode string

const (
	// ModeGoogle is the production default: Google is the OIDC issuer.
	ModeGoogle Mode = "google"
	// ModeDev enables the built-in stub issuer under /dev/oidc/* (see
	// devidp.go). Auth.New refuses to build a dev-mode Auth unless the
	// listen address is also loopback -- see New's doc comment.
	ModeDev Mode = "dev"
)

// googleIssuerURL is Google's OIDC discovery issuer (tmp/05-auth-and-permissions.md
// §5.1: "Google は「デフォルトの issuer 設定」とする").
const googleIssuerURL = "https://accounts.google.com"

// DefaultSessionDuration is the sliding session expiry applied when the
// organization hasn't overridden it via settings.Org.SessionDurationSeconds
// (tmp/05-auth-and-permissions.md §5.1: "有効期限はスライディングで 7
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

	// ListenAddr is the server's listen address (FUNCBOX_ADDR), checked
	// against loopback as part of dev mode's startup guard. Required when
	// Mode is ModeDev.
	ListenAddr string

	// ClientID / ClientSecret are the OIDC client credentials
	// (FUNCBOX_GOOGLE_CLIENT_ID / FUNCBOX_GOOGLE_CLIENT_SECRET). Required
	// in ModeGoogle; optional in ModeDev, where they default to a fixed
	// placeholder pair (the stub issuer doesn't police them).
	ClientID     string
	ClientSecret string

	// SessionSecret (FUNCBOX_SESSION_SECRET) is the single operator secret
	// this package derives its subkeys from: the CSRF HMAC key here, and
	// (via the same derivation, used by internal/api) the env-var
	// encryption key. Required.
	SessionSecret string
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
// Dev mode hard guard (tmp/05-auth-and-permissions.md §5.1): New refuses to
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

	switch cfg.Mode {
	case ModeGoogle:
		if cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, fmt.Errorf("auth: ClientID and ClientSecret are required in mode %q", ModeGoogle)
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

	a := &Auth{
		cfg:     cfg,
		store:   st,
		csrfKey: csrfKey,
	}

	if cfg.Mode == ModeDev {
		a.issuerURL = strings.TrimSuffix(cfg.BaseURL, "/") + devOIDCPrefix
		a.dev = newDevIdP(a.issuerURL)
	} else {
		a.issuerURL = googleIssuerURL
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
