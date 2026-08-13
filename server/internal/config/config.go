package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Default values applied when the corresponding environment variable
// is unset.
const (
	DefaultAddr          = ":8080"
	DefaultInvokeTimeout = 30 * time.Second
)

// Config holds funcbox-server's process-wide configuration, loaded
// from environment variables by FromEnv.
type Config struct {
	// Addr is the listen address (FUNCBOX_ADDR). Defaults to ":8080".
	Addr string
	// BaseURL is the externally reachable base URL, used for things
	// like OAuth redirects (FUNCBOX_BASE_URL). Empty if unset.
	BaseURL string
	// ControlURL is the externally reachable control-plane origin
	// (FUNCBOX_CONTROL_URL). It hosts dashboard, API and auth routes.
	// FUNCBOX_BASE_URL remains a deprecated alias during migration.
	ControlURL string
	// FunctionDomain is the DNS suffix used for managed function hosts
	// (FUNCBOX_FUNCTION_DOMAIN). A function named "report" is served at
	// report.<FunctionDomain>.
	FunctionDomain string
	// LandingURL optionally identifies a separate landing origin
	// (FUNCBOX_LANDING_URL). Safe requests are redirected to ControlURL.
	LandingURL string
	// OriginProfile documents the intended deployment boundary
	// (FUNCBOX_ORIGIN_PROFILE): same-site, cross-site, or development.
	OriginProfile string
	// DB is the database connection string (FUNCBOX_DB). Empty if unset
	// (cmd/funcbox-server defaults to "sqlite:funcbox.db"); interpreting
	// the scheme is cmd/funcbox-server's job (see its openStore). One of:
	//
	//   - "sqlite:PATH"                                  store/sqlite
	//   - "sqlite::memory:"                               store/sqlite, in-memory
	//   - "turso:URL?authToken=TOKEN"                     store/turso (libsql)
	//   - "postgres://user:pass@host/db?sslmode=..."      store/neon (any PostgreSQL)
	//   - "dynamodb:table=NAME[;endpoint=URL][;region=R]" store/dynamodb
	//
	DB string
	// Blob is the blob storage connection string (FUNCBOX_BLOB). Empty if
	// unset (cmd/funcbox-server defaults to "fs:./data/blobs");
	// interpreting the scheme is cmd/funcbox-server's job (see its
	// openBlob). One of:
	//
	//   - "fs:PATH"                                           blob/fs
	//   - "s3:bucket=B[;endpoint=URL][;region=R][;pathstyle=1]" blob/s3 (AWS S3, R2, MinIO, ...)
	//   - "gcs:bucket=B"                                       blob/gcs
	//
	Blob string
	// InvokeTimeout is the default function execution timeout
	// (FUNCBOX_INVOKE_TIMEOUT). Defaults to 30s.
	InvokeTimeout time.Duration

	// AuthMode selects the OIDC issuer configuration (FUNCBOX_AUTH_MODE):
	// "google" (default) or "dev" (see internal/auth's package doc for the
	// dev-mode stub identity provider and its startup guard).
	AuthMode string
	// GoogleClientID / GoogleClientSecret are the OIDC client credentials
	// (FUNCBOX_GOOGLE_CLIENT_ID / FUNCBOX_GOOGLE_CLIENT_SECRET). Required
	// unless AuthMode is "dev".
	GoogleClientID     string
	GoogleClientSecret string
	// SessionSecret (FUNCBOX_SESSION_SECRET) is the operator secret every
	// derived subkey (CSRF HMAC, env-var AES-GCM encryption) comes from
	// via HKDF; see internal/crypto's package doc for its rotation
	// implications. Always required.
	SessionSecret string

	// DashboardDistDir (FUNCBOX_DASHBOARD_DIST_DIR), if set, points
	// internal/dashboard at a dist/ directory on disk instead of the
	// binary's embedded build -- development only: run `pnpm -C dashboard
	// watch` and point this at internal/dashboard/dist so edits are picked
	// Empty (the default) uses the embedded build, as production does.
	DashboardDistDir string
}

// FromEnv loads a Config from the process environment. It returns an
// error if a set environment variable has an invalid value (e.g. a
// malformed duration or URL); unset variables fall back to their
// documented defaults.
func FromEnv() (*Config, error) {
	cfg := &Config{
		Addr:          DefaultAddr,
		InvokeTimeout: DefaultInvokeTimeout,
	}

	if v, ok := os.LookupEnv("FUNCBOX_ADDR"); ok {
		if v == "" {
			return nil, fmt.Errorf("config: FUNCBOX_ADDR must not be empty")
		}
		cfg.Addr = v
	}

	baseURL := os.Getenv("FUNCBOX_BASE_URL")
	controlURL := os.Getenv("FUNCBOX_CONTROL_URL")
	if controlURL != "" && baseURL != "" && baseURL != controlURL {
		return nil, fmt.Errorf("config: FUNCBOX_BASE_URL and FUNCBOX_CONTROL_URL must match when both are set")
	}
	if controlURL != "" {
		normalized, err := parseOrigin("FUNCBOX_CONTROL_URL", controlURL, true)
		if err != nil {
			return nil, err
		}
		cfg.ControlURL = normalized
		cfg.BaseURL = normalized
	} else if baseURL != "" {
		normalized, err := parseOrigin("FUNCBOX_BASE_URL", baseURL, true)
		if err != nil {
			return nil, err
		}
		cfg.BaseURL = normalized
	}

	if v := os.Getenv("FUNCBOX_FUNCTION_DOMAIN"); v != "" {
		domain, err := parseDNSName("FUNCBOX_FUNCTION_DOMAIN", v)
		if err != nil {
			return nil, err
		}
		cfg.FunctionDomain = domain
	}
	if v := os.Getenv("FUNCBOX_LANDING_URL"); v != "" {
		normalized, err := parseOrigin("FUNCBOX_LANDING_URL", v, true)
		if err != nil {
			return nil, err
		}
		cfg.LandingURL = normalized
	}
	cfg.OriginProfile = os.Getenv("FUNCBOX_ORIGIN_PROFILE")
	if cfg.OriginProfile == "" {
		cfg.OriginProfile = "same-site"
	}
	switch cfg.OriginProfile {
	case "same-site", "cross-site", "development":
	default:
		return nil, fmt.Errorf("config: invalid FUNCBOX_ORIGIN_PROFILE %q: must be \"same-site\", \"cross-site\", or \"development\"", cfg.OriginProfile)
	}
	if err := cfg.validateHosting(); err != nil {
		return nil, err
	}

	cfg.DB = os.Getenv("FUNCBOX_DB")
	cfg.Blob = os.Getenv("FUNCBOX_BLOB")

	if v, ok := os.LookupEnv("FUNCBOX_INVOKE_TIMEOUT"); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: invalid FUNCBOX_INVOKE_TIMEOUT %q: %w", v, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("config: FUNCBOX_INVOKE_TIMEOUT %q must be positive", v)
		}
		cfg.InvokeTimeout = d
	}

	cfg.AuthMode = os.Getenv("FUNCBOX_AUTH_MODE")
	if cfg.AuthMode != "" && cfg.AuthMode != "google" && cfg.AuthMode != "dev" {
		return nil, fmt.Errorf("config: invalid FUNCBOX_AUTH_MODE %q: must be \"google\" or \"dev\"", cfg.AuthMode)
	}
	cfg.GoogleClientID = os.Getenv("FUNCBOX_GOOGLE_CLIENT_ID")
	cfg.GoogleClientSecret = os.Getenv("FUNCBOX_GOOGLE_CLIENT_SECRET")
	cfg.SessionSecret = os.Getenv("FUNCBOX_SESSION_SECRET")
	cfg.DashboardDistDir = os.Getenv("FUNCBOX_DASHBOARD_DIST_DIR")

	return cfg, nil
}

func parseOrigin(name, raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("config: invalid %s %q: must contain only scheme and authority", name, raw)
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return "", fmt.Errorf("config: invalid %s %q: scheme must be https", name, raw)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("config: invalid %s %q: hostname is required", name, raw)
	}
	u.Host = strings.ToLower(u.Host)
	return strings.TrimSuffix(u.String(), "/"), nil
}

func parseDNSName(name, raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(raw, "."))
	if domain == "" || strings.ContainsAny(raw, "/:@[] \\\t\r\n") || net.ParseIP(domain) != nil || len(domain) > 253 {
		return "", fmt.Errorf("config: invalid %s %q: must be a DNS name without scheme, port, or path", name, raw)
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("config: invalid %s %q: invalid DNS label", name, raw)
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("config: invalid %s %q: invalid DNS label", name, raw)
			}
		}
	}
	return domain, nil
}

func (cfg *Config) validateHosting() error {
	if cfg.ControlURL == "" && cfg.FunctionDomain == "" && cfg.LandingURL == "" {
		return nil
	}
	if cfg.ControlURL == "" || cfg.FunctionDomain == "" {
		return fmt.Errorf("config: FUNCBOX_CONTROL_URL and FUNCBOX_FUNCTION_DOMAIN must be set together")
	}
	control, _ := url.Parse(cfg.ControlURL)
	if strings.EqualFold(control.Hostname(), cfg.FunctionDomain) || strings.HasSuffix(strings.ToLower(control.Hostname()), "."+cfg.FunctionDomain) && strings.Count(control.Hostname(), ".") == strings.Count(cfg.FunctionDomain, ".")+1 {
		label := strings.TrimSuffix(strings.ToLower(control.Hostname()), "."+cfg.FunctionDomain)
		if label != "dashboard" {
			return fmt.Errorf("config: control host %q collides with the managed function host pattern", control.Hostname())
		}
	}
	if cfg.LandingURL != "" {
		landing, _ := url.Parse(cfg.LandingURL)
		if strings.EqualFold(landing.Host, control.Host) {
			return fmt.Errorf("config: FUNCBOX_LANDING_URL must not equal FUNCBOX_CONTROL_URL")
		}
	}
	if cfg.OriginProfile != "development" && (control.Scheme != "https") {
		return fmt.Errorf("config: production origin profiles require https control URL")
	}
	if cfg.OriginProfile != "development" {
		controlSite, controlErr := publicsuffix.EffectiveTLDPlusOne(control.Hostname())
		functionSite, functionErr := publicsuffix.EffectiveTLDPlusOne(cfg.FunctionDomain)
		if controlErr != nil || functionErr != nil {
			return fmt.Errorf("config: control and function domains must have registrable DNS names outside development")
		}
		sameSite := strings.EqualFold(controlSite, functionSite)
		if cfg.OriginProfile == "same-site" && !sameSite {
			return fmt.Errorf("config: FUNCBOX_ORIGIN_PROFILE=same-site does not match the configured domains")
		}
		if cfg.OriginProfile == "cross-site" && sameSite {
			return fmt.Errorf("config: FUNCBOX_ORIGIN_PROFILE=cross-site requires different registrable domains")
		}
	}
	return nil
}

// ManagedFunctionURL returns the canonical URL for a managed function.
// It never derives authority from an incoming request.
func (cfg *Config) ManagedFunctionURL(name, requestPath string) (string, error) {
	if cfg.FunctionDomain == "" {
		return "", fmt.Errorf("config: FUNCBOX_FUNCTION_DOMAIN is not configured")
	}
	if _, err := parseDNSName("function name", name); err != nil || strings.Contains(name, ".") {
		return "", fmt.Errorf("config: invalid function name %q", name)
	}
	scheme := "https"
	if cfg.OriginProfile == "development" {
		if control, err := url.Parse(cfg.ControlURL); err == nil && control.Scheme == "http" {
			scheme = "http"
		}
	}
	if requestPath == "" {
		requestPath = "/"
	} else if !strings.HasPrefix(requestPath, "/") {
		requestPath = "/" + requestPath
	}
	return scheme + "://" + strings.ToLower(name) + "." + cfg.FunctionDomain + requestPath, nil
}
