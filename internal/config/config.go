package config

import (
	"fmt"
	"net/url"
	"os"
	"time"
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
	// DB is the database connection string, e.g. "sqlite:./funcbox.db"
	// (FUNCBOX_DB). Empty if unset; interpreting the scheme is the
	// store package's job.
	DB string
	// Blob is the blob storage connection string, e.g. "fs:./data/blobs"
	// (FUNCBOX_BLOB). Empty if unset; interpreting the scheme is the
	// blob package's job.
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

	if v, ok := os.LookupEnv("FUNCBOX_BASE_URL"); ok && v != "" {
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("config: invalid FUNCBOX_BASE_URL %q: must be an absolute URL", v)
		}
		cfg.BaseURL = v
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

	return cfg, nil
}
