package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Default values applied when the corresponding environment variable
// is unset.
const (
	DefaultAddr          = ":8080"
	DefaultInvokeTimeout = 30 * time.Second
	// DefaultPoolMaxFunctions is the default LRU cap on the number of
	// distinct function versions kept warm at once (14.2 Pool LRU). See
	// Config.PoolMaxFunctions.
	DefaultPoolMaxFunctions = 10
)

// Config holds funcbox-server's process-wide configuration, loaded
// from environment variables by FromEnv.
type Config struct {
	// Addr is the listen address (FUNCBOX_ADDR). Defaults to ":8080".
	Addr string
	// BaseURL is the externally reachable base URL, used for things
	// like OAuth redirects (FUNCBOX_BASE_URL). Empty if unset.
	BaseURL string
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

	// PoolMaxFunctions caps the number of distinct function versions the
	// invoke-path runtime.Manager keeps warm at once (FUNCBOX_POOL_MAX_FUNCTIONS,
	// 14.2 Pool LRU). Over the cap, the least-recently-invoked version's pool
	// is evicted and closed gracefully. Defaults to 10; 0 means unlimited.
	// This is a process memory-capacity knob, not an org setting -- it only
	// applies to the invoke Manager, never to the dashboard's own pool.
	PoolMaxFunctions int

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
		Addr:             DefaultAddr,
		InvokeTimeout:    DefaultInvokeTimeout,
		PoolMaxFunctions: DefaultPoolMaxFunctions,
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

	if v, ok := os.LookupEnv("FUNCBOX_POOL_MAX_FUNCTIONS"); ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("config: invalid FUNCBOX_POOL_MAX_FUNCTIONS %q: %w", v, err)
		}
		if n < 0 {
			return nil, fmt.Errorf("config: FUNCBOX_POOL_MAX_FUNCTIONS %q must not be negative (0 means unlimited)", v)
		}
		cfg.PoolMaxFunctions = n
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
