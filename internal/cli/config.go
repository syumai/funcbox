package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// Config is the CLI's persisted configuration: the funcbox server to talk
// to, and the CLI login credential `funcbox login` saved
// "~/.config/funcbox/config.yaml"). Both fields can be overridden per
// invocation by the FUNCBOX_SERVER / FUNCBOX_CREDENTIAL environment
// variables (see ResolveConfig). Credential is the long-lived "fbxc_..."
// secret (§14.4 of tmp/14-auth-and-pool-improvements.md) minted by the
// loopback+PKCE browser login flow -- it is never sent directly as a
// management-API bearer credential; Client mints and caches short-lived
// access tokens from it on demand (see client.go).
type Config struct {
	Server     string `yaml:"server"`
	Credential string `yaml:"credential"`
}

// configFileMode is the permission the config file is written with. It
// contains a bearer credential, so it must never be group/world-readable.
const configFileMode = 0o600

// ConfigPath returns the path to the CLI's config file
// (~/.config/funcbox/config.yaml), honoring $XDG_CONFIG_HOME when set.
func ConfigPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cli: resolve home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "funcbox", "config.yaml"), nil
}

// LoadConfig reads the CLI config file. A missing file is not an error: it
// returns a zero-value Config (both fields empty), since a caller may be
// relying entirely on FUNCBOX_SERVER / FUNCBOX_API_TOKEN (see
// ResolveConfig).
func LoadConfig() (Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return Config{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("cli: read config file %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("cli: parse config file %s: %w", path, err)
	}
	return cfg, nil
}

// SaveConfig writes cfg to the CLI config file, creating its parent
// directory if needed, with mode 0600 (it holds a bearer credential).
func SaveConfig(cfg Config) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cli: create config directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("cli: encode config: %w", err)
	}
	if err := os.WriteFile(path, data, configFileMode); err != nil {
		return fmt.Errorf("cli: write config file %s: %w", path, err)
	}
	// os.WriteFile applies configFileMode only when creating a new file; an
	// existing file (e.g. a stale one left at 0644 by a previous version)
	// keeps its old mode unless we fix it up explicitly.
	if err := os.Chmod(path, configFileMode); err != nil {
		return fmt.Errorf("cli: set config file permissions: %w", err)
	}
	return nil
}

// ResolveConfig loads the on-disk config and applies the
// FUNCBOX_SERVER / FUNCBOX_CREDENTIAL environment variable overrides
// (§14.4's CI/headless decision: "資格情報を環境変数 FUNCBOX_CREDENTIAL=
// fbxc_... で持ち込める（設定ファイルより優先）" -- for CI, run
// `funcbox login` once interactively and register the resulting
// credential as a CI secret). Either field may end up empty if neither the
// file nor the environment supplies it; callers that require one report
// their own actionable error (e.g. "run `funcbox login`").
func ResolveConfig() (Config, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return Config{}, err
	}
	if v := os.Getenv("FUNCBOX_SERVER"); v != "" {
		cfg.Server = v
	}
	if v := os.Getenv("FUNCBOX_CREDENTIAL"); v != "" {
		cfg.Credential = v
	}
	return cfg, nil
}

// RequireConfig is ResolveConfig plus the validation every subcommand but
// login needs: both a server URL and a CLI login credential must be
// present.
func RequireConfig() (Config, error) {
	cfg, err := ResolveConfig()
	if err != nil {
		return Config{}, err
	}
	if cfg.Server == "" || cfg.Credential == "" {
		return Config{}, fmt.Errorf("not logged in: run `funcbox login --server <url>`, or set FUNCBOX_SERVER and FUNCBOX_CREDENTIAL")
	}
	return cfg, nil
}
