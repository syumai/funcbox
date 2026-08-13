package config

import (
	"os"
	"testing"
	"time"
)

// withEnv sets environment variables for the duration of the test and
// restores the previous environment afterward.
func withEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// unsetEnv removes the given environment variables for the duration
// of the test and restores their previous state (set or unset)
// afterward. This is needed because testing.T has no built-in
// "unset" complement to Setenv.
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		old, existed := os.LookupEnv(k)
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("os.Unsetenv(%q): %v", k, err)
		}
		t.Cleanup(func() {
			if existed {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

func TestFromEnv_Defaults(t *testing.T) {
	// Ensure a clean slate: explicitly unset every recognized
	// variable so this test is independent of the ambient
	// environment.
	unsetEnv(t, "FUNCBOX_ADDR", "FUNCBOX_BASE_URL", "FUNCBOX_DB", "FUNCBOX_BLOB", "FUNCBOX_INVOKE_TIMEOUT",
		"FUNCBOX_AUTH_MODE", "FUNCBOX_GOOGLE_CLIENT_ID", "FUNCBOX_GOOGLE_CLIENT_SECRET", "FUNCBOX_SESSION_SECRET")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv() unexpected error: %v", err)
	}
	if cfg.Addr != DefaultAddr {
		t.Errorf("Addr = %q, want %q", cfg.Addr, DefaultAddr)
	}
	if cfg.BaseURL != "" {
		t.Errorf("BaseURL = %q, want empty", cfg.BaseURL)
	}
	if cfg.DB != "" {
		t.Errorf("DB = %q, want empty", cfg.DB)
	}
	if cfg.Blob != "" {
		t.Errorf("Blob = %q, want empty", cfg.Blob)
	}
	if cfg.InvokeTimeout != DefaultInvokeTimeout {
		t.Errorf("InvokeTimeout = %v, want %v", cfg.InvokeTimeout, DefaultInvokeTimeout)
	}
	if cfg.AuthMode != "" {
		t.Errorf("AuthMode = %q, want empty (caller defaults it to \"google\")", cfg.AuthMode)
	}
}

func TestFromEnv_AuthVars(t *testing.T) {
	withEnv(t, map[string]string{
		"FUNCBOX_AUTH_MODE":            "dev",
		"FUNCBOX_GOOGLE_CLIENT_ID":     "client-id",
		"FUNCBOX_GOOGLE_CLIENT_SECRET": "client-secret",
		"FUNCBOX_SESSION_SECRET":       "s3cr3t",
	})
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv() unexpected error: %v", err)
	}
	if cfg.AuthMode != "dev" {
		t.Errorf("AuthMode = %q, want %q", cfg.AuthMode, "dev")
	}
	if cfg.GoogleClientID != "client-id" {
		t.Errorf("GoogleClientID = %q", cfg.GoogleClientID)
	}
	if cfg.GoogleClientSecret != "client-secret" {
		t.Errorf("GoogleClientSecret = %q", cfg.GoogleClientSecret)
	}
	if cfg.SessionSecret != "s3cr3t" {
		t.Errorf("SessionSecret = %q", cfg.SessionSecret)
	}
}

func TestFromEnv_InvalidAuthMode(t *testing.T) {
	withEnv(t, map[string]string{"FUNCBOX_AUTH_MODE": "bogus"})
	if _, err := FromEnv(); err == nil {
		t.Fatal("FromEnv() with an invalid FUNCBOX_AUTH_MODE = nil error, want error")
	}
}

func TestFromEnv_Overrides(t *testing.T) {
	withEnv(t, map[string]string{
		"FUNCBOX_ADDR":           "127.0.0.1:9090",
		"FUNCBOX_BASE_URL":       "https://fb.example.com",
		"FUNCBOX_DB":             "sqlite:./funcbox.db",
		"FUNCBOX_BLOB":           "fs:./data/blobs",
		"FUNCBOX_INVOKE_TIMEOUT": "45s",
	})

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv() unexpected error: %v", err)
	}
	if cfg.Addr != "127.0.0.1:9090" {
		t.Errorf("Addr = %q", cfg.Addr)
	}
	if cfg.BaseURL != "https://fb.example.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.DB != "sqlite:./funcbox.db" {
		t.Errorf("DB = %q", cfg.DB)
	}
	if cfg.Blob != "fs:./data/blobs" {
		t.Errorf("Blob = %q", cfg.Blob)
	}
	if cfg.InvokeTimeout != 45*time.Second {
		t.Errorf("InvokeTimeout = %v, want 45s", cfg.InvokeTimeout)
	}
}

func TestFromEnv_InvalidValues(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "empty addr", env: map[string]string{"FUNCBOX_ADDR": ""}},
		{name: "invalid base url: no scheme", env: map[string]string{"FUNCBOX_BASE_URL": "fb.example.com"}},
		{name: "invalid base url: garbage", env: map[string]string{"FUNCBOX_BASE_URL": "://nope"}},
		{name: "invalid invoke timeout: not a duration", env: map[string]string{"FUNCBOX_INVOKE_TIMEOUT": "soon"}},
		{name: "invalid invoke timeout: zero", env: map[string]string{"FUNCBOX_INVOKE_TIMEOUT": "0s"}},
		{name: "invalid invoke timeout: negative", env: map[string]string{"FUNCBOX_INVOKE_TIMEOUT": "-1s"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withEnv(t, tt.env)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("FromEnv() with %v = nil error, want error", tt.env)
			}
		})
	}
}

func TestFromEnv_EmptyBaseURLIsIgnored(t *testing.T) {
	withEnv(t, map[string]string{"FUNCBOX_BASE_URL": ""})
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv() unexpected error: %v", err)
	}
	if cfg.BaseURL != "" {
		t.Errorf("BaseURL = %q, want empty", cfg.BaseURL)
	}
}
