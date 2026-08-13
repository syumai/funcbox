package config

import (
	"fmt"
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
		"FUNCBOX_AUTH_MODE", "FUNCBOX_GOOGLE_CLIENT_ID", "FUNCBOX_GOOGLE_CLIENT_SECRET", "FUNCBOX_SESSION_SECRET",
		"FUNCBOX_CONTROL_URL", "FUNCBOX_FUNCTION_DOMAIN", "FUNCBOX_LANDING_URL", "FUNCBOX_ORIGIN_PROFILE")

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
	if cfg.OriginProfile != "same-site" {
		t.Errorf("OriginProfile = %q, want same-site", cfg.OriginProfile)
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

func TestFromEnv_Hosting(t *testing.T) {
	withEnv(t, map[string]string{
		"FUNCBOX_CONTROL_URL":     "https://dashboard.funcbox.example.com",
		"FUNCBOX_FUNCTION_DOMAIN": "run.funcbox.example.com.",
		"FUNCBOX_LANDING_URL":     "https://funcbox.example.com",
		"FUNCBOX_ORIGIN_PROFILE":  "same-site",
	})
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.ControlURL != "https://dashboard.funcbox.example.com" || cfg.BaseURL != cfg.ControlURL {
		t.Fatalf("ControlURL/BaseURL = %q/%q", cfg.ControlURL, cfg.BaseURL)
	}
	if cfg.FunctionDomain != "run.funcbox.example.com" {
		t.Fatalf("FunctionDomain = %q", cfg.FunctionDomain)
	}
}

func TestFromEnv_InvalidHosting(t *testing.T) {
	tests := []map[string]string{
		{"FUNCBOX_CONTROL_URL": "https://dashboard.example.com/path", "FUNCBOX_FUNCTION_DOMAIN": "run.example.com"},
		{"FUNCBOX_CONTROL_URL": "https://dashboard.example.com", "FUNCBOX_FUNCTION_DOMAIN": "https://run.example.com"},
		{"FUNCBOX_CONTROL_URL": "https://dashboard.example.com"},
		{"FUNCBOX_CONTROL_URL": "http://dashboard.example.com", "FUNCBOX_FUNCTION_DOMAIN": "run.example.com"},
		{"FUNCBOX_CONTROL_URL": "https://report.example.com", "FUNCBOX_FUNCTION_DOMAIN": "example.com"},
		{"FUNCBOX_CONTROL_URL": "https://dashboard.example.com", "FUNCBOX_FUNCTION_DOMAIN": "run.example.com", "FUNCBOX_ORIGIN_PROFILE": "invalid"},
		{"FUNCBOX_CONTROL_URL": "https://dashboard.example.com", "FUNCBOX_FUNCTION_DOMAIN": "run.example.com", "FUNCBOX_ORIGIN_PROFILE": "cross-site"},
		{"FUNCBOX_CONTROL_URL": "https://dashboard.example.com", "FUNCBOX_FUNCTION_DOMAIN": "functions.example.net", "FUNCBOX_ORIGIN_PROFILE": "same-site"},
	}
	for i, env := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			unsetEnv(t, "FUNCBOX_BASE_URL", "FUNCBOX_CONTROL_URL", "FUNCBOX_FUNCTION_DOMAIN", "FUNCBOX_LANDING_URL", "FUNCBOX_ORIGIN_PROFILE")
			withEnv(t, env)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("FromEnv(%v) succeeded, want error", env)
			}
		})
	}
}

func TestManagedFunctionURL(t *testing.T) {
	cfg := Config{ControlURL: "https://dashboard.funcbox.example.com", FunctionDomain: "run.funcbox.example.com", OriginProfile: "same-site"}
	got, err := cfg.ManagedFunctionURL("report", "/items?q=1")
	if err != nil {
		t.Fatalf("ManagedFunctionURL: %v", err)
	}
	if got != "https://report.run.funcbox.example.com/items?q=1" {
		t.Fatalf("ManagedFunctionURL = %q", got)
	}
	if _, err := cfg.ManagedFunctionURL("bad.name", "/"); err == nil {
		t.Fatal("ManagedFunctionURL accepted a multi-label function name")
	}
}
