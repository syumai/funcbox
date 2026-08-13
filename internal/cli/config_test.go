package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// withXDGConfigHome points XDG_CONFIG_HOME at a fresh temp directory for
// the duration of the test, so ConfigPath/LoadConfig/SaveConfig never touch
// the real ~/.config/funcbox.
func withXDGConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func TestSaveAndLoadConfig(t *testing.T) {
	withXDGConfigHome(t)

	want := Config{Server: "https://fb.example.com", Credential: "fbxc_abc123"}
	if err := SaveConfig(want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got != want {
		t.Errorf("LoadConfig() = %+v, want %+v", got, want)
	}

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config file mode = %o, want 0600", perm)
	}
}

func TestLoadConfigMissingFileIsNotError(t *testing.T) {
	withXDGConfigHome(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig on missing file: %v", err)
	}
	if cfg != (Config{}) {
		t.Errorf("LoadConfig() on missing file = %+v, want zero value", cfg)
	}
}

func TestResolveConfigEnvOverride(t *testing.T) {
	withXDGConfigHome(t)

	if err := SaveConfig(Config{Server: "https://file.example.com", Credential: "fbxc_file"}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	t.Run("no env vars set, file wins", func(t *testing.T) {
		cfg, err := ResolveConfig()
		if err != nil {
			t.Fatalf("ResolveConfig: %v", err)
		}
		want := Config{Server: "https://file.example.com", Credential: "fbxc_file"}
		if cfg != want {
			t.Errorf("ResolveConfig() = %+v, want %+v", cfg, want)
		}
	})

	t.Run("FUNCBOX_SERVER overrides file", func(t *testing.T) {
		t.Setenv("FUNCBOX_SERVER", "https://env.example.com")
		cfg, err := ResolveConfig()
		if err != nil {
			t.Fatalf("ResolveConfig: %v", err)
		}
		if cfg.Server != "https://env.example.com" {
			t.Errorf("Server = %q, want env override", cfg.Server)
		}
		if cfg.Credential != "fbxc_file" {
			t.Errorf("Credential = %q, want file value preserved", cfg.Credential)
		}
	})

	t.Run("FUNCBOX_CREDENTIAL overrides file", func(t *testing.T) {
		t.Setenv("FUNCBOX_CREDENTIAL", "fbxc_env")
		cfg, err := ResolveConfig()
		if err != nil {
			t.Fatalf("ResolveConfig: %v", err)
		}
		if cfg.Credential != "fbxc_env" {
			t.Errorf("Credential = %q, want env override", cfg.Credential)
		}
	})
}

func TestRequireConfigMissing(t *testing.T) {
	withXDGConfigHome(t)

	if _, err := RequireConfig(); err == nil {
		t.Error("RequireConfig should fail when no config file and no env vars are set")
	}
}

func TestConfigPathUsesXDGConfigHome(t *testing.T) {
	dir := withXDGConfigHome(t)

	path, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	want := filepath.Join(dir, "funcbox", "config.yaml")
	if path != want {
		t.Errorf("ConfigPath() = %q, want %q", path, want)
	}
}
