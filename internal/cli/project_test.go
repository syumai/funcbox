package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/syumai/funcbox/manifest"
)

func TestResolveOwnerPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		flagOwner  string
		manifest   *manifest.Manifest
		meFallback func() (string, error)
		want       string
		wantErr    bool
	}{
		{
			name:      "flag wins over manifest",
			flagOwner: "flag-owner",
			manifest:  &manifest.Manifest{Owner: "manifest-owner"},
			want:      "flag-owner",
		},
		{
			name:     "manifest owner used when no flag",
			manifest: &manifest.Manifest{Owner: "manifest-owner"},
			want:     "manifest-owner",
		},
		{
			name:     "neither set and no fallback is an error",
			manifest: &manifest.Manifest{},
			wantErr:  true,
		},
		{
			name:       "flag wins over the /me fallback too",
			flagOwner:  "flag-owner",
			manifest:   &manifest.Manifest{},
			meFallback: func() (string, error) { return "me-owner", nil },
			want:       "flag-owner",
		},
		{
			name:       "manifest wins over the /me fallback too",
			manifest:   &manifest.Manifest{Owner: "manifest-owner"},
			meFallback: func() (string, error) { return "me-owner", nil },
			want:       "manifest-owner",
		},
		{
			name:       "falls back to /me when neither flag nor manifest are set",
			manifest:   &manifest.Manifest{},
			meFallback: func() (string, error) { return "me-owner", nil },
			want:       "me-owner",
		},
		{
			name:       "fallback error is surfaced",
			manifest:   &manifest.Manifest{},
			meFallback: func() (string, error) { return "", errors.New("network down") },
			wantErr:    true,
		},
		{
			name:       "fallback returning an empty User ID is an error",
			manifest:   &manifest.Manifest{},
			meFallback: func() (string, error) { return "", nil },
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveOwner(tt.flagOwner, tt.manifest, tt.meFallback)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveOwner: %v", err)
			}
			if got != tt.want {
				t.Errorf("ResolveOwner() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadProjectManifestMissingIsEmpty(t *testing.T) {
	dir := t.TempDir()
	m, err := LoadProjectManifest(dir)
	if err != nil {
		t.Fatalf("LoadProjectManifest: %v", err)
	}
	if m.Source != "" {
		t.Errorf("Source = %q, want empty for a project with no manifest file", m.Source)
	}
}

func TestLoadProjectManifestParsesFile(t *testing.T) {
	dir := t.TempDir()
	data := []byte("name: hello\nowner: acme\n")
	if err := os.WriteFile(filepath.Join(dir, "funcbox.yaml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadProjectManifest(dir)
	if err != nil {
		t.Fatalf("LoadProjectManifest: %v", err)
	}
	if m.Name != "hello" || m.Owner != "acme" {
		t.Errorf("got Name=%q Owner=%q, want Name=hello Owner=acme", m.Name, m.Owner)
	}
}
