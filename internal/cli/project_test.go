package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/syumai/funcbox/internal/manifest"
)

func TestResolveOwnerPrecedence(t *testing.T) {
	tests := []struct {
		name      string
		flagOwner string
		manifest  *manifest.Manifest
		want      string
		wantErr   bool
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
			name:     "neither set is an error",
			manifest: &manifest.Manifest{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveOwner(tt.flagOwner, tt.manifest)
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
