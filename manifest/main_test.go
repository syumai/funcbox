package manifest

import (
	"errors"
	"testing"
)

func TestResolveMain(t *testing.T) {
	tests := []struct {
		name    string
		main    string
		files   map[string][]byte
		want    string
		wantErr error
	}{
		{
			name:  "explicit main present",
			main:  "src/index.js",
			files: map[string][]byte{"src/index.js": []byte("x")},
			want:  "src/index.js",
		},
		{
			name:    "explicit main missing",
			main:    "src/index.js",
			files:   map[string][]byte{"other.js": []byte("x")},
			wantErr: ErrMainNotFound,
		},
		{
			name:  "default resolves to index.js",
			main:  "",
			files: map[string][]byte{"index.js": []byte("x"), "index.mjs": []byte("y")},
			want:  "index.js",
		},
		{
			name:  "default falls back to index.mjs",
			main:  "",
			files: map[string][]byte{"index.mjs": []byte("y")},
			want:  "index.mjs",
		},
		{
			name:    "default with no candidates present",
			main:    "",
			files:   map[string][]byte{"README.md": []byte("z")},
			wantErr: ErrNoEntryPoint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveMain(tt.main, tt.files)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ResolveMain() error = %v, want error wrapping %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveMain() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ResolveMain() = %q, want %q", got, tt.want)
			}
		})
	}
}
