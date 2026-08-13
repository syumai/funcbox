package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/syumai/funcbox/internal/bundle"
)

// writeTree creates each key of files as a file (with the given contents)
// under dir, creating parent directories as needed.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCollectFilesImplicitExcludes(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"index.js":                 "export default {};",
		".git/HEAD":                "ref: refs/heads/main",
		".env":                     "SECRET=1",
		".env.local":               "SECRET=2",
		".funcboxignore":           "*.tmp\n",
		"node_modules/left-pad.js": "module.exports = {};",
		"scratch.tmp":              "junk",
	})

	matcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreMatcher: %v", err)
	}

	t.Run("node_modules excluded by default", func(t *testing.T) {
		files, err := CollectFiles(dir, false, matcher)
		if err != nil {
			t.Fatalf("CollectFiles: %v", err)
		}
		assertFileSet(t, files, []string{"index.js"})
	})

	t.Run("node_modules included with compat.nodejs", func(t *testing.T) {
		files, err := CollectFiles(dir, true, matcher)
		if err != nil {
			t.Fatalf("CollectFiles: %v", err)
		}
		assertFileSet(t, files, []string{"index.js", "node_modules/left-pad.js"})
	})
}

func assertFileSet(t *testing.T, got map[string][]byte, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d files %v, want %d files %v", len(got), keysOf(got), len(want), want)
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing expected file %q; got %v", w, keysOf(got))
		}
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCollectFilesFunctionboxIgnoreCustomRule(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"index.js":       "export default {};",
		"README.md":      "docs",
		"dist/bundle.js": "compiled",
		".funcboxignore": "dist/\n*.md\n",
	})
	matcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreMatcher: %v", err)
	}
	files, err := CollectFiles(dir, false, matcher)
	if err != nil {
		t.Fatalf("CollectFiles: %v", err)
	}
	assertFileSet(t, files, []string{"index.js"})
}

func TestCollectFilesNoIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"index.js": "export default {};"})
	matcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreMatcher: %v", err)
	}
	files, err := CollectFiles(dir, false, matcher)
	if err != nil {
		t.Fatalf("CollectFiles: %v", err)
	}
	assertFileSet(t, files, []string{"index.js"})
}

func TestCheckUnpackedSize(t *testing.T) {
	ok := map[string][]byte{"a.js": make([]byte, 1024)}
	if err := CheckUnpackedSize(ok); err != nil {
		t.Errorf("CheckUnpackedSize(1KiB) should pass: %v", err)
	}

	tooBig := map[string][]byte{"a.js": make([]byte, bundle.MaxUnpackedBytes+1)}
	if err := CheckUnpackedSize(tooBig); err == nil {
		t.Error("CheckUnpackedSize should reject a bundle exceeding MaxUnpackedBytes")
	}

	tooManyFiles := make(map[string][]byte, bundle.MaxFiles+1)
	for i := 0; i < bundle.MaxFiles+1; i++ {
		tooManyFiles[string(rune('a'+i%26))+"-"+string(rune(i))] = []byte("x")
	}
	if err := CheckUnpackedSize(tooManyFiles); err == nil {
		t.Error("CheckUnpackedSize should reject too many files")
	}
}
