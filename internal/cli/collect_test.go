package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

// symlinkOrSkip creates a symlink at newname pointing to oldname, skipping
// the test if the platform/environment doesn't support creating symlinks
// (e.g. an unprivileged account on Windows).
func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("os.Symlink unsupported in this environment: %v", err)
	}
}

// TestCollectFilesFollowsSymlinkedDirectory reproduces pnpm's default
// node_modules layout closely enough to be the regression test for
// examples/nodejs-compat's documented failure: a package directory that
// lives elsewhere on disk (pnpm's content-addressable store,
// node_modules/.pnpm/...) and is symlinked in at its logical
// node_modules/<pkg> path. Before collect.go followed directory symlinks,
// this failed with "read node_modules/leftpad: is a directory" (WalkDir
// doesn't follow symlinks and collect.go didn't special-case one pointing
// at a directory).
func TestCollectFilesFollowsSymlinkedDirectory(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"index.js": "export default {};",
		"node_modules/.pnpm/leftpad@1.0.0/node_modules/leftpad/index.js":     "module.exports = {};",
		"node_modules/.pnpm/leftpad@1.0.0/node_modules/leftpad/package.json": `{"name":"leftpad"}`,
	})
	symlinkOrSkip(t,
		filepath.Join(dir, "node_modules", ".pnpm", "leftpad@1.0.0", "node_modules", "leftpad"),
		filepath.Join(dir, "node_modules", "leftpad"))

	matcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreMatcher: %v", err)
	}
	files, err := CollectFiles(dir, true, matcher)
	if err != nil {
		t.Fatalf("CollectFiles: %v", err)
	}
	assertFileSet(t, files, []string{
		"index.js",
		"node_modules/.pnpm/leftpad@1.0.0/node_modules/leftpad/index.js",
		"node_modules/.pnpm/leftpad@1.0.0/node_modules/leftpad/package.json",
		"node_modules/leftpad/index.js",
		"node_modules/leftpad/package.json",
	})
	if got := string(files["node_modules/leftpad/index.js"]); got != "module.exports = {};" {
		t.Errorf("content reached through the symlinked dir = %q, want %q", got, "module.exports = {};")
	}
}

// TestCollectFilesFollowsSymlinkedFile checks a symlink that points
// directly at a regular file (as opposed to a directory): the target's
// content must be included at the symlink's own logical path.
func TestCollectFilesFollowsSymlinkedFile(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"real/shared.js": "export const shared = 1;",
		"index.js":       "export default {};",
	})
	symlinkOrSkip(t, filepath.Join(dir, "real", "shared.js"), filepath.Join(dir, "shared-link.js"))

	matcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreMatcher: %v", err)
	}
	files, err := CollectFiles(dir, false, matcher)
	if err != nil {
		t.Fatalf("CollectFiles: %v", err)
	}
	assertFileSet(t, files, []string{"index.js", "real/shared.js", "shared-link.js"})
	if got := string(files["shared-link.js"]); got != "export const shared = 1;" {
		t.Errorf("content reached through the file symlink = %q, want %q", got, "export const shared = 1;")
	}
}

// TestCollectFilesSkipsSymlinkCycle ensures a directory symlink that
// points back at one of its own ancestors is detected and skipped rather
// than causing CollectFiles to recurse forever.
func TestCollectFilesSkipsSymlinkCycle(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"index.js": "export default {};"})
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// sub/loop -> dir (an ancestor of sub itself): following it would
	// recurse into dir -> sub -> loop -> dir -> ... forever if uncaught.
	symlinkOrSkip(t, dir, filepath.Join(dir, "sub", "loop"))

	matcher, err := LoadIgnoreMatcher(dir)
	if err != nil {
		t.Fatalf("LoadIgnoreMatcher: %v", err)
	}

	done := make(chan struct{})
	var files map[string][]byte
	go func() {
		files, err = CollectFiles(dir, false, matcher)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("CollectFiles did not return within 10s; a symlink cycle was likely not detected")
	}
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
