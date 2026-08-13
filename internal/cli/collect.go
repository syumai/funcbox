package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/syumai/funcbox/internal/bundle"
)

// IgnoreFileName is the name of the ignore file consulted by CollectFiles
// (tmp/07-http-api.md §7.5).
const IgnoreFileName = ".funcboxignore"

// implicitExcludeDirs are directory names always excluded from a bundle,
// regardless of .funcboxignore (tmp/07-http-api.md §7.5's file-name table).
// node_modules is handled separately (see CollectFiles) since its exclusion
// depends on compat.nodejs.
var implicitExcludeDirs = map[string]bool{
	".git": true,
}

// LoadIgnoreMatcher reads dir's .funcboxignore file, if any, and returns
// the resulting Matcher. A missing file yields an empty (never-matching)
// Matcher, not an error.
func LoadIgnoreMatcher(dir string) (*Matcher, error) {
	data, err := os.ReadFile(filepath.Join(dir, IgnoreFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return NewMatcher(nil), nil
		}
		return nil, fmt.Errorf("cli: read %s: %w", IgnoreFileName, err)
	}
	return NewMatcher(data), nil
}

// CollectFiles walks dir and returns every file that belongs in the
// function's bundle: implicit excludes (.git/, .env*, .funcboxignore
// itself, and node_modules/ unless includeNodeModules) are applied first,
// then ignoreMatcher (the parsed .funcboxignore). Returned map keys are
// "/"-separated paths relative to dir.
//
// includeNodeModules should be the manifest's compat.nodejs value
// (tmp/07-http-api.md §7.5: "node_modules は compat.nodejs: false のとき
// 暗黙除外、true のとき同梱").
func CollectFiles(dir string, includeNodeModules bool, ignoreMatcher *Matcher) (map[string][]byte, error) {
	files := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if isImplicitDirExclude(rel, includeNodeModules) || ignoreMatcher.Match(rel, true) {
				return fs.SkipDir
			}
			return nil
		}

		if isImplicitFileExclude(rel) || ignoreMatcher.Match(rel, false) {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("cli: read %s: %w", rel, err)
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// isImplicitDirExclude reports whether rel (a directory's relative path)
// is one of the always-excluded directories.
func isImplicitDirExclude(rel string, includeNodeModules bool) bool {
	base := path.Base(rel)
	if implicitExcludeDirs[base] {
		return true
	}
	if !includeNodeModules && base == "node_modules" {
		return true
	}
	return false
}

// isImplicitFileExclude reports whether rel (a file's relative path) is
// always excluded: ".env" and any ".env.*" variant (never bundled — it's
// the CLI's own local secrets file, tmp/07-http-api.md §7.5: "常にバンド
// ル除外"), and .funcboxignore itself.
func isImplicitFileExclude(rel string) bool {
	base := path.Base(rel)
	if base == IgnoreFileName {
		return true
	}
	ok, _ := path.Match(".env*", base)
	return ok
}

// CheckUnpackedSize enforces the same total-size limit the server applies
// (bundle.MaxUnpackedBytes), client-side, so an oversized bundle fails
// immediately with a clear message instead of a round trip to the server.
func CheckUnpackedSize(files map[string][]byte) error {
	var total int64
	for _, data := range files {
		total += int64(len(data))
	}
	if total > bundle.MaxUnpackedBytes {
		return fmt.Errorf("bundle too large: %d bytes exceeds the %d byte (5 MiB) limit; trim files or add entries to %s", total, bundle.MaxUnpackedBytes, IgnoreFileName)
	}
	if len(files) > bundle.MaxFiles {
		return fmt.Errorf("bundle has too many files: %d exceeds the %d file limit; add entries to %s", len(files), bundle.MaxFiles, IgnoreFileName)
	}
	return nil
}
