package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/syumai/funcbox/bundle"
)

// IgnoreFileName is the name of the ignore file consulted by CollectFiles
const IgnoreFileName = ".funcboxignore"

// implicitExcludeDirs are directory names always excluded from a bundle,
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
// 暗黙除外、true のとき同梱").
//
// Directory symlinks are followed. pnpm's default node_modules layout
// symlinks each installed package in from its content-addressable store
// (node_modules/foo -> node_modules/.pnpm/foo@1.0.0/node_modules/foo), and
// plain filepath.WalkDir does not follow symlinks or special-case one that
// points at a directory, which used to fail collection outright with
// "read node_modules/foo: is a directory" (see examples/nodejs-compat). A
// symlink to a regular file is also followed, and its target's content is
// included at the symlink's own logical bundle path.
//
// A symlink cycle (a directory reached again, by real path, from within
// its own current descent — whether the loop closes through a symlink or
// not) is detected via each descent's chain of already-visited real
// (symlink-resolved) directory paths and skipped rather than recursed
// into forever; the SAME real directory reached again through a
// different, non-ancestor branch (e.g. two packages both symlinking into
// pnpm's shared store) is legitimate and is walked again, since each
// occurrence needs its own copy of the content at its own logical bundle
// path. File count and total size are checked incrementally against the
// same limits CheckUnpackedSize enforces afterward, so a pathological
// (non-cyclic but enormous) symlink fan-out still fails fast instead of
// reading unbounded data into memory.
func CollectFiles(dir string, includeNodeModules bool, ignoreMatcher *Matcher) (map[string][]byte, error) {
	rootReal, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("cli: resolve %s: %w", dir, err)
	}
	files := make(map[string][]byte)
	var total int64
	ancestors := map[string]bool{rootReal: true}
	if err := collectDir(dir, dir, ancestors, includeNodeModules, ignoreMatcher, files, &total); err != nil {
		return nil, err
	}
	return files, nil
}

// collectDir recursively collects files under currentDir (a real
// filesystem path, possibly reached by following one or more symlinks)
// into files, using root to compute "/"-separated bundle-relative paths.
//
// ancestorReal is the set of real (symlink-resolved) directory paths on
// the current descent chain (root included), used to detect a cycle
// closed by a symlink pointing back at any of its own ancestors. It is
// never mutated in place: each recursive call builds and passes down its
// own extended copy, so sibling branches of the walk don't see each
// other's ancestors.
func collectDir(root, currentDir string, ancestorReal map[string]bool, includeNodeModules bool, ignoreMatcher *Matcher, files map[string][]byte, total *int64) error {
	entries, err := os.ReadDir(currentDir)
	if err != nil {
		return fmt.Errorf("cli: read directory %s: %w", currentDir, err)
	}

	for _, entry := range entries {
		p := filepath.Join(currentDir, entry.Name())
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		isSymlink := entry.Type()&fs.ModeSymlink != 0
		isDir := entry.IsDir()
		if isSymlink {
			target, err := os.Stat(p) // follows the symlink
			if err != nil {
				return fmt.Errorf("cli: read %s: broken symlink: %w", rel, err)
			}
			isDir = target.IsDir()
		}

		if isDir {
			if isImplicitDirExclude(rel, includeNodeModules) || ignoreMatcher.Match(rel, true) {
				continue
			}
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				return fmt.Errorf("cli: resolve %s: %w", rel, err)
			}
			if ancestorReal[real] {
				// A cycle: this directory (reached directly, or through a
				// symlink) is one of its own ancestors in the current
				// descent. Skip rather than recursing forever.
				continue
			}
			nextAncestors := make(map[string]bool, len(ancestorReal)+1)
			for k := range ancestorReal {
				nextAncestors[k] = true
			}
			nextAncestors[real] = true
			if err := collectDir(root, p, nextAncestors, includeNodeModules, ignoreMatcher, files, total); err != nil {
				return err
			}
			continue
		}

		if isImplicitFileExclude(rel) || ignoreMatcher.Match(rel, false) {
			continue
		}
		data, err := os.ReadFile(p) // follows a regular-file symlink to its target's content
		if err != nil {
			return fmt.Errorf("cli: read %s: %w", rel, err)
		}
		*total += int64(len(data))
		if len(files)+1 > bundle.MaxFiles || *total > bundle.MaxUnpackedBytes {
			return fmt.Errorf("bundle too large: exceeds the %d byte (5 MiB) / %d file limit while collecting %s; trim files or add entries to %s", bundle.MaxUnpackedBytes, bundle.MaxFiles, rel, IgnoreFileName)
		}
		files[rel] = data
	}
	return nil
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
