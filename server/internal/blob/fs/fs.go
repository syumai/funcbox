// Package fs implements blob.Store on top of the local filesystem. It is
// the default backend for local development and tests: no external
// dependencies, atomic writes via temp-file-then-rename.
package fs

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/syumai/funcbox/server/internal/blob"
)

// Store is a filesystem-backed blob.Store rooted at a directory.
type Store struct {
	root string
}

// New creates a Store rooted at root, creating the directory if needed.
func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &Store{root: root}, nil
}

// path validates key and resolves it to an absolute filesystem path under
// the store's root.
func (s *Store) path(key string) (string, error) {
	if err := blob.ValidateKey(key); err != nil {
		return "", err
	}
	return filepath.Join(s.root, filepath.FromSlash(key)), nil
}

// Put writes r to key atomically: it writes to a temp file in the same
// directory as the destination, fsyncs it, then renames it into place.
// Because keys are content-addressed, a Put that races with another Put of
// the same key is safe — both write the same bytes and whichever rename
// lands last determines the (identical) final content.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dst, err := s.path(key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := io.CopyN(tmp, r, size); err != nil && err != io.EOF {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	committed = true

	// Best-effort fsync of the parent directory so the rename itself is
	// durable across a crash. Not all platforms support syncing a
	// directory handle; ignore failure.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Get returns a reader for the content stored under key. Returns
// blob.ErrNotExist if key has no stored content.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, blob.ErrNotExist
		}
		return nil, err
	}
	return f, nil
}

// Exists reports whether key has stored content.
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	p, err := s.path(key)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Delete removes key. Deleting a missing key is not an error (see
// blob.ErrNotExist doc comment).
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// List implements blob.Lister by walking the directory tree under root.
// Temp files from an in-flight Put (".tmp-*", see Put) are skipped: they
// aren't a stored key yet, and Put always removes them on any non-success
// path, but a crash mid-write could in principle leave one behind, and
// such a leftover must never be mistaken for -- or garbage-collected as --
// a real, referenced key.
func (s *Store) List(ctx context.Context, prefix string, fn func(key string) error) error {
	return filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".tmp-") {
			return nil
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			return nil
		}
		return fn(key)
	})
}

var (
	_ blob.Store  = (*Store)(nil)
	_ blob.Lister = (*Store)(nil)
)
