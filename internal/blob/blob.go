// Package blob defines the storage-agnostic interface used to persist
// canonical function bundles (and any other content-addressed binary
// payload). Keys are content-addressed, so Put is expected to be
// idempotent: writing the same key more than once (even concurrently)
// must never corrupt the stored content.
package blob

import (
	"context"
	"errors"
	"io"
	"strings"
)

// ErrNotExist is returned by Get when the requested key has no stored
// content.
//
// Delete, in contrast, is idempotent and does NOT return ErrNotExist for a
// missing key: because keys are content-addressed, deleting a key that is
// already absent leaves the store in the caller's desired end state, so it
// is treated as success. This mirrors how most object stores (e.g. S3)
// behave and keeps garbage-collection code (which repeatedly deletes
// possibly-already-deleted keys) simple. Get is stricter because callers
// generally need to distinguish "no such blob" from other I/O errors.
var ErrNotExist = errors.New("blob: key does not exist")

// Store is the interface every blob backend (filesystem, S3, GCS, ...)
// implements. Keys look like "bundles/sha256/<hex>.tar.gz".
type Store interface {
	// Put stores the content read from r (exactly size bytes) under key.
	// Because keys are content-addressed, Put is idempotent: storing the
	// same key multiple times (including concurrently, from multiple
	// callers) is safe and the result is indistinguishable from a single
	// successful Put.
	Put(ctx context.Context, key string, r io.Reader, size int64) error

	// Get returns a reader for the content stored under key. The caller
	// must Close it. Returns ErrNotExist if key has no stored content.
	Get(ctx context.Context, key string) (io.ReadCloser, error)

	// Exists reports whether key has stored content.
	Exists(ctx context.Context, key string) (bool, error)

	// Delete removes key. Deleting a missing key is not an error; see
	// ErrNotExist.
	Delete(ctx context.Context, key string) error
}

// Lister is implemented by backends that can enumerate their stored keys.
// It is deliberately kept separate from Store (rather than a required
// method on it): every ordinary caller of a blob.Store only ever does
// content-addressed Put/Get/Exists/Delete by a key it already knows, and
// requiring every future backend to support enumeration would be a needless
// constraint on backends where that's expensive or awkward. The one caller
// that genuinely needs it is garbage collection (funcbox-server gc,
// tmp/10-roadmap.md Phase 4): finding blobs no function_version references
// anymore requires knowing every key that exists. fs, s3, and gcs all
// implement it; a caller that needs it type-asserts a blob.Store against
// Lister and handles the "not supported" case explicitly (see
// cmd/funcbox-server/gc.go).
type Lister interface {
	// List calls fn once for every stored key with the given prefix (pass
	// "" to enumerate every key), in no particular order. It stops and
	// returns fn's error immediately if fn returns a non-nil error.
	List(ctx context.Context, prefix string, fn func(key string) error) error
}

// ValidateKey checks that key is a well-formed blob key: a slash-separated
// path of non-empty segments drawn from [A-Za-z0-9_.-], with no ".." or "."
// segments and no leading slash. This rules out path traversal and
// absolute paths regardless of backend (filesystem, S3, ...).
func ValidateKey(key string) error {
	if key == "" {
		return errors.New("blob: key must not be empty")
	}
	if strings.HasPrefix(key, "/") {
		return errors.New("blob: key must not be absolute")
	}
	segments := strings.Split(key, "/")
	for _, seg := range segments {
		if seg == "" {
			return errors.New("blob: key must not contain empty path segments")
		}
		if seg == "." || seg == ".." {
			return errors.New("blob: key must not contain \".\" or \"..\" segments")
		}
		for _, r := range seg {
			if !isValidKeyRune(r) {
				return errors.New("blob: key contains invalid character " + string(r))
			}
		}
	}
	return nil
}

func isValidKeyRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '_' || r == '.' || r == '-':
		return true
	default:
		return false
	}
}
