// Package gcs implements blob.Store on top of native Google Cloud Storage.
// It uses the official cloud.google.com/go/storage client, which is pure
// Go, so using it keeps the funcbox-server binary CGo-free.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/syumai/funcbox/server/internal/blob"
)

// Options configures a Store.
type Options struct {
	// Bucket is the GCS bucket name. Required.
	Bucket string
}

// Store is a GCS-backed blob.Store.
//
// Credentials: New calls storage.NewClient with no extra options, which
// resolves Application Default Credentials — the GOOGLE_APPLICATION_CREDENTIALS
// env var, a gcloud ADC file, or the GCE/GKE metadata server, in that order.
// That's the right default for real GCS and needs no configuration here.
//
// For local development and tests, set the STORAGE_EMULATOR_HOST env var
// (e.g. to a fake-gcs-server instance's address). cloud.google.com/go/storage
// detects that variable itself and automatically switches to an
// unauthenticated client pointed at that host, so New requires no
// emulator-specific code path of its own.
type Store struct {
	client *storage.Client
	bucket *storage.BucketHandle
}

// New creates a Store for the given bucket. See Options and the Store doc
// comment for credential/emulator resolution.
func New(ctx context.Context, opts Options) (*Store, error) {
	if opts.Bucket == "" {
		return nil, errors.New("blob/gcs: Bucket is required")
	}
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("blob/gcs: new client: %w", err)
	}
	return &Store{client: client, bucket: client.Bucket(opts.Bucket)}, nil
}

// Close closes the underlying GCS client and releases its connections.
// Close is not part of blob.Store (the fs and s3 backends have nothing to
// close), so callers that need to release a gcs.Store's resources on
// shutdown should do so via an io.Closer type assertion on the concrete
// blob.Store value, since the interface itself doesn't expose Close.
func (s *Store) Close() error {
	return s.client.Close()
}

// Put uploads r (exactly size bytes) to key. GCS object writes aren't
// visible or durable until the writer's Close succeeds, so Put treats a
// Close error as a failed write even if the byte count copied matched
// size. Because keys are content-addressed, concurrent Puts of the same
// key+content are safe: GCS objects are only ever replaced wholesale by a
// successful Close, so the final state is the same identical content no
// matter which writer's Close lands last.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	if err := blob.ValidateKey(key); err != nil {
		return err
	}
	w := s.bucket.Object(key).NewWriter(ctx)
	if _, err := io.CopyN(w, r, size); err != nil && err != io.EOF {
		_ = w.Close()
		return fmt.Errorf("blob/gcs: put %q: %w", key, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("blob/gcs: put %q: close: %w", key, err)
	}
	return nil
}

// Get returns a reader for the content stored under key, streaming
// directly from the GCS object reader rather than buffering it. Returns
// blob.ErrNotExist if key has no stored content.
func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := blob.ValidateKey(key); err != nil {
		return nil, err
	}
	r, err := s.bucket.Object(key).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, blob.ErrNotExist
		}
		return nil, fmt.Errorf("blob/gcs: get %q: %w", key, err)
	}
	return r, nil
}

// Exists reports whether key has stored content.
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	if err := blob.ValidateKey(key); err != nil {
		return false, err
	}
	_, err := s.bucket.Object(key).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("blob/gcs: stat %q: %w", key, err)
	}
	return true, nil
}

// Delete removes key. Deleting a missing key is not an error (see
// blob.ErrNotExist doc comment); storage.ErrObjectNotExist is translated
// to nil to match that contract, since GCS itself (unlike S3) returns an
// error for deleting an absent object.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := blob.ValidateKey(key); err != nil {
		return err
	}
	err := s.bucket.Object(key).Delete(ctx)
	if err != nil && !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("blob/gcs: delete %q: %w", key, err)
	}
	return nil
}

// List implements blob.Lister via the bucket's object iterator.
func (s *Store) List(ctx context.Context, prefix string, fn func(key string) error) error {
	it := s.bucket.Objects(ctx, &storage.Query{Prefix: prefix})
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			return nil
		}
		if err != nil {
			return fmt.Errorf("blob/gcs: list: %w", err)
		}
		if err := fn(attrs.Name); err != nil {
			return err
		}
	}
}

var (
	_ blob.Store  = (*Store)(nil)
	_ blob.Lister = (*Store)(nil)
)
