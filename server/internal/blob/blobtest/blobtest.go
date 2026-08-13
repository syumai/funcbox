// Package blobtest provides a conformance test suite that every blob.Store
// implementation should pass. Backend packages call TestStore from their
// own tests, supplying a constructor for a fresh store.
package blobtest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/syumai/funcbox/internal/blob"
)

// TestStore runs the blob.Store conformance suite against the store
// produced by newStore. newStore is called once per subtest and should
// return an empty, ready-to-use store (e.g. rooted at t.TempDir() for the
// filesystem backend).
func TestStore(t *testing.T, newStore func(t *testing.T) blob.Store) {
	t.Helper()

	t.Run("RoundTrip", func(t *testing.T) { testRoundTrip(t, newStore) })
	t.Run("OverwriteIdempotent", func(t *testing.T) { testOverwriteIdempotent(t, newStore) })
	t.Run("Exists", func(t *testing.T) { testExists(t, newStore) })
	t.Run("Delete", func(t *testing.T) { testDelete(t, newStore) })
	t.Run("MissingKey", func(t *testing.T) { testMissingKey(t, newStore) })
	t.Run("ConcurrentPutSameKey", func(t *testing.T) { testConcurrentPutSameKey(t, newStore) })
	t.Run("InvalidKey", func(t *testing.T) { testInvalidKey(t, newStore) })
}

// TestLister runs the blob.Lister conformance suite against the store
// produced by newStore, IF it implements blob.Lister (skipping cleanly if
// not -- Lister is an optional, separate interface from Store; see its doc
// comment). Call this alongside TestStore from any backend that does
// implement it (fs, s3, gcs all do).
func TestLister(t *testing.T, newStore func(t *testing.T) blob.Store) {
	t.Helper()
	s := newStore(t)
	lister, ok := s.(blob.Lister)
	if !ok {
		t.Skip("store does not implement blob.Lister")
	}

	ctx := context.Background()
	keys := []string{
		"bundles/sha256/aaaa.tar.gz",
		"bundles/sha256/bbbb.tar.gz",
		"other/cccc.tar.gz",
	}
	for _, k := range keys {
		if err := s.Put(ctx, k, bytes.NewReader([]byte("x")), 1); err != nil {
			t.Fatalf("Put(%q): %v", k, err)
		}
	}

	var all []string
	if err := lister.List(ctx, "", func(key string) error {
		all = append(all, key)
		return nil
	}); err != nil {
		t.Fatalf("List(\"\"): %v", err)
	}
	if !sameSet(all, keys) {
		t.Fatalf("List(\"\") = %v, want (in any order) %v", all, keys)
	}

	var prefixed []string
	if err := lister.List(ctx, "bundles/", func(key string) error {
		prefixed = append(prefixed, key)
		return nil
	}); err != nil {
		t.Fatalf("List(\"bundles/\"): %v", err)
	}
	if !sameSet(prefixed, keys[:2]) {
		t.Fatalf("List(\"bundles/\") = %v, want (in any order) %v", prefixed, keys[:2])
	}

	// A callback error must stop enumeration and propagate.
	stop := errors.New("stop")
	err := lister.List(ctx, "", func(key string) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("List with an erroring callback: got %v, want %v", err, stop)
	}
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gotSet := make(map[string]bool, len(got))
	for _, k := range got {
		gotSet[k] = true
	}
	for _, k := range want {
		if !gotSet[k] {
			return false
		}
	}
	return true
}

const key = "bundles/sha256/deadbeef.tar.gz"

func testRoundTrip(t *testing.T, newStore func(t *testing.T) blob.Store) {
	ctx := context.Background()
	s := newStore(t)
	content := []byte("hello, funcbox bundle")

	if err := s.Put(ctx, key, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rc, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}
}

func testOverwriteIdempotent(t *testing.T, newStore func(t *testing.T) blob.Store) {
	ctx := context.Background()
	s := newStore(t)
	content := []byte("idempotent content")

	for i := 0; i < 3; i++ {
		if err := s.Put(ctx, key, bytes.NewReader(content), int64(len(content))); err != nil {
			t.Fatalf("Put #%d: %v", i, err)
		}
	}

	rc, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch after repeated Put: got %q, want %q", got, content)
	}
}

func testExists(t *testing.T, newStore func(t *testing.T) blob.Store) {
	ctx := context.Background()
	s := newStore(t)

	ok, err := s.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists (before put): %v", err)
	}
	if ok {
		t.Fatalf("Exists (before put) = true, want false")
	}

	content := []byte("exists content")
	if err := s.Put(ctx, key, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err = s.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists (after put): %v", err)
	}
	if !ok {
		t.Fatalf("Exists (after put) = false, want true")
	}
}

func testDelete(t *testing.T, newStore func(t *testing.T) blob.Store) {
	ctx := context.Background()
	s := newStore(t)
	content := []byte("delete content")

	if err := s.Put(ctx, key, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	ok, err := s.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists (after delete): %v", err)
	}
	if ok {
		t.Fatalf("Exists (after delete) = true, want false")
	}

	_, err = s.Get(ctx, key)
	if !errors.Is(err, blob.ErrNotExist) {
		t.Fatalf("Get (after delete) error = %v, want blob.ErrNotExist", err)
	}
}

func testMissingKey(t *testing.T, newStore func(t *testing.T) blob.Store) {
	ctx := context.Background()
	s := newStore(t)

	_, err := s.Get(ctx, key)
	if !errors.Is(err, blob.ErrNotExist) {
		t.Fatalf("Get (missing) error = %v, want blob.ErrNotExist", err)
	}

	ok, err := s.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists (missing): %v", err)
	}
	if ok {
		t.Fatalf("Exists (missing) = true, want false")
	}

	// Delete of a missing key must not be an error: it is idempotent.
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete (missing) = %v, want nil", err)
	}
}

func testConcurrentPutSameKey(t *testing.T, newStore func(t *testing.T) blob.Store) {
	ctx := context.Background()
	s := newStore(t)
	content := bytes.Repeat([]byte("concurrent-content-"), 1024)

	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.Put(ctx, key, bytes.NewReader(content), int64(len(content)))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Put #%d: %v", i, err)
		}
	}

	rc, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch after concurrent Put: got %d bytes, want %d bytes matching content", len(got), len(content))
	}
}

func testInvalidKey(t *testing.T, newStore func(t *testing.T) blob.Store) {
	ctx := context.Background()
	s := newStore(t)
	content := []byte("x")

	invalidKeys := []string{
		"",
		"/absolute/path",
		"../escape.tar.gz",
		"bundles/../escape.tar.gz",
		"bundles//double-slash.tar.gz",
		"bundles/has space.tar.gz",
	}
	for _, k := range invalidKeys {
		if err := s.Put(ctx, k, bytes.NewReader(content), int64(len(content))); err == nil {
			t.Errorf("Put(%q) = nil error, want error", k)
		}
		if _, err := s.Get(ctx, k); err == nil {
			t.Errorf("Get(%q) = nil error, want error", k)
		}
	}
}
