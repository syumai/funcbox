package gcs_test

import (
	"context"
	"os"
	"testing"

	"github.com/syumai/funcbox/server/internal/blob"
	"github.com/syumai/funcbox/server/internal/blob/blobtest"
	blobgcs "github.com/syumai/funcbox/server/internal/blob/gcs"
)

// TestStore runs the shared blob.Store conformance suite against a real
// GCS bucket (or, more commonly for local/CI runs, a fake-gcs-server
// emulator pointed to via STORAGE_EMULATOR_HOST). It requires
// FUNCBOX_TEST_GCS_BUCKET and skips cleanly when unset, since no such
// bucket/emulator is available in ordinary dev/CI sandboxes.
func TestStore(t *testing.T) {
	blobtest.TestStore(t, gcsTestStore(t))
}

func TestLister(t *testing.T) {
	blobtest.TestLister(t, gcsTestStore(t))
}

// gcsTestStore returns a constructor for a blob.Store backed by the real
// GCS bucket (or fake-gcs-server emulator) named by FUNCBOX_TEST_GCS_BUCKET,
// skipping the calling test cleanly if it's unset.
func gcsTestStore(t *testing.T) func(t *testing.T) blob.Store {
	t.Helper()
	bucket := os.Getenv("FUNCBOX_TEST_GCS_BUCKET")
	if bucket == "" {
		t.Skip("FUNCBOX_TEST_GCS_BUCKET not set; skipping GCS blob.Store conformance test")
	}

	ctx := context.Background()
	return func(t *testing.T) blob.Store {
		s, err := blobgcs.New(ctx, blobgcs.Options{Bucket: bucket})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
		return s
	}
}
