package fs_test

import (
	"testing"

	"github.com/syumai/funcbox/server/internal/blob"
	"github.com/syumai/funcbox/server/internal/blob/blobtest"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
)

func newStore(t *testing.T) blob.Store {
	s, err := blobfs.New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestStore(t *testing.T) {
	blobtest.TestStore(t, newStore)
}

func TestLister(t *testing.T) {
	blobtest.TestLister(t, newStore)
}
