package fs_test

import (
	"testing"

	"github.com/syumai/funcbox/internal/blob"
	"github.com/syumai/funcbox/internal/blob/blobtest"
	blobfs "github.com/syumai/funcbox/internal/blob/fs"
)

func TestStore(t *testing.T) {
	blobtest.TestStore(t, func(t *testing.T) blob.Store {
		s, err := blobfs.New(t.TempDir())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return s
	})
}
