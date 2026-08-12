package sqlite_test

import (
	"context"
	"testing"

	"github.com/syumai/funcbox/internal/store"
	sqlitestore "github.com/syumai/funcbox/internal/store/sqlite"
	"github.com/syumai/funcbox/internal/store/storetest"
)

// newStore opens an in-memory database and applies migrations. This works
// reliably here (despite modernc.org/sqlite's per-connection ":memory:"
// semantics) because Store.Open caps the connection pool at one
// connection; see the doc comment on sqlite.Open for details.
func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := sqlitestore.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestStore(t *testing.T) {
	storetest.TestStore(t, newStore)
}
