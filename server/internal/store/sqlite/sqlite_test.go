package sqlite_test

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlcommon"
	sqlitestore "github.com/syumai/funcbox/server/internal/store/sqlite"
	"github.com/syumai/funcbox/server/internal/store/storetest"
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

func TestGlobalFunctionNameMigrationPreservesDuplicateFunctions(t *testing.T) {
	ctx := context.Background()
	s, err := sqlitestore.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	legacy := fstest.MapFS{}
	all := sqlcommon.SQLiteMigrations()
	for i := 1; i <= 3; i++ {
		name := map[int]string{1: "0001_init.sql", 2: "0002_invocation_logs.sql", 3: "0003_user_language.sql"}[i]
		body, err := fs.ReadFile(all, name)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		legacy[name] = &fstest.MapFile{Data: body}
	}
	if err := s.ApplyMigrations(ctx, legacy); err != nil {
		t.Fatalf("apply legacy migrations: %v", err)
	}

	for _, row := range []struct {
		id, owner string
		created   int64
	}{{"z-newer", "owner-b", 20}, {"a-older", "owner-a", 10}} {
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO functions (id, owner_type, owner_id, name, description, created_at, updated_at) VALUES (?, 'user', ?, 'shared', '', ?, ?)`,
			row.id, row.owner, row.created, row.created); err != nil {
			t.Fatalf("insert legacy function %s: %v", row.id, err)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	winner, err := s.Functions().ByName(ctx, "shared")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	if winner.ID != "a-older" {
		t.Fatalf("winner ID = %q, want oldest function", winner.ID)
	}
	allFunctions, err := s.Functions().ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(allFunctions) != 2 {
		t.Fatalf("legacy functions after migration = %d, want 2", len(allFunctions))
	}
}
