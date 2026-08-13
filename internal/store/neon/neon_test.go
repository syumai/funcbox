package neon_test

import (
	"context"
	"os"
	"testing"

	"github.com/syumai/funcbox/internal/store"
	neonstore "github.com/syumai/funcbox/internal/store/neon"
	"github.com/syumai/funcbox/internal/store/storetest"
)

// TestStore runs the store.Store conformance suite against a real
// PostgreSQL database (Neon or otherwise -- this package has nothing
// Neon-specific in it, see its doc comment), gated behind
// FUNCBOX_TEST_POSTGRES_URL so it skips cleanly wherever that isn't
// available (this project's default `go test ./...` run, most CI). Works
// against any PostgreSQL, including a local one:
//
//	docker run --rm -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
//	FUNCBOX_TEST_POSTGRES_URL="postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable" \
//	  go test ./internal/store/neon/...
func TestStore(t *testing.T) {
	dsn := os.Getenv("FUNCBOX_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("FUNCBOX_TEST_POSTGRES_URL not set; skipping neon (PostgreSQL) conformance suite")
	}

	storetest.TestStore(t, func(t *testing.T) store.Store {
		t.Helper()
		s, err := neonstore.Open(dsn)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { s.Close() })
		if err := resetSchema(context.Background(), s); err != nil {
			t.Fatalf("resetSchema: %v", err)
		}
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		return s
	})
}

// resetSchema drops every table this package's migrations create, so each
// storetest.TestStore subtest gets an effectively fresh database despite
// them all sharing one persistent PostgreSQL database -- see
// store/turso's identical resetSchema for why this matters (most notably
// BootstrapFirstUser's "no users exist yet" precondition).
func resetSchema(ctx context.Context, s *neonstore.Store) error {
	tables := []string{
		"invocation_logs", "env_vars", "function_versions", "functions",
		"workspace_members", "workspaces", "handles", "api_tokens",
		"sessions", "login_rules", "users", "organizations", "audit_logs",
		"schema_migrations",
	}
	for _, table := range tables {
		if _, err := s.DB().ExecContext(ctx, "DROP TABLE IF EXISTS "+table+" CASCADE"); err != nil {
			return err
		}
	}
	return nil
}
