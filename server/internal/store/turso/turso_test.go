package turso_test

import (
	"context"
	"os"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/storetest"
	tursostore "github.com/syumai/funcbox/server/internal/store/turso"
)

// TestStore runs the store.Store conformance suite against a real Turso
// (or local sqld / embedded-replica dev server) database, gated behind
// FUNCBOX_TEST_TURSO_URL so it skips cleanly wherever that isn't
// available (this project's default `go test ./...` run, most CI). Point
// it at a scratch database -- the suite creates its own users/functions/etc
// but never drops the database itself.
//
// FUNCBOX_TEST_TURSO_URL is passed straight to tursostore.Open, so it may
// carry an "?authToken=..." query parameter the same way FUNCBOX_DB does
// (see internal/config's doc comment): e.g.
//
//	FUNCBOX_TEST_TURSO_URL="libsql://mydb-org.turso.io?authToken=..." go test ./internal/store/turso/...
//
// or, against a local sqld dev server with no auth:
//
//	FUNCBOX_TEST_TURSO_URL="http://127.0.0.1:8080" go test ./internal/store/turso/...
func TestStore(t *testing.T) {
	dsn := os.Getenv("FUNCBOX_TEST_TURSO_URL")
	if dsn == "" {
		t.Skip("FUNCBOX_TEST_TURSO_URL not set; skipping turso conformance suite")
	}

	storetest.TestStore(t, func(t *testing.T) store.Store {
		t.Helper()
		s, err := tursostore.Open(dsn)
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

// resetSchema drops every table this project's migrations create, so each
// storetest.TestStore subtest gets an effectively fresh database despite
// them all sharing one persistent remote Turso database (unlike
// store/sqlite's ":memory:" DSN, there is no cheap way to hand the suite an
// actually-new database per subtest here). This matters because several
// subtests -- most notably BootstrapFirstUser and
// BootstrapFirstUserConcurrent -- assert on "no users exist yet"
// preconditions that only hold for a genuinely empty database.
func resetSchema(ctx context.Context, s *tursostore.Store) error {
	// Children before parents (foreign keys), then schema_migrations last
	// so Migrate reapplies every migration from scratch.
	tables := []string{
		"invocation_logs", "env_vars", "function_versions", "functions",
		"function_names", "invoke_auth_codes", "cli_auth_codes",
		"cli_credentials", "oauth_grants", "oauth_auth_codes", "oauth_clients",
		"workspace_members", "workspaces", "handles", "api_tokens",
		"sessions", "login_rules", "users", "organizations", "audit_logs",
		"schema_migrations",
	}
	for _, table := range tables {
		if _, err := s.DB().ExecContext(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
			return err
		}
	}
	return nil
}
