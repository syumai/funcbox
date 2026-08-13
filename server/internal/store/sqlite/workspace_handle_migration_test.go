package sqlite_test

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/syumai/funcbox/server/internal/store/sqlcommon"
	sqlitestore "github.com/syumai/funcbox/server/internal/store/sqlite"
)

func TestWorkspaceHandleMigrationRemovesOnlyLegacyWorkspaceRows(t *testing.T) {
	ctx := context.Background()
	s, err := sqlitestore.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	legacy := fstest.MapFS{}
	all := sqlcommon.SQLiteMigrations()
	for _, name := range []string{
		"0001_init.sql",
		"0002_invocation_logs.sql",
		"0003_user_language.sql",
		"0004_global_function_names.sql",
		"0005_invoke_auth_codes.sql",
	} {
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
		handle, ownerType, ownerID string
	}{
		{"legacy-workspace", "workspace", "ws-1"},
		{"alice", "user", "user-1"},
	} {
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO handles (handle, owner_type, owner_id, created_at, updated_at) VALUES (?, ?, ?, 1, 1)`,
			row.handle, row.ownerType, row.ownerID); err != nil {
			t.Fatalf("insert %s handle: %v", row.ownerType, err)
		}
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	var workspaceCount, userCount int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM handles WHERE owner_type = 'workspace'`).Scan(&workspaceCount); err != nil {
		t.Fatalf("count workspace handles: %v", err)
	}
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM handles WHERE owner_type = 'user' AND handle = 'alice'`).Scan(&userCount); err != nil {
		t.Fatalf("count public User IDs: %v", err)
	}
	if workspaceCount != 0 {
		t.Fatalf("workspace handles after migration = %d, want 0", workspaceCount)
	}
	if userCount != 1 {
		t.Fatalf("public User IDs after migration = %d, want 1", userCount)
	}
}
