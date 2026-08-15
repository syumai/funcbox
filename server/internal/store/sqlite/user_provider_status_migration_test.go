package sqlite_test

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlcommon"
	sqlitestore "github.com/syumai/funcbox/server/internal/store/sqlite"
)

// TestUserProviderStatusAndCreatedByMigration seeds a database on the
// pre-0007 schema (users.google_sub, users.disabled; functions with no
// created_by column) and asserts that running Migrate converts it in
// place: google_sub -> provider="google"/provider_subject, disabled ->
// status, and functions.created_by backfilled from each function's oldest
// version.
func TestUserProviderStatusAndCreatedByMigration(t *testing.T) {
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
		"0006_remove_workspace_handles.sql",
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

	// Seed users on the old schema: google_sub + disabled.
	for _, row := range []struct{ id, sub, email, disabled string }{
		{"u-active", "sub-active", "active@example.com", "0"},
		{"u-disabled", "sub-disabled", "disabled@example.com", "1"},
	} {
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO users (id, google_sub, email, name, role, disabled, language, created_at, updated_at)
			 VALUES (?, ?, ?, 'Legacy User', 'member', ?, '', 1, 1)`,
			row.id, row.sub, row.email, row.disabled); err != nil {
			t.Fatalf("insert legacy user %s: %v", row.id, err)
		}
	}

	// Seed a function with two versions (oldest, by created_at, must win
	// the created_by backfill) and a function with no versions at all
	// (must be left NULL -- nothing to backfill from).
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO functions (id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at)
		 VALUES ('fn-versioned', 'user', 'u-active', 'versioned', '', NULL, 1, 1)`); err != nil {
		t.Fatalf("insert legacy function fn-versioned: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx,
		`INSERT INTO functions (id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at)
		 VALUES ('fn-versionless', 'user', 'u-active', 'versionless', '', NULL, 1, 1)`); err != nil {
		t.Fatalf("insert legacy function fn-versionless: %v", err)
	}
	for _, v := range []struct {
		id, createdBy string
		createdAt     int64
	}{
		{"ver-newer", "u-disabled", 20},
		{"ver-older", "u-active", 10}, // earlier created_at: this creator must win
	} {
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO function_versions (id, function_id, manifest, main_path, bundle_hash, bundle_size, unpacked_size, files, created_by, note, created_at, updated_at)
			 VALUES (?, 'fn-versioned', '{}', 'index.js', 'deadbeef', 1, 1, '[]', ?, '', ?, ?)`,
			v.id, v.createdBy, v.createdAt, v.createdAt); err != nil {
			t.Fatalf("insert legacy function_version %s: %v", v.id, err)
		}
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Idempotency: a second call must not error or change the outcome.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	active, err := s.Users().ByProviderSubject(ctx, store.ProviderGoogle, "sub-active")
	if err != nil {
		t.Fatalf("ByProviderSubject(active): %v", err)
	}
	if active.ID != "u-active" {
		t.Fatalf("active.ID = %q, want %q", active.ID, "u-active")
	}
	if active.Status != store.UserStatusActive {
		t.Fatalf("active.Status = %q, want %q", active.Status, store.UserStatusActive)
	}

	disabled, err := s.Users().ByProviderSubject(ctx, store.ProviderGoogle, "sub-disabled")
	if err != nil {
		t.Fatalf("ByProviderSubject(disabled): %v", err)
	}
	if disabled.Status != store.UserStatusDisabled {
		t.Fatalf("disabled.Status = %q, want %q", disabled.Status, store.UserStatusDisabled)
	}

	versioned, err := s.Functions().ByID(ctx, "fn-versioned")
	if err != nil {
		t.Fatalf("Functions().ByID(fn-versioned): %v", err)
	}
	if versioned.CreatedBy == nil || *versioned.CreatedBy != "u-active" {
		t.Fatalf("fn-versioned.CreatedBy = %v, want %q (the oldest version's creator)", versioned.CreatedBy, "u-active")
	}

	versionless, err := s.Functions().ByID(ctx, "fn-versionless")
	if err != nil {
		t.Fatalf("Functions().ByID(fn-versionless): %v", err)
	}
	if versionless.CreatedBy != nil {
		t.Fatalf("fn-versionless.CreatedBy = %v, want nil (no version to backfill from)", versionless.CreatedBy)
	}
}
