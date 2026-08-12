package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/syumai/funcbox/internal/store"
)

// BootstrapFirstUser atomically creates the singleton organization (if it
// doesn't already exist) and promotes u to admin, but only if no user
// exists yet.
//
// Concurrency: the whole operation runs in a single transaction that
// (1) checks the users table is empty and (2) inserts the new user, with
// no gap where another caller's writes could interleave undetected. Because
// Store's connection pool is capped at one connection (see Open's doc
// comment), SQLite transactions on this Store are already serialized —
// a second BeginTx blocks until the first transaction's connection is
// returned to the pool — so the empty-table check and the insert are
// effectively atomic with respect to any other call on this Store today.
// The users.google_sub / users.email UNIQUE constraints are kept as a
// backstop against that changing (e.g. a future backend with a real
// connection pool), in which case a second racing INSERT INTO users
// would fail with a constraint error, mapped to ErrConflict just the
// same as the pre-check.
func (s *Store) BootstrapFirstUser(ctx context.Context, u *store.User, orgName string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return store.ErrConflict
	}

	now := nowUnix()

	var orgExists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM organizations WHERE id = 'org'`).Scan(&orgExists); err != nil {
		return err
	}
	if orgExists == 0 {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO organizations (id, name, settings, settings_gen, created_at, updated_at) VALUES ('org', ?, '{}', 1, ?, ?)`,
			orgName, now, now); err != nil {
			return mapErr(err)
		}
	}

	if u.ID == "" {
		u.ID = store.NewID()
	}
	u.Role = store.RoleAdmin
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (id, google_sub, email, name, role, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.GoogleSub, u.Email, u.Name, u.Role, boolToInt(u.Disabled), now, now); err != nil {
		return mapErr(err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	u.CreatedAt, u.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

// ActivateVersion atomically verifies versionID belongs to funcID and
// repoints functions.active_version_id at it.
func (s *Store) ActivateVersion(ctx context.Context, funcID, versionID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var versionFuncID string
	err = tx.QueryRowContext(ctx, `SELECT function_id FROM function_versions WHERE id = ?`, versionID).Scan(&versionFuncID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return err
	}
	if versionFuncID != funcID {
		return store.ErrNotFound
	}

	now := nowUnix()
	res, err := tx.ExecContext(ctx,
		`UPDATE functions SET active_version_id = ?, updated_at = ? WHERE id = ?`, versionID, now, funcID)
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}

	return tx.Commit()
}

// CreateWorkspace atomically creates ws, claims handle for it, and adds
// creatorUserID as an admin member.
func (s *Store) CreateWorkspace(ctx context.Context, ws *store.Workspace, handle string, creatorUserID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if ws.ID == "" {
		ws.ID = store.NewID()
	}
	if ws.Settings == nil {
		ws.Settings = []byte("{}")
	}
	if ws.SettingsGen == 0 {
		ws.SettingsGen = 1
	}
	now := nowUnix()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO workspaces (id, name, settings, settings_gen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ws.ID, ws.Name, ws.Settings, ws.SettingsGen, now, now); err != nil {
		return mapErr(err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO handles (handle, owner_type, owner_id, created_at, updated_at) VALUES (?, 'workspace', ?, ?, ?)`,
		handle, ws.ID, now, now); err != nil {
		return mapErr(err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO workspace_members (workspace_id, user_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		ws.ID, creatorUserID, store.RoleAdmin, now, now); err != nil {
		return mapErr(err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	ws.CreatedAt, ws.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}
