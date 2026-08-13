package sqlcommon

import (
	"context"
	"database/sql"
	"errors"

	"github.com/syumai/funcbox/server/internal/store"
)

// BootstrapFirstUser atomically creates the singleton organization (if it
// doesn't already exist) and promotes u to admin, but only if no user
// exists yet.
//
// Concurrency: the whole operation runs in a single transaction that
// (1) checks the users table is empty and (2) inserts the new user, with
// no gap where another caller's writes could interleave undetected. For
// store/sqlite specifically, the connection pool is capped at one
// connection (see that package's Open doc comment), so SQLite transactions
// are already serialized there; the users.(provider, provider_subject) / users.email UNIQUE
// constraints are kept as a backstop regardless (a real connection pool --
// store/turso, store/neon -- relies on that backstop directly), in which
// case a second racing INSERT INTO users fails with a constraint error,
// mapped to ErrConflict just the same as the pre-check.
func (s *Store) BootstrapFirstUser(ctx context.Context, u *store.User, orgName string) error {
	tx, err := s.c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var count int
	if err := s.c.queryRowOn(ctx, tx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return store.ErrConflict
	}

	now := nowUnix()

	var orgExists int
	if err := s.c.queryRowOn(ctx, tx, `SELECT COUNT(*) FROM organizations WHERE id = 'org'`).Scan(&orgExists); err != nil {
		return err
	}
	if orgExists == 0 {
		if _, err := s.c.execOn(ctx, tx,
			`INSERT INTO organizations (id, name, settings, settings_gen, created_at, updated_at) VALUES ('org', ?, '{}', 1, ?, ?)`,
			orgName, now, now); err != nil {
			return s.c.mapErr(err)
		}
	}

	if u.ID == "" {
		u.ID = store.NewID()
	}
	u.Role = store.RoleAdmin
	// The bootstrap admin is always active regardless of the organization's
	// require_approval setting (tmp/13-public-mode.md §13.3: "ブートストラップ
	// の初回ユーザー...は設定に関わらず常に active") -- there'd be nobody able
	// to approve them otherwise.
	u.Status = store.UserStatusActive
	if _, err := s.c.execOn(ctx, tx,
		`INSERT INTO users (id, provider, provider_subject, email, name, role, status, language, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Provider, u.ProviderSubject, u.Email, u.Name, u.Role, u.Status, u.Language, now, now); err != nil {
		return s.c.mapErr(err)
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
	tx, err := s.c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var versionFuncID string
	err = s.c.queryRowOn(ctx, tx, `SELECT function_id FROM function_versions WHERE id = ?`, versionID).Scan(&versionFuncID)
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
	res, err := s.c.execOn(ctx, tx,
		`UPDATE functions SET active_version_id = ?, updated_at = ? WHERE id = ?`, versionID, now, funcID)
	if err != nil {
		return s.c.mapErr(err)
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

// CreateWorkspace atomically creates ws and adds creatorUserID as an admin
// member.
func (s *Store) CreateWorkspace(ctx context.Context, ws *store.Workspace, creatorUserID string) error {
	tx, err := s.c.db.BeginTx(ctx, nil)
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

	if _, err := s.c.execOn(ctx, tx,
		`INSERT INTO workspaces (id, name, settings, settings_gen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		ws.ID, ws.Name, ws.Settings, ws.SettingsGen, now, now); err != nil {
		return s.c.mapErr(err)
	}

	if _, err := s.c.execOn(ctx, tx,
		`INSERT INTO workspace_members (workspace_id, user_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		ws.ID, creatorUserID, store.RoleAdmin, now, now); err != nil {
		return s.c.mapErr(err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	ws.CreatedAt, ws.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}
