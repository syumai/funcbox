package sqlcommon

import (
	"context"

	"github.com/syumai/funcbox/internal/store"
)

type workspaceRepo struct {
	c *conn
}

func (r *workspaceRepo) Create(ctx context.Context, w *store.Workspace) error {
	if w.ID == "" {
		w.ID = store.NewID()
	}
	if w.Settings == nil {
		w.Settings = []byte("{}")
	}
	if w.SettingsGen == 0 {
		w.SettingsGen = 1
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO workspaces (id, name, settings, settings_gen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		w.ID, w.Name, w.Settings, w.SettingsGen, now, now); err != nil {
		return r.c.mapErr(err)
	}
	w.CreatedAt, w.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *workspaceRepo) ByID(ctx context.Context, id string) (*store.Workspace, error) {
	return scanWorkspace(r.c, r.c.queryRow(ctx,
		`SELECT id, name, settings, settings_gen, created_at, updated_at FROM workspaces WHERE id = ?`, id))
}

func (r *workspaceRepo) Update(ctx context.Context, w *store.Workspace) error {
	now := nowUnix()
	res, err := r.c.exec(ctx,
		`UPDATE workspaces SET name = ?, settings = ?, settings_gen = ?, updated_at = ? WHERE id = ?`,
		w.Name, w.Settings, w.SettingsGen, now, w.ID)
	if err != nil {
		return r.c.mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	w.UpdatedAt = fromUnix(now)
	return nil
}

func (r *workspaceRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.c.exec(ctx, `DELETE FROM workspace_members WHERE workspace_id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	if _, err := r.c.exec(ctx, `DELETE FROM workspaces WHERE id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	return nil
}

func (r *workspaceRepo) AddMember(ctx context.Context, m *store.WorkspaceMember) error {
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO workspace_members (workspace_id, user_id, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		m.WorkspaceID, m.UserID, m.Role, now, now); err != nil {
		return r.c.mapErr(err)
	}
	m.CreatedAt, m.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *workspaceRepo) RemoveMember(ctx context.Context, workspaceID, userID string) error {
	res, err := r.c.exec(ctx,
		`DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?`, workspaceID, userID)
	if err != nil {
		return r.c.mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *workspaceRepo) UpdateMemberRole(ctx context.Context, workspaceID, userID string, role store.Role) error {
	now := nowUnix()
	res, err := r.c.exec(ctx,
		`UPDATE workspace_members SET role = ?, updated_at = ? WHERE workspace_id = ? AND user_id = ?`,
		role, now, workspaceID, userID)
	if err != nil {
		return r.c.mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (r *workspaceRepo) ListMembers(ctx context.Context, workspaceID string) ([]*store.WorkspaceMember, error) {
	rows, err := r.c.query(ctx,
		`SELECT workspace_id, user_id, role, created_at, updated_at FROM workspace_members WHERE workspace_id = ? ORDER BY created_at ASC`,
		workspaceID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var members []*store.WorkspaceMember
	for rows.Next() {
		m := &store.WorkspaceMember{}
		var createdAt, updatedAt int64
		if err := rows.Scan(&m.WorkspaceID, &m.UserID, &m.Role, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		m.CreatedAt, m.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
		members = append(members, m)
	}
	return members, rows.Err()
}

func (r *workspaceRepo) ListForUser(ctx context.Context, userID string) ([]*store.Workspace, error) {
	rows, err := r.c.query(ctx,
		`SELECT w.id, w.name, w.settings, w.settings_gen, w.created_at, w.updated_at
		 FROM workspaces w
		 JOIN workspace_members m ON m.workspace_id = w.id
		 WHERE m.user_id = ?
		 ORDER BY w.created_at ASC`, userID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.Workspace
	for rows.Next() {
		w, err := scanWorkspace(r.c, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (r *workspaceRepo) ListAll(ctx context.Context) ([]*store.Workspace, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, name, settings, settings_gen, created_at, updated_at FROM workspaces ORDER BY created_at ASC`)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.Workspace
	for rows.Next() {
		w, err := scanWorkspace(r.c, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func scanWorkspace(c *conn, row rowScanner) (*store.Workspace, error) {
	w := &store.Workspace{}
	var createdAt, updatedAt int64
	if err := row.Scan(&w.ID, &w.Name, &w.Settings, &w.SettingsGen, &createdAt, &updatedAt); err != nil {
		return nil, c.mapErr(err)
	}
	w.CreatedAt, w.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return w, nil
}
