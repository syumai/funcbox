package sqlcommon

import (
	"context"
	"database/sql"

	"github.com/syumai/funcbox/server/internal/store"
)

type functionRepo struct {
	c *conn
}

func (r *functionRepo) Create(ctx context.Context, f *store.Function) error {
	if f.ID == "" {
		f.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO functions (id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.OwnerType, f.OwnerID, f.Name, f.Description, f.ActiveVersionID, now, now); err != nil {
		return r.c.mapErr(err)
	}
	f.CreatedAt, f.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *functionRepo) ByID(ctx context.Context, id string) (*store.Function, error) {
	return scanFunction(r.c, r.c.queryRow(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at
		 FROM functions WHERE id = ?`, id))
}

func (r *functionRepo) ByOwnerAndName(ctx context.Context, ownerType store.OwnerType, ownerID, name string) (*store.Function, error) {
	return scanFunction(r.c, r.c.queryRow(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at
		 FROM functions WHERE owner_type = ? AND owner_id = ? AND name = ?`, ownerType, ownerID, name))
}

func (r *functionRepo) ListByOwner(ctx context.Context, ownerType store.OwnerType, ownerID string) ([]*store.Function, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at
		 FROM functions WHERE owner_type = ? AND owner_id = ? ORDER BY created_at ASC`, ownerType, ownerID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()
	return scanFunctions(r.c, rows)
}

func (r *functionRepo) ListVisibleTo(ctx context.Context, userID string) ([]*store.Function, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at
		 FROM functions
		 WHERE (owner_type = 'user' AND owner_id = ?)
		    OR (owner_type = 'workspace' AND owner_id IN (
		        SELECT workspace_id FROM workspace_members WHERE user_id = ?
		    ))
		 ORDER BY created_at ASC`, userID, userID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()
	return scanFunctions(r.c, rows)
}

func (r *functionRepo) ListAll(ctx context.Context) ([]*store.Function, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_at, updated_at
		 FROM functions ORDER BY created_at ASC`)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()
	return scanFunctions(r.c, rows)
}

func (r *functionRepo) Update(ctx context.Context, f *store.Function) error {
	now := nowUnix()
	res, err := r.c.exec(ctx,
		`UPDATE functions SET name = ?, description = ?, active_version_id = ?, updated_at = ? WHERE id = ?`,
		f.Name, f.Description, f.ActiveVersionID, now, f.ID)
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
	f.UpdatedAt = fromUnix(now)
	return nil
}

func (r *functionRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.c.exec(ctx, `DELETE FROM env_vars WHERE function_id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	if _, err := r.c.exec(ctx, `DELETE FROM invocation_logs WHERE function_id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	if _, err := r.c.exec(ctx, `DELETE FROM function_versions WHERE function_id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	if _, err := r.c.exec(ctx, `DELETE FROM functions WHERE id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	return nil
}

func (r *functionRepo) CreateVersion(ctx context.Context, v *store.FunctionVersion) error {
	if v.ID == "" {
		v.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO function_versions
		   (id, function_id, manifest, main_path, bundle_hash, bundle_size, unpacked_size, files, created_by, note, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.FunctionID, v.Manifest, v.MainPath, v.BundleHash, v.BundleSize, v.UnpackedSize, v.Files, v.CreatedBy, v.Note, now, now); err != nil {
		return r.c.mapErr(err)
	}
	v.CreatedAt, v.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *functionRepo) Version(ctx context.Context, id string) (*store.FunctionVersion, error) {
	return scanVersion(r.c, r.c.queryRow(ctx,
		`SELECT id, function_id, manifest, main_path, bundle_hash, bundle_size, unpacked_size, files, created_by, note, created_at, updated_at
		 FROM function_versions WHERE id = ?`, id))
}

func (r *functionRepo) ListVersions(ctx context.Context, funcID string, limit int) ([]*store.FunctionVersion, error) {
	q := `SELECT id, function_id, manifest, main_path, bundle_hash, bundle_size, unpacked_size, files, created_by, note, created_at, updated_at
	      FROM function_versions WHERE function_id = ? ORDER BY created_at DESC, id DESC`
	args := []any{funcID}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := r.c.query(ctx, q, args...)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.FunctionVersion
	for rows.Next() {
		v, err := scanVersion(r.c, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *functionRepo) SetEnv(ctx context.Context, funcID, key string, valueEnc []byte) error {
	now := nowUnix()
	_, err := r.c.exec(ctx,
		`INSERT INTO env_vars (function_id, key, value_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (function_id, key) DO UPDATE SET value_enc = excluded.value_enc, updated_at = excluded.updated_at`,
		funcID, key, valueEnc, now, now)
	return r.c.mapErr(err)
}

func (r *functionRepo) DeleteEnv(ctx context.Context, funcID, key string) error {
	if _, err := r.c.exec(ctx,
		`DELETE FROM env_vars WHERE function_id = ? AND key = ?`, funcID, key); err != nil {
		return r.c.mapErr(err)
	}
	return nil
}

func (r *functionRepo) ListEnv(ctx context.Context, funcID string) (map[string][]byte, error) {
	rows, err := r.c.query(ctx,
		`SELECT key, value_enc FROM env_vars WHERE function_id = ?`, funcID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	out := map[string][]byte{}
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func scanFunctions(c *conn, rows *sql.Rows) ([]*store.Function, error) {
	var out []*store.Function
	for rows.Next() {
		f, err := scanFunction(c, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func scanFunction(c *conn, row rowScanner) (*store.Function, error) {
	f := &store.Function{}
	var createdAt, updatedAt int64
	var activeVersionID sql.NullString
	if err := row.Scan(&f.ID, &f.OwnerType, &f.OwnerID, &f.Name, &f.Description, &activeVersionID, &createdAt, &updatedAt); err != nil {
		return nil, c.mapErr(err)
	}
	if activeVersionID.Valid {
		f.ActiveVersionID = &activeVersionID.String
	}
	f.CreatedAt, f.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return f, nil
}

func scanVersion(c *conn, row rowScanner) (*store.FunctionVersion, error) {
	v := &store.FunctionVersion{}
	var createdAt, updatedAt int64
	if err := row.Scan(&v.ID, &v.FunctionID, &v.Manifest, &v.MainPath, &v.BundleHash, &v.BundleSize, &v.UnpackedSize,
		&v.Files, &v.CreatedBy, &v.Note, &createdAt, &updatedAt); err != nil {
		return nil, c.mapErr(err)
	}
	v.CreatedAt, v.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return v, nil
}
