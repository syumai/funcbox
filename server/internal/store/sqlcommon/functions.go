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
	return r.create(ctx, f, 0)
}

func (r *functionRepo) CreateWithinLimit(ctx context.Context, f *store.Function, limit int) error {
	return r.create(ctx, f, limit)
}

// create is Create/CreateWithinLimit's shared implementation. limit <= 0
// behaves exactly like the original unconditional Create (a plain INSERT).
//
// For limit > 0, the functions insert and its quota check are combined
// into ONE statement -- "INSERT ... SELECT ... WHERE (subquery count) <
// limit" -- so RowsAffected alone tells us whether the row was created,
// with no separate round-trip whose result could go stale before the
// INSERT runs.
//
// That single statement is race-free by itself on the SQLite family
// (store/sqlite pins its connection pool to a single connection, so
// BeginTx already serializes every transaction against this one; libsql/
// turso is SQLite under the hood with the same single-writer model,
// serializing concurrent writers at the storage layer instead). It is NOT
// enough by itself on PostgreSQL: default READ COMMITTED gives each
// statement its own snapshot, so two concurrent transactions' subqueries
// can both see the pre-insert count and both pass the WHERE guard (the
// exact "N concurrent deploys each observe count = limit-1" race this
// method exists to close). A session-scoped pg_advisory_xact_lock keyed
// on f's counting scope closes that gap cheaply: it serializes concurrent
// create calls for the SAME owner scope (unrelated owners never
// contend), auto-releases at commit/rollback, and needs no schema change.
func (r *functionRepo) create(ctx context.Context, f *store.Function, limit int) error {
	if f.ID == "" {
		f.ID = store.NewID()
	}
	now := nowUnix()
	tx, err := r.c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if limit > 0 && r.c.dialect.Name == "postgres" {
		if _, err := r.c.execOn(ctx, tx,
			`SELECT pg_advisory_xact_lock(hashtext(?)::bigint)`, functionLimitScopeKey(f)); err != nil {
			return r.c.mapErr(err)
		}
	}

	insertQuery := `INSERT INTO functions (id, owner_type, owner_id, name, description, active_version_id, created_by, created_at, updated_at) `
	args := []any{f.ID, f.OwnerType, f.OwnerID, f.Name, f.Description, f.ActiveVersionID, f.CreatedBy, now, now}
	if limit > 0 {
		scopeQuery, scopeArgs := functionLimitScopeCond(f)
		insertQuery += `SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (` + scopeQuery + `) < ?`
		args = append(args, scopeArgs...)
		args = append(args, limit)
	} else {
		insertQuery += `VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}

	res, err := r.c.execOn(ctx, tx, insertQuery, args...)
	if err != nil {
		return r.c.mapErr(err)
	}
	if limit > 0 {
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrFunctionLimitReached
		}
	}

	if _, err := r.c.execOn(ctx, tx,
		`INSERT INTO function_names (name, function_id, state, claimed_at) VALUES (?, ?, 'active', ?)`,
		f.Name, f.ID, now); err != nil {
		return r.c.mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return r.c.mapErr(err)
	}
	f.CreatedAt, f.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

// functionLimitScopeCond returns the "SELECT COUNT(*) FROM functions
// WHERE ..." expression (using "?" placeholders, rebound like every other
// sqlcommon query) and its bind args that create's atomic
// "INSERT ... WHERE (...) < limit" guard counts against. Mirrors
// service.Deployer.checkFunctionLimit's own scope switch exactly: a
// workspace-owned f counts by (owner_type, owner_id, created_by)
// [CountByWorkspaceAndCreator's scope], everything else (in practice only
// OwnerTypeUser) counts by (owner_type, owner_id) [CountByOwner's scope].
func functionLimitScopeCond(f *store.Function) (string, []any) {
	if f.OwnerType == store.OwnerTypeWorkspace {
		return `SELECT COUNT(*) FROM functions WHERE owner_type = ? AND owner_id = ? AND created_by = ?`,
			[]any{f.OwnerType, f.OwnerID, f.CreatedBy}
	}
	return `SELECT COUNT(*) FROM functions WHERE owner_type = ? AND owner_id = ?`,
		[]any{f.OwnerType, f.OwnerID}
}

// functionLimitScopeKey returns a stable string identifying f's counting
// scope (the same scope functionLimitScopeCond counts), used only to
// derive create's PostgreSQL advisory-lock key.
func functionLimitScopeKey(f *store.Function) string {
	if f.OwnerType == store.OwnerTypeWorkspace {
		createdBy := ""
		if f.CreatedBy != nil {
			createdBy = *f.CreatedBy
		}
		return "workspace|" + f.OwnerID + "|" + createdBy
	}
	return string(f.OwnerType) + "|" + f.OwnerID
}

func (r *functionRepo) ByID(ctx context.Context, id string) (*store.Function, error) {
	return scanFunction(r.c, r.c.queryRow(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_by, created_at, updated_at
		 FROM functions WHERE id = ?`, id))
}

func (r *functionRepo) ByName(ctx context.Context, name string) (*store.Function, error) {
	return scanFunction(r.c, r.c.queryRow(ctx,
		`SELECT f.id, f.owner_type, f.owner_id, f.name, f.description, f.active_version_id, f.created_by, f.created_at, f.updated_at
		 FROM function_names n JOIN functions f ON f.id = n.function_id
		 WHERE n.name = ? AND n.state = 'active'`, name))
}

func (r *functionRepo) ByOwnerAndName(ctx context.Context, ownerType store.OwnerType, ownerID, name string) (*store.Function, error) {
	return scanFunction(r.c, r.c.queryRow(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_by, created_at, updated_at
		 FROM functions WHERE owner_type = ? AND owner_id = ? AND name = ?`, ownerType, ownerID, name))
}

func (r *functionRepo) ListByOwner(ctx context.Context, ownerType store.OwnerType, ownerID string) ([]*store.Function, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_by, created_at, updated_at
		 FROM functions WHERE owner_type = ? AND owner_id = ? ORDER BY created_at ASC`, ownerType, ownerID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()
	return scanFunctions(r.c, rows)
}

func (r *functionRepo) ListVisibleTo(ctx context.Context, userID string) ([]*store.Function, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_by, created_at, updated_at
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

func (r *functionRepo) CountByOwner(ctx context.Context, ownerType store.OwnerType, ownerID string) (int, error) {
	var n int
	if err := r.c.queryRow(ctx,
		`SELECT COUNT(*) FROM functions WHERE owner_type = ? AND owner_id = ?`, ownerType, ownerID).Scan(&n); err != nil {
		return 0, r.c.mapErr(err)
	}
	return n, nil
}

func (r *functionRepo) CountByWorkspaceAndCreator(ctx context.Context, wsID, userID string) (int, error) {
	var n int
	if err := r.c.queryRow(ctx,
		`SELECT COUNT(*) FROM functions WHERE owner_type = ? AND owner_id = ? AND created_by = ?`,
		store.OwnerTypeWorkspace, wsID, userID).Scan(&n); err != nil {
		return 0, r.c.mapErr(err)
	}
	return n, nil
}

func (r *functionRepo) ListAll(ctx context.Context) ([]*store.Function, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, owner_type, owner_id, name, description, active_version_id, created_by, created_at, updated_at
		 FROM functions ORDER BY created_at ASC`)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()
	return scanFunctions(r.c, rows)
}

func (r *functionRepo) Update(ctx context.Context, f *store.Function) error {
	existing, err := r.ByID(ctx, f.ID)
	if err != nil {
		return err
	}
	// Renames need an explicit alias/tombstone policy. Reject accidental
	// name changes until that operation is exposed as its own use case.
	if existing.Name != f.Name {
		return store.ErrConflict
	}
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
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`UPDATE function_names SET state = 'tombstoned', released_at = ? WHERE function_id = ? AND state = 'active'`, now, id); err != nil {
		return r.c.mapErr(err)
	}
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
	var activeVersionID, createdBy sql.NullString
	if err := row.Scan(&f.ID, &f.OwnerType, &f.OwnerID, &f.Name, &f.Description, &activeVersionID, &createdBy, &createdAt, &updatedAt); err != nil {
		return nil, c.mapErr(err)
	}
	if activeVersionID.Valid {
		f.ActiveVersionID = &activeVersionID.String
	}
	if createdBy.Valid {
		f.CreatedBy = &createdBy.String
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
