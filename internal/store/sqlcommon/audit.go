package sqlcommon

import (
	"context"
	"database/sql"

	"github.com/syumai/funcbox/internal/store"
)

type auditRepo struct {
	c *conn
}

func (r *auditRepo) Append(ctx context.Context, a *store.AuditLog) error {
	if a.ID == "" {
		a.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO audit_logs (id, actor_id, action, target, detail, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ActorID, a.Action, a.Target, a.Detail, now, now); err != nil {
		return r.c.mapErr(err)
	}
	a.CreatedAt, a.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

// List returns audit entries newest-first (by ULID id, which is
// time-sortable), at most limit entries, starting strictly before cursor
// if non-empty.
func (r *auditRepo) List(ctx context.Context, cursor string, limit int) ([]*store.AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if cursor == "" {
		rows, err = r.c.query(ctx,
			`SELECT id, actor_id, action, target, detail, created_at, updated_at
			 FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	} else {
		rows, err = r.c.query(ctx,
			`SELECT id, actor_id, action, target, detail, created_at, updated_at
			 FROM audit_logs WHERE id < ? ORDER BY id DESC LIMIT ?`, cursor, limit)
	}
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.AuditLog
	for rows.Next() {
		a := &store.AuditLog{}
		var createdAt, updatedAt int64
		if err := rows.Scan(&a.ID, &a.ActorID, &a.Action, &a.Target, &a.Detail, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		a.CreatedAt, a.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
		out = append(out, a)
	}
	return out, rows.Err()
}
