package sqlcommon

import (
	"context"
	"database/sql"
	"time"

	"github.com/syumai/funcbox/internal/store"
)

type invocationLogRepo struct {
	c *conn
}

func (r *invocationLogRepo) Append(ctx context.Context, l *store.InvocationLog) error {
	if l.ID == "" {
		l.ID = store.NewID()
	}
	if l.FetchDecisions == nil {
		l.FetchDecisions = []byte(`[]`)
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO invocation_logs
		   (id, function_id, version_id, method, path, status, duration_ms, stdout, stderr, fetch_decisions, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.FunctionID, l.VersionID, l.Method, l.Path, l.Status, l.DurationMS, l.Stdout, l.Stderr, l.FetchDecisions, now); err != nil {
		return r.c.mapErr(err)
	}
	l.CreatedAt = fromUnix(now)
	return nil
}

// List returns functionID's invocation logs newest-first (by ULID id), at
// most limit entries (0 = backend default of 50), starting strictly before
// cursor if non-empty. Mirrors auditRepo.List's keyset-pagination shape.
func (r *invocationLogRepo) List(ctx context.Context, functionID string, cursor string, limit int) ([]*store.InvocationLog, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows *sql.Rows
	var err error
	if cursor == "" {
		rows, err = r.c.query(ctx,
			`SELECT id, function_id, version_id, method, path, status, duration_ms, stdout, stderr, fetch_decisions, created_at
			 FROM invocation_logs WHERE function_id = ? ORDER BY id DESC LIMIT ?`, functionID, limit)
	} else {
		rows, err = r.c.query(ctx,
			`SELECT id, function_id, version_id, method, path, status, duration_ms, stdout, stderr, fetch_decisions, created_at
			 FROM invocation_logs WHERE function_id = ? AND id < ? ORDER BY id DESC LIMIT ?`, functionID, cursor, limit)
	}
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.InvocationLog
	for rows.Next() {
		l := &store.InvocationLog{}
		var createdAt int64
		if err := rows.Scan(&l.ID, &l.FunctionID, &l.VersionID, &l.Method, &l.Path, &l.Status, &l.DurationMS,
			&l.Stdout, &l.Stderr, &l.FetchDecisions, &createdAt); err != nil {
			return nil, err
		}
		l.CreatedAt = fromUnix(createdAt)
		out = append(out, l)
	}
	return out, rows.Err()
}

// DeleteOlderThan actively deletes every row with created_at strictly
// before cutoff; see store.InvocationLogRepo.DeleteOlderThan's doc comment
// for why this is the SQL-family strategy (vs. DynamoDB's TTL attribute).
func (r *invocationLogRepo) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := r.c.exec(ctx, `DELETE FROM invocation_logs WHERE created_at < ?`, toUnix(cutoff))
	if err != nil {
		return 0, r.c.mapErr(err)
	}
	return res.RowsAffected()
}
