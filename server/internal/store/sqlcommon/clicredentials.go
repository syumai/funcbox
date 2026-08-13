package sqlcommon

import (
	"context"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

type cliCredentialRepo struct {
	c *conn
}

func (r *cliCredentialRepo) Create(ctx context.Context, cred *store.CLICredential) error {
	if cred.ID == "" {
		cred.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO cli_credentials (id, user_id, name, secret_hash, created_at, updated_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, cred.UserID, cred.Name, cred.SecretHash, now, now, nil); err != nil {
		return r.c.mapErr(err)
	}
	cred.CreatedAt, cred.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *cliCredentialRepo) ByHash(ctx context.Context, secretHash string) (*store.CLICredential, error) {
	return scanCLICredential(r.c, r.c.queryRow(ctx,
		`SELECT id, user_id, name, secret_hash, created_at, updated_at, last_used_at FROM cli_credentials WHERE secret_hash = ?`, secretHash))
}

func (r *cliCredentialRepo) ListByUser(ctx context.Context, userID string) ([]*store.CLICredential, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, user_id, name, secret_hash, created_at, updated_at, last_used_at FROM cli_credentials WHERE user_id = ? ORDER BY created_at ASC`,
		userID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.CLICredential
	for rows.Next() {
		c, err := scanCLICredential(r.c, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *cliCredentialRepo) Touch(ctx context.Context, id string, now time.Time) error {
	nowU := toUnix(now)
	res, err := r.c.exec(ctx,
		`UPDATE cli_credentials SET last_used_at = ?, updated_at = ? WHERE id = ?`, nowU, nowU, id)
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

func (r *cliCredentialRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.c.exec(ctx, `DELETE FROM cli_credentials WHERE id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	return nil
}

func scanCLICredential(c *conn, row rowScanner) (*store.CLICredential, error) {
	cred := &store.CLICredential{}
	var createdAt, updatedAt int64
	var lastUsedAt *int64
	if err := row.Scan(&cred.ID, &cred.UserID, &cred.Name, &cred.SecretHash, &createdAt, &updatedAt, &lastUsedAt); err != nil {
		return nil, c.mapErr(err)
	}
	cred.CreatedAt, cred.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	if lastUsedAt != nil {
		cred.LastUsedAt = fromUnix(*lastUsedAt)
	}
	return cred, nil
}
