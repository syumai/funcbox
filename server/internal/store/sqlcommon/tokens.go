package sqlcommon

import (
	"context"

	"github.com/syumai/funcbox/server/internal/store"
)

type tokenRepo struct {
	c *conn
}

func (r *tokenRepo) Create(ctx context.Context, t *store.APIToken) error {
	if t.ID == "" {
		t.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO api_tokens (id, user_id, token_hash, name, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.TokenHash, t.Name, toUnix(t.ExpiresAt), now, now); err != nil {
		return r.c.mapErr(err)
	}
	t.CreatedAt, t.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *tokenRepo) ByHash(ctx context.Context, tokenHash string) (*store.APIToken, error) {
	return scanToken(r.c, r.c.queryRow(ctx,
		`SELECT id, user_id, token_hash, name, expires_at, created_at, updated_at FROM api_tokens WHERE token_hash = ?`, tokenHash))
}

func (r *tokenRepo) ListByUser(ctx context.Context, userID string) ([]*store.APIToken, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, user_id, token_hash, name, expires_at, created_at, updated_at FROM api_tokens WHERE user_id = ? ORDER BY created_at ASC`,
		userID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.APIToken
	for rows.Next() {
		t, err := scanToken(r.c, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *tokenRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.c.exec(ctx, `DELETE FROM api_tokens WHERE id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	return nil
}

func scanToken(c *conn, row rowScanner) (*store.APIToken, error) {
	t := &store.APIToken{}
	var expiresAt, createdAt, updatedAt int64
	if err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.Name, &expiresAt, &createdAt, &updatedAt); err != nil {
		return nil, c.mapErr(err)
	}
	t.ExpiresAt = fromUnix(expiresAt)
	t.CreatedAt, t.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return t, nil
}
