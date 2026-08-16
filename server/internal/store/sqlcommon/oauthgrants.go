package sqlcommon

import (
	"context"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

type oauthGrantRepo struct{ c *conn }

func (r *oauthGrantRepo) Create(ctx context.Context, g *store.OAuthGrant) error {
	if g.ID == "" {
		g.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO oauth_grants (id, user_id, client_id, secret_hash, created_at, updated_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.UserID, g.ClientID, g.SecretHash, now, now, nil); err != nil {
		return r.c.mapErr(err)
	}
	g.CreatedAt, g.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *oauthGrantRepo) ByHash(ctx context.Context, secretHash string) (*store.OAuthGrant, error) {
	return scanOAuthGrant(r.c, r.c.queryRow(ctx,
		`SELECT id, user_id, client_id, secret_hash, created_at, updated_at, last_used_at FROM oauth_grants WHERE secret_hash = ?`, secretHash))
}

func (r *oauthGrantRepo) ListByUser(ctx context.Context, userID string) ([]*store.OAuthGrant, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, user_id, client_id, secret_hash, created_at, updated_at, last_used_at FROM oauth_grants WHERE user_id = ? ORDER BY created_at ASC`,
		userID)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var out []*store.OAuthGrant
	for rows.Next() {
		g, err := scanOAuthGrant(r.c, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r *oauthGrantRepo) Touch(ctx context.Context, id string, now time.Time) error {
	nowU := toUnix(now)
	res, err := r.c.exec(ctx,
		`UPDATE oauth_grants SET last_used_at = ?, updated_at = ? WHERE id = ?`, nowU, nowU, id)
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

func (r *oauthGrantRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.c.exec(ctx, `DELETE FROM oauth_grants WHERE id = ?`, id); err != nil {
		return r.c.mapErr(err)
	}
	return nil
}

func scanOAuthGrant(c *conn, row rowScanner) (*store.OAuthGrant, error) {
	g := &store.OAuthGrant{}
	var createdAt, updatedAt int64
	var lastUsedAt *int64
	if err := row.Scan(&g.ID, &g.UserID, &g.ClientID, &g.SecretHash, &createdAt, &updatedAt, &lastUsedAt); err != nil {
		return nil, c.mapErr(err)
	}
	g.CreatedAt, g.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	if lastUsedAt != nil {
		g.LastUsedAt = fromUnix(*lastUsedAt)
	}
	return g, nil
}
