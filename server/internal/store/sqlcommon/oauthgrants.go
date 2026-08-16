package sqlcommon

import (
	"context"
	"errors"
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
		`INSERT INTO oauth_grants (id, user_id, client_id, secret_hash, prev_secret_hash, created_at, updated_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.UserID, g.ClientID, g.SecretHash, "", now, now, nil); err != nil {
		return r.c.mapErr(err)
	}
	g.CreatedAt, g.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *oauthGrantRepo) ByHash(ctx context.Context, secretHash string) (*store.OAuthGrant, error) {
	return scanOAuthGrant(r.c, r.c.queryRow(ctx,
		`SELECT id, user_id, client_id, secret_hash, prev_secret_hash, created_at, updated_at, last_used_at FROM oauth_grants WHERE secret_hash = ?`, secretHash))
}

func (r *oauthGrantRepo) ListByUser(ctx context.Context, userID string) ([]*store.OAuthGrant, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, user_id, client_id, secret_hash, prev_secret_hash, created_at, updated_at, last_used_at FROM oauth_grants WHERE user_id = ? ORDER BY created_at ASC`,
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

// Rotate is the atomic CAS UPDATE described on the interface: the WHERE
// clause (id AND secret_hash = oldHash) IS the compare-and-swap condition,
// and RETURNING lets a single round trip both perform the swap and hand
// back the updated row -- exactly the same "DELETE ... RETURNING" shape
// oauthAuthCodeRepo.Consume already uses for its own single-use guarantee.
// A concurrent second caller racing the same oldHash sees this UPDATE
// affect zero rows (SQL row-level locking serializes the two writers), so
// RETURNING scans sql.ErrNoRows -> store.ErrNotFound, mapped to
// store.ErrConflict below per the interface's documented contract.
func (r *oauthGrantRepo) Rotate(ctx context.Context, id, oldHash, newHash string, now time.Time) (*store.OAuthGrant, error) {
	nowU := toUnix(now)
	row := r.c.queryRow(ctx, `UPDATE oauth_grants
		SET secret_hash = ?, prev_secret_hash = ?, last_used_at = ?, updated_at = ?
		WHERE id = ? AND secret_hash = ?
		RETURNING id, user_id, client_id, secret_hash, prev_secret_hash, created_at, updated_at, last_used_at`,
		newHash, oldHash, nowU, nowU, id, oldHash)
	g, err := scanOAuthGrant(r.c, row)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrConflict
		}
		return nil, err
	}
	return g, nil
}

// RevokeIfPreviousSecret is a single conditional DELETE: at most one grant
// can ever have prev_secret_hash = hash (Rotate only ever sets it to the
// caller-presented oldHash, a 256-bit random value), so RowsAffected is
// always 0 or 1.
func (r *oauthGrantRepo) RevokeIfPreviousSecret(ctx context.Context, hash string) (bool, error) {
	res, err := r.c.exec(ctx, `DELETE FROM oauth_grants WHERE prev_secret_hash = ? AND prev_secret_hash != ''`, hash)
	if err != nil {
		return false, r.c.mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func scanOAuthGrant(c *conn, row rowScanner) (*store.OAuthGrant, error) {
	g := &store.OAuthGrant{}
	var createdAt, updatedAt int64
	var lastUsedAt *int64
	if err := row.Scan(&g.ID, &g.UserID, &g.ClientID, &g.SecretHash, &g.PrevSecretHash, &createdAt, &updatedAt, &lastUsedAt); err != nil {
		return nil, c.mapErr(err)
	}
	g.CreatedAt, g.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	if lastUsedAt != nil {
		g.LastUsedAt = fromUnix(*lastUsedAt)
	}
	return g, nil
}
