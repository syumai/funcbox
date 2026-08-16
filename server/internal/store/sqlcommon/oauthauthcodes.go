package sqlcommon

import (
	"context"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

type oauthAuthCodeRepo struct{ c *conn }

func (r *oauthAuthCodeRepo) Create(ctx context.Context, code *store.OAuthAuthCode) error {
	now := nowUnix()
	// Codes live for only a few minutes; opportunistic cleanup on issuance
	// keeps SQL installations bounded without a background worker, same as
	// cliAuthCodeRepo.Create/invokeAuthCodeRepo.Create.
	if _, err := r.c.exec(ctx, `DELETE FROM oauth_auth_codes WHERE expires_at <= ?`, now); err != nil {
		return r.c.mapErr(err)
	}
	_, err := r.c.exec(ctx, `INSERT INTO oauth_auth_codes
		(id, user_id, client_id, redirect_uri, challenge, resource, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		code.ID, code.UserID, code.ClientID, code.RedirectURI, code.Challenge, code.Resource, toUnix(code.ExpiresAt), now)
	if err != nil {
		return r.c.mapErr(err)
	}
	code.CreatedAt = fromUnix(now)
	return nil
}

func (r *oauthAuthCodeRepo) Consume(ctx context.Context, id string, now time.Time) (*store.OAuthAuthCode, error) {
	row := r.c.queryRow(ctx, `DELETE FROM oauth_auth_codes
		WHERE id = ? AND expires_at > ?
		RETURNING id, user_id, client_id, redirect_uri, challenge, resource, expires_at, created_at`,
		id, toUnix(now))
	code := &store.OAuthAuthCode{}
	var expiresAt, createdAt int64
	if err := row.Scan(&code.ID, &code.UserID, &code.ClientID, &code.RedirectURI, &code.Challenge,
		&code.Resource, &expiresAt, &createdAt); err != nil {
		return nil, r.c.mapErr(err)
	}
	code.ExpiresAt, code.CreatedAt = fromUnix(expiresAt), fromUnix(createdAt)
	return code, nil
}

func (r *oauthAuthCodeRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.c.exec(ctx, `DELETE FROM oauth_auth_codes WHERE expires_at <= ?`, toUnix(now))
	if err != nil {
		return 0, r.c.mapErr(err)
	}
	return res.RowsAffected()
}
