package sqlcommon

import (
	"context"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

type cliAuthCodeRepo struct{ c *conn }

func (r *cliAuthCodeRepo) Create(ctx context.Context, code *store.CLIAuthCode) error {
	now := nowUnix()
	// Codes live for only a few minutes; opportunistic cleanup on issuance
	// keeps SQL installations bounded without a background worker, same as
	// invokeAuthCodeRepo.Create.
	if _, err := r.c.exec(ctx, `DELETE FROM cli_auth_codes WHERE expires_at <= ?`, now); err != nil {
		return r.c.mapErr(err)
	}
	_, err := r.c.exec(ctx, `INSERT INTO cli_auth_codes
		(id, user_id, name, challenge, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, code.ID, code.UserID, code.Name, code.Challenge, toUnix(code.ExpiresAt), now)
	if err != nil {
		return r.c.mapErr(err)
	}
	code.CreatedAt = fromUnix(now)
	return nil
}

func (r *cliAuthCodeRepo) Consume(ctx context.Context, id string, now time.Time) (*store.CLIAuthCode, error) {
	row := r.c.queryRow(ctx, `DELETE FROM cli_auth_codes
		WHERE id = ? AND expires_at > ?
		RETURNING id, user_id, name, challenge, expires_at, created_at`,
		id, toUnix(now))
	code := &store.CLIAuthCode{}
	var expiresAt, createdAt int64
	if err := row.Scan(&code.ID, &code.UserID, &code.Name, &code.Challenge, &expiresAt, &createdAt); err != nil {
		return nil, r.c.mapErr(err)
	}
	code.ExpiresAt, code.CreatedAt = fromUnix(expiresAt), fromUnix(createdAt)
	return code, nil
}

func (r *cliAuthCodeRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.c.exec(ctx, `DELETE FROM cli_auth_codes WHERE expires_at <= ?`, toUnix(now))
	if err != nil {
		return 0, r.c.mapErr(err)
	}
	return res.RowsAffected()
}
