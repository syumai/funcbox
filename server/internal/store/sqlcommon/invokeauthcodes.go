package sqlcommon

import (
	"context"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

type invokeAuthCodeRepo struct{ c *conn }

func (r *invokeAuthCodeRepo) Create(ctx context.Context, code *store.InvokeAuthCode) error {
	now := nowUnix()
	// Codes live for only a minute. Opportunistic cleanup on issuance keeps
	// SQL installations bounded without requiring another background worker;
	// DynamoDB uses its TTL attribute for the equivalent lifecycle.
	if _, err := r.c.exec(ctx, `DELETE FROM invoke_auth_codes WHERE expires_at <= ?`, now); err != nil {
		return r.c.mapErr(err)
	}
	_, err := r.c.exec(ctx, `INSERT INTO invoke_auth_codes
		(id, user_id, function_id, host, return_to, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, code.ID, code.UserID, code.FunctionID,
		code.Host, code.ReturnTo, toUnix(code.ExpiresAt), now)
	if err != nil {
		return r.c.mapErr(err)
	}
	code.CreatedAt = fromUnix(now)
	return nil
}

func (r *invokeAuthCodeRepo) Consume(ctx context.Context, id, functionID, host string, now time.Time) (*store.InvokeAuthCode, error) {
	row := r.c.queryRow(ctx, `DELETE FROM invoke_auth_codes
		WHERE id = ? AND function_id = ? AND host = ? AND expires_at > ?
		RETURNING id, user_id, function_id, host, return_to, expires_at, created_at`,
		id, functionID, host, toUnix(now))
	code := &store.InvokeAuthCode{}
	var expiresAt, createdAt int64
	if err := row.Scan(&code.ID, &code.UserID, &code.FunctionID, &code.Host,
		&code.ReturnTo, &expiresAt, &createdAt); err != nil {
		return nil, r.c.mapErr(err)
	}
	code.ExpiresAt, code.CreatedAt = fromUnix(expiresAt), fromUnix(createdAt)
	return code, nil
}

func (r *invokeAuthCodeRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.c.exec(ctx, `DELETE FROM invoke_auth_codes WHERE expires_at <= ?`, toUnix(now))
	if err != nil {
		return 0, r.c.mapErr(err)
	}
	return res.RowsAffected()
}
