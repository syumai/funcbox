package sqlcommon

import (
	"context"

	"github.com/syumai/funcbox/server/internal/store"
)

type handleRepo struct {
	c *conn
}

func (r *handleRepo) Create(ctx context.Context, id *store.PublicUserID) error {
	now := nowUnix()
	// The handles table and its columns are legacy physical schema names.
	if _, err := r.c.exec(ctx,
		`INSERT INTO handles (handle, owner_type, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		id.UserID, store.OwnerTypeUser, id.InternalUserID, now, now); err != nil {
		return r.c.mapErr(err)
	}
	id.CreatedAt, id.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *handleRepo) ByUserID(ctx context.Context, userID string) (*store.PublicUserID, error) {
	id, ownerType, err := scanPublicUserID(r.c, r.c.queryRow(ctx,
		`SELECT handle, owner_type, owner_id, created_at, updated_at FROM handles WHERE handle = ?`, userID))
	if err != nil {
		return nil, err
	}
	if ownerType != store.OwnerTypeUser {
		return nil, store.ErrNotFound
	}
	return id, nil
}

func (r *handleRepo) ByOwner(ctx context.Context, internalUserID string) (*store.PublicUserID, error) {
	id, _, err := scanPublicUserID(r.c, r.c.queryRow(ctx,
		`SELECT handle, owner_type, owner_id, created_at, updated_at FROM handles WHERE owner_type = ? AND owner_id = ?`,
		store.OwnerTypeUser, internalUserID))
	return id, err
}

func (r *handleRepo) Rename(ctx context.Context, oldUserID, newUserID string) error {
	now := nowUnix()
	res, err := r.c.exec(ctx,
		`UPDATE handles SET handle = ?, updated_at = ? WHERE handle = ?`, newUserID, now, oldUserID)
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

func (r *handleRepo) Delete(ctx context.Context, userID string) error {
	if _, err := r.c.exec(ctx, `DELETE FROM handles WHERE handle = ?`, userID); err != nil {
		return r.c.mapErr(err)
	}
	return nil
}

func scanPublicUserID(c *conn, row rowScanner) (*store.PublicUserID, store.OwnerType, error) {
	id := &store.PublicUserID{}
	var ownerType store.OwnerType
	var createdAt, updatedAt int64
	if err := row.Scan(&id.UserID, &ownerType, &id.InternalUserID, &createdAt, &updatedAt); err != nil {
		return nil, "", c.mapErr(err)
	}
	id.CreatedAt, id.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return id, ownerType, nil
}
