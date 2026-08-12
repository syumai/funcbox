package sqlite

import (
	"context"
	"database/sql"

	"github.com/syumai/funcbox/internal/store"
)

type handleRepo struct {
	db *sql.DB
}

func (r *handleRepo) Create(ctx context.Context, h *store.Handle) error {
	now := nowUnix()
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO handles (handle, owner_type, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		h.Handle, h.OwnerType, h.OwnerID, now, now); err != nil {
		return mapErr(err)
	}
	h.CreatedAt, h.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *handleRepo) ByHandle(ctx context.Context, handle string) (*store.Handle, error) {
	return scanHandle(r.db.QueryRowContext(ctx,
		`SELECT handle, owner_type, owner_id, created_at, updated_at FROM handles WHERE handle = ?`, handle))
}

func (r *handleRepo) ByOwner(ctx context.Context, ownerType store.OwnerType, ownerID string) (*store.Handle, error) {
	return scanHandle(r.db.QueryRowContext(ctx,
		`SELECT handle, owner_type, owner_id, created_at, updated_at FROM handles WHERE owner_type = ? AND owner_id = ?`,
		ownerType, ownerID))
}

func (r *handleRepo) Rename(ctx context.Context, oldHandle, newHandle string) error {
	now := nowUnix()
	res, err := r.db.ExecContext(ctx,
		`UPDATE handles SET handle = ?, updated_at = ? WHERE handle = ?`, newHandle, now, oldHandle)
	if err != nil {
		return mapErr(err)
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

func (r *handleRepo) Delete(ctx context.Context, handle string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM handles WHERE handle = ?`, handle); err != nil {
		return mapErr(err)
	}
	return nil
}

func scanHandle(row rowScanner) (*store.Handle, error) {
	h := &store.Handle{}
	var createdAt, updatedAt int64
	if err := row.Scan(&h.Handle, &h.OwnerType, &h.OwnerID, &createdAt, &updatedAt); err != nil {
		return nil, mapErr(err)
	}
	h.CreatedAt, h.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return h, nil
}
