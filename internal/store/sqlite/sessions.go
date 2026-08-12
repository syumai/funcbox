package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/syumai/funcbox/internal/store"
)

type sessionRepo struct {
	db *sql.DB
}

func (r *sessionRepo) Create(ctx context.Context, s *store.Session) error {
	if s.ID == "" {
		s.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		s.ID, s.UserID, toUnix(s.ExpiresAt), now, now); err != nil {
		return mapErr(err)
	}
	s.CreatedAt, s.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

// Get returns the session if it exists and has not expired as of now. See
// store.SessionRepo.Get doc comment for why expiry is folded into
// ErrNotFound rather than reported separately.
func (r *sessionRepo) Get(ctx context.Context, id string, now time.Time) (*store.Session, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, expires_at, created_at, updated_at FROM sessions WHERE id = ? AND expires_at > ?`,
		id, toUnix(now))
	s := &store.Session{}
	var expiresAt, createdAt, updatedAt int64
	if err := row.Scan(&s.ID, &s.UserID, &expiresAt, &createdAt, &updatedAt); err != nil {
		return nil, mapErr(err)
	}
	s.ExpiresAt = fromUnix(expiresAt)
	s.CreatedAt, s.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return s, nil
}

func (r *sessionRepo) Delete(ctx context.Context, id string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id); err != nil {
		return mapErr(err)
	}
	return nil
}

func (r *sessionRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, toUnix(now))
	if err != nil {
		return 0, mapErr(err)
	}
	return res.RowsAffected()
}
