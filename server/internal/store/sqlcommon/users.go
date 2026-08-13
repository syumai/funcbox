package sqlcommon

import (
	"context"

	"github.com/syumai/funcbox/server/internal/store"
)

type userRepo struct {
	c *conn
}

func (r *userRepo) Create(ctx context.Context, u *store.User) error {
	if u.ID == "" {
		u.ID = store.NewID()
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO users (id, google_sub, email, name, role, disabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.GoogleSub, u.Email, u.Name, u.Role, boolToInt(u.Disabled), now, now); err != nil {
		return r.c.mapErr(err)
	}
	u.CreatedAt, u.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *userRepo) ByID(ctx context.Context, id string) (*store.User, error) {
	return r.scanOne(r.c.queryRow(ctx,
		`SELECT id, google_sub, email, name, role, disabled, created_at, updated_at FROM users WHERE id = ?`, id))
}

func (r *userRepo) ByGoogleSub(ctx context.Context, sub string) (*store.User, error) {
	return r.scanOne(r.c.queryRow(ctx,
		`SELECT id, google_sub, email, name, role, disabled, created_at, updated_at FROM users WHERE google_sub = ?`, sub))
}

func (r *userRepo) ByEmail(ctx context.Context, email string) (*store.User, error) {
	return r.scanOne(r.c.queryRow(ctx,
		`SELECT id, google_sub, email, name, role, disabled, created_at, updated_at FROM users WHERE email = ?`, email))
}

func (r *userRepo) Update(ctx context.Context, u *store.User) error {
	now := nowUnix()
	res, err := r.c.exec(ctx,
		`UPDATE users SET google_sub = ?, email = ?, name = ?, role = ?, disabled = ?, updated_at = ? WHERE id = ?`,
		u.GoogleSub, u.Email, u.Name, u.Role, boolToInt(u.Disabled), now, u.ID)
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
	u.UpdatedAt = fromUnix(now)
	return nil
}

func (r *userRepo) List(ctx context.Context) ([]*store.User, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, google_sub, email, name, role, disabled, created_at, updated_at FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	defer rows.Close()

	var users []*store.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *userRepo) scanOne(row rowScanner) (*store.User, error) {
	u, err := scanUser(row)
	if err != nil {
		return nil, r.c.mapErr(err)
	}
	return u, nil
}

func scanUser(row rowScanner) (*store.User, error) {
	u := &store.User{}
	var disabled int
	var createdAt, updatedAt int64
	if err := row.Scan(&u.ID, &u.GoogleSub, &u.Email, &u.Name, &u.Role, &disabled, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.CreatedAt, u.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return u, nil
}
