package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/syumai/funcbox/internal/store"
)

type organizationRepo struct {
	db *sql.DB
}

func (r *organizationRepo) Get(ctx context.Context) (*store.Organization, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, settings, settings_gen, created_at, updated_at FROM organizations WHERE id = 'org'`)
	o := &store.Organization{}
	var createdAt, updatedAt int64
	if err := row.Scan(&o.ID, &o.Name, &o.Settings, &o.SettingsGen, &createdAt, &updatedAt); err != nil {
		return nil, mapErr(err)
	}
	o.CreatedAt, o.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return o, nil
}

func (r *organizationRepo) Update(ctx context.Context, o *store.Organization) error {
	now := nowUnix()
	res, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET name = ?, settings = ?, settings_gen = ?, updated_at = ? WHERE id = 'org'`,
		o.Name, o.Settings, o.SettingsGen, now)
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
	o.UpdatedAt = fromUnix(now)
	return nil
}

func (r *organizationRepo) ListLoginRules(ctx context.Context) ([]*store.LoginRule, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, ord, rule_type, value, action, created_at, updated_at FROM login_rules ORDER BY ord ASC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var rules []*store.LoginRule
	for rows.Next() {
		lr := &store.LoginRule{}
		var createdAt, updatedAt int64
		if err := rows.Scan(&lr.ID, &lr.Ord, &lr.RuleType, &lr.Value, &lr.Action, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		lr.CreatedAt, lr.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
		rules = append(rules, lr)
	}
	return rules, rows.Err()
}

func (r *organizationRepo) ReplaceLoginRules(ctx context.Context, rules []*store.LoginRule) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `DELETE FROM login_rules`); err != nil {
		return mapErr(err)
	}
	now := nowUnix()
	for _, lr := range rules {
		if lr.ID == "" {
			lr.ID = store.NewID()
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO login_rules (id, ord, rule_type, value, action, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			lr.ID, lr.Ord, lr.RuleType, lr.Value, lr.Action, now, now); err != nil {
			return mapErr(err)
		}
		lr.CreatedAt, lr.UpdatedAt = fromUnix(now), fromUnix(now)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlite: commit ReplaceLoginRules: %w", err)
	}
	return nil
}
