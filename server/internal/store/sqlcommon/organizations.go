package sqlcommon

import (
	"context"
	"fmt"

	"github.com/syumai/funcbox/internal/store"
)

type organizationRepo struct {
	c *conn
}

func (r *organizationRepo) Get(ctx context.Context) (*store.Organization, error) {
	row := r.c.queryRow(ctx,
		`SELECT id, name, settings, settings_gen, created_at, updated_at FROM organizations WHERE id = 'org'`)
	o := &store.Organization{}
	var createdAt, updatedAt int64
	if err := row.Scan(&o.ID, &o.Name, &o.Settings, &o.SettingsGen, &createdAt, &updatedAt); err != nil {
		return nil, r.c.mapErr(err)
	}
	o.CreatedAt, o.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return o, nil
}

func (r *organizationRepo) Update(ctx context.Context, o *store.Organization) error {
	now := nowUnix()
	res, err := r.c.exec(ctx,
		`UPDATE organizations SET name = ?, settings = ?, settings_gen = ?, updated_at = ? WHERE id = 'org'`,
		o.Name, o.Settings, o.SettingsGen, now)
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
	o.UpdatedAt = fromUnix(now)
	return nil
}

func (r *organizationRepo) ListLoginRules(ctx context.Context) ([]*store.LoginRule, error) {
	rows, err := r.c.query(ctx,
		`SELECT id, ord, rule_type, value, action, created_at, updated_at FROM login_rules ORDER BY ord ASC`)
	if err != nil {
		return nil, r.c.mapErr(err)
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
	tx, err := r.c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := r.c.execOn(ctx, tx, `DELETE FROM login_rules`); err != nil {
		return r.c.mapErr(err)
	}
	now := nowUnix()
	for _, lr := range rules {
		if lr.ID == "" {
			lr.ID = store.NewID()
		}
		if _, err := r.c.execOn(ctx, tx,
			`INSERT INTO login_rules (id, ord, rule_type, value, action, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			lr.ID, lr.Ord, lr.RuleType, lr.Value, lr.Action, now, now); err != nil {
			return r.c.mapErr(err)
		}
		lr.CreatedAt, lr.UpdatedAt = fromUnix(now), fromUnix(now)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlcommon: commit ReplaceLoginRules: %w", err)
	}
	return nil
}
