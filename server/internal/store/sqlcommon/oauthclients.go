package sqlcommon

import (
	"context"
	"encoding/json"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
)

type oauthClientRepo struct{ c *conn }

func (r *oauthClientRepo) Create(ctx context.Context, cl *store.OAuthClient) error {
	if cl.ID == "" {
		cl.ID = store.NewID()
	}
	redirectURIs, err := json.Marshal(cl.RedirectURIs)
	if err != nil {
		return err
	}
	now := nowUnix()
	if _, err := r.c.exec(ctx,
		`INSERT INTO oauth_clients (id, name, redirect_uris, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		cl.ID, cl.Name, string(redirectURIs), now, now); err != nil {
		return r.c.mapErr(err)
	}
	cl.CreatedAt, cl.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *oauthClientRepo) ByID(ctx context.Context, id string) (*store.OAuthClient, error) {
	row := r.c.queryRow(ctx,
		`SELECT id, name, redirect_uris, created_at, updated_at FROM oauth_clients WHERE id = ?`, id)
	return scanOAuthClient(r.c, row)
}

// DeleteUnusedOlderThan removes every client created at or before cutoff
// that no oauth_grant or oauth_auth_code row has ever referenced (both
// tables declare client_id REFERENCES oauth_clients(id), so an unused
// client also has no live foreign-key reference blocking its delete).
// oauth_auth_codes rows live only a few minutes (see that table's own
// opportunistic cleanup), so in practice the NOT EXISTS check against it
// only ever matters for a registration whose very first authorization is
// mid-flight at the exact moment this sweep runs.
func (r *oauthClientRepo) DeleteUnusedOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := r.c.exec(ctx, `DELETE FROM oauth_clients
		WHERE created_at <= ?
		AND NOT EXISTS (SELECT 1 FROM oauth_grants WHERE oauth_grants.client_id = oauth_clients.id)
		AND NOT EXISTS (SELECT 1 FROM oauth_auth_codes WHERE oauth_auth_codes.client_id = oauth_clients.id)`,
		toUnix(cutoff))
	if err != nil {
		return 0, r.c.mapErr(err)
	}
	return res.RowsAffected()
}

func scanOAuthClient(c *conn, row rowScanner) (*store.OAuthClient, error) {
	cl := &store.OAuthClient{}
	var redirectURIsJSON string
	var createdAt, updatedAt int64
	if err := row.Scan(&cl.ID, &cl.Name, &redirectURIsJSON, &createdAt, &updatedAt); err != nil {
		return nil, c.mapErr(err)
	}
	if err := json.Unmarshal([]byte(redirectURIsJSON), &cl.RedirectURIs); err != nil {
		return nil, err
	}
	cl.CreatedAt, cl.UpdatedAt = fromUnix(createdAt), fromUnix(updatedAt)
	return cl, nil
}
