package sqlcommon

import (
	"context"
	"encoding/json"

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
