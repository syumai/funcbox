package dynamodb

import (
	"context"

	"github.com/syumai/funcbox/server/internal/store"
)

type oauthClientRepo struct{ s *Store }

type oauthClientItem struct {
	PK, SK, Entity       string
	ID, Name             string
	RedirectURIs         []string
	CreatedAt, UpdatedAt int64
}

func oauthClientFromItem(it *oauthClientItem) *store.OAuthClient {
	return &store.OAuthClient{
		ID: it.ID, Name: it.Name, RedirectURIs: it.RedirectURIs,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

func (r *oauthClientRepo) Create(ctx context.Context, cl *store.OAuthClient) error {
	if cl.ID == "" {
		cl.ID = store.NewID()
	}
	now := nowUnix()
	item, err := marshalMap(&oauthClientItem{
		PK: pkOAuthClient(cl.ID), SK: skMeta, Entity: entityOAuthClient,
		ID: cl.ID, Name: cl.Name, RedirectURIs: cl.RedirectURIs, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	if err := r.s.putItemIfNotExists(ctx, item); err != nil {
		return err
	}
	cl.CreatedAt, cl.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *oauthClientRepo) ByID(ctx context.Context, id string) (*store.OAuthClient, error) {
	item, err := r.s.getItem(ctx, pkOAuthClient(id), skMeta)
	if err != nil {
		return nil, err
	}
	var it oauthClientItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return oauthClientFromItem(&it), nil
}
