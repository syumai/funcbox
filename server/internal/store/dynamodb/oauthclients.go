package dynamodb

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

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

// DeleteUnusedOlderThan has no client->grant/auth-code index in the
// single-table layout, so this is three full-table Scans (candidates,
// every grant's ClientID, every auth code's ClientID) -- acceptable at
// funcbox's expected scale, same tradeoff as oauthGrantRepo.ListByUser;
// see store.OAuthClientRepo.DeleteUnusedOlderThan's doc comment for why
// this needs to check both tables.
func (r *oauthClientRepo) DeleteUnusedOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	type candidate struct{ pk, sk, id string }
	var candidates []candidate
	err := r.s.scanPages(ctx, "Entity = :e AND CreatedAt <= :cutoff", map[string]types.AttributeValue{
		":e": stringAV(entityOAuthClient), ":cutoff": numberAV(toUnix(cutoff)),
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it oauthClientItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		pk, sk := itemKeyStrings(item)
		candidates = append(candidates, candidate{pk: pk, sk: sk, id: it.ID})
		return true, nil
	})
	if err != nil || len(candidates) == 0 {
		return 0, err
	}

	used := make(map[string]bool)
	collectClientIDs := func(entity string, clientIDOf func(map[string]types.AttributeValue) (string, error)) error {
		return r.s.scanPages(ctx, "Entity = :e", map[string]types.AttributeValue{":e": stringAV(entity)},
			func(item map[string]types.AttributeValue) (bool, error) {
				id, err := clientIDOf(item)
				if err != nil {
					return false, err
				}
				if id != "" {
					used[id] = true
				}
				return true, nil
			})
	}
	if err := collectClientIDs(entityOAuthGrant, func(item map[string]types.AttributeValue) (string, error) {
		var it oauthGrantItem
		err := unmarshalMap(item, &it)
		return it.ClientID, err
	}); err != nil {
		return 0, err
	}
	if err := collectClientIDs(entityOAuthAuthCode, func(item map[string]types.AttributeValue) (string, error) {
		var it oauthAuthCodeItem
		err := unmarshalMap(item, &it)
		return it.ClientID, err
	}); err != nil {
		return 0, err
	}

	var writes []types.WriteRequest
	for _, c := range candidates {
		if used[c.id] {
			continue
		}
		writes = append(writes, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: key(c.pk, c.sk)}})
	}
	if err := r.s.batchWrite(ctx, writes); err != nil {
		return 0, err
	}
	return int64(len(writes)), nil
}
