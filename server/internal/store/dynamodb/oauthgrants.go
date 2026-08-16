package dynamodb

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// oauthGrantRepo implements store.OAuthGrantRepo, mirroring
// cliCredentialRepo's PK=OAUTHGRANT#<hash> + by-id lookup pointer
// (PK=OAUTHGRANTID#<id>) pattern exactly -- see that repo's doc comment.
type oauthGrantRepo struct{ s *Store }

type oauthGrantItem struct {
	PK, SK, Entity string
	ID             string
	UserID         string
	ClientID       string
	SecretHash     string
	CreatedAt      int64
	UpdatedAt      int64
	LastUsedAt     int64 // 0 means "never used" (OAuthGrant.LastUsedAt zero value)
}

type oauthGrantIDPointerItem struct {
	PK, SK, Entity string
	SecretHash     string
}

func oauthGrantFromItem(it *oauthGrantItem) *store.OAuthGrant {
	g := &store.OAuthGrant{
		ID: it.ID, UserID: it.UserID, ClientID: it.ClientID, SecretHash: it.SecretHash,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
	if it.LastUsedAt != 0 {
		g.LastUsedAt = fromUnix(it.LastUsedAt)
	}
	return g
}

// Create writes the primary OAUTHGRANT#<hash> item and its
// OAUTHGRANTID#<id> lookup pointer atomically via TransactWriteItems, both
// conditioned on non-existence -- mirrors cliCredentialRepo.Create.
func (r *oauthGrantRepo) Create(ctx context.Context, g *store.OAuthGrant) error {
	if g.ID == "" {
		g.ID = store.NewID()
	}
	now := nowUnix()
	grantItemMap, err := marshalMap(&oauthGrantItem{
		PK: pkOAuthGrant(g.SecretHash), SK: skMeta, Entity: entityOAuthGrant,
		ID: g.ID, UserID: g.UserID, ClientID: g.ClientID, SecretHash: g.SecretHash,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	ptrItemMap, err := marshalMap(&oauthGrantIDPointerItem{
		PK: pkOAuthGrantID(g.ID), SK: skMeta, Entity: entityOAuthGrant, SecretHash: g.SecretHash,
	})
	if err != nil {
		return err
	}

	err = r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: grantItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: ptrItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	})
	if transactionConditionFailed(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	g.CreatedAt, g.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *oauthGrantRepo) ByHash(ctx context.Context, secretHash string) (*store.OAuthGrant, error) {
	item, err := r.s.getItem(ctx, pkOAuthGrant(secretHash), skMeta)
	if err != nil {
		return nil, err
	}
	var it oauthGrantItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return oauthGrantFromItem(&it), nil
}

// ListByUser has no user->grants index in the single-table layout, so this
// is a full-table Scan with a FilterExpression -- acceptable at funcbox's
// expected scale, same as cliCredentialRepo.ListByUser.
func (r *oauthGrantRepo) ListByUser(ctx context.Context, userID string) ([]*store.OAuthGrant, error) {
	var out []*store.OAuthGrant
	err := r.s.scanPages(ctx, "Entity = :e AND UserID = :uid", map[string]types.AttributeValue{
		":e":   &types.AttributeValueMemberS{Value: entityOAuthGrant},
		":uid": &types.AttributeValueMemberS{Value: userID},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it oauthGrantItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		out = append(out, oauthGrantFromItem(&it))
		return true, nil
	})
	return out, err
}

// Touch advances the primary item's LastUsedAt via the by-id pointer.
func (r *oauthGrantRepo) Touch(ctx context.Context, id string, now time.Time) error {
	ptr, err := r.pointer(ctx, id)
	if err != nil {
		return err
	}
	nowU := toUnix(now)
	upd := expression.Set(expression.Name("LastUsedAt"), expression.Value(nowU)).
		Set(expression.Name("UpdatedAt"), expression.Value(nowU))
	return r.s.updateItemIfExists(ctx, pkOAuthGrant(ptr.SecretHash), skMeta, upd)
}

// Delete removes both the primary and pointer items. A nonexistent id is a
// silent no-op, matching the SQL backends.
func (r *oauthGrantRepo) Delete(ctx context.Context, id string) error {
	ptr, err := r.pointer(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	writes := []types.WriteRequest{
		{DeleteRequest: &types.DeleteRequest{Key: key(pkOAuthGrant(ptr.SecretHash), skMeta)}},
		{DeleteRequest: &types.DeleteRequest{Key: key(pkOAuthGrantID(id), skMeta)}},
	}
	return r.s.batchWrite(ctx, writes)
}

func (r *oauthGrantRepo) pointer(ctx context.Context, id string) (*oauthGrantIDPointerItem, error) {
	item, err := r.s.getItem(ctx, pkOAuthGrantID(id), skMeta)
	if err != nil {
		return nil, err
	}
	var ptr oauthGrantIDPointerItem
	if err := unmarshalMap(item, &ptr); err != nil {
		return nil, err
	}
	return &ptr, nil
}
