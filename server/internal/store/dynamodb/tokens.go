package dynamodb

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// tokenRepo implements store.TokenRepo. Tokens live at PK=TOKEN#<hash>
// SK=META, per tmp/06-data-model.md, giving ByHash a plain GetItem. Delete
// is handed only an id (not a hash), so a lookup pointer item at
// PK=TOKENID#<id> SK=META (this package's addition; see pkTokenID's doc
// comment) makes that a GetItem too instead of a Scan.
type tokenRepo struct{ s *Store }

type tokenItem struct {
	PK        string
	SK        string
	Entity    string
	ID        string
	UserID    string
	TokenHash string
	Name      string
	ExpiresAt int64
	CreatedAt int64
	UpdatedAt int64
}

type tokenIDPointerItem struct {
	PK        string
	SK        string
	Entity    string
	TokenHash string
}

func tokenFromItem(it *tokenItem) *store.APIToken {
	return &store.APIToken{
		ID: it.ID, UserID: it.UserID, TokenHash: it.TokenHash, Name: it.Name,
		ExpiresAt: fromUnix(it.ExpiresAt), CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

// Create writes the primary TOKEN#<hash> item and its TOKENID#<id> lookup
// pointer atomically via TransactWriteItems, both conditioned on
// non-existence.
func (r *tokenRepo) Create(ctx context.Context, t *store.APIToken) error {
	if t.ID == "" {
		t.ID = store.NewID()
	}
	now := nowUnix()
	tokenItemMap, err := marshalMap(&tokenItem{
		PK: pkToken(t.TokenHash), SK: skMeta, Entity: entityAPIToken,
		ID: t.ID, UserID: t.UserID, TokenHash: t.TokenHash, Name: t.Name,
		ExpiresAt: toUnix(t.ExpiresAt), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	ptrItemMap, err := marshalMap(&tokenIDPointerItem{
		PK: pkTokenID(t.ID), SK: skMeta, Entity: entityAPIToken, TokenHash: t.TokenHash,
	})
	if err != nil {
		return err
	}

	err = r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: tokenItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: ptrItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	})
	if transactionConditionFailed(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	t.CreatedAt, t.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *tokenRepo) ByHash(ctx context.Context, tokenHash string) (*store.APIToken, error) {
	item, err := r.s.getItem(ctx, pkToken(tokenHash), skMeta)
	if err != nil {
		return nil, err
	}
	var it tokenItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return tokenFromItem(&it), nil
}

// ListByUser has no user->tokens index in the single-table layout, so this
// is a full-table Scan with a FilterExpression; acceptable at funcbox's
// expected scale (a handful of tokens per user). See this package's doc
// comment.
func (r *tokenRepo) ListByUser(ctx context.Context, userID string) ([]*store.APIToken, error) {
	var out []*store.APIToken
	err := r.s.scanPages(ctx, "Entity = :e AND UserID = :uid", map[string]types.AttributeValue{
		":e":   &types.AttributeValueMemberS{Value: entityAPIToken},
		":uid": &types.AttributeValueMemberS{Value: userID},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it tokenItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		out = append(out, tokenFromItem(&it))
		return true, nil
	})
	return out, err
}

// Delete removes both the primary and pointer items. A nonexistent id is a
// silent no-op, matching the SQL backends (a DELETE affecting zero rows is
// not an error).
func (r *tokenRepo) Delete(ctx context.Context, id string) error {
	item, err := r.s.getItem(ctx, pkTokenID(id), skMeta)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var ptr tokenIDPointerItem
	if err := unmarshalMap(item, &ptr); err != nil {
		return err
	}
	writes := []types.WriteRequest{
		{DeleteRequest: &types.DeleteRequest{Key: key(pkToken(ptr.TokenHash), skMeta)}},
		{DeleteRequest: &types.DeleteRequest{Key: key(pkTokenID(id), skMeta)}},
	}
	return r.s.batchWrite(ctx, writes)
}
