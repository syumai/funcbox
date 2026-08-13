package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// handleRepo stores public User IDs using legacy physical attribute names.
// Records live at PK=HANDLE#<user-id>, SK=META; legacy workspace
// records are removed by the startup migration and rejected on lookup.
type handleRepo struct{ s *Store }

type handleItem struct {
	PK        string
	SK        string
	Entity    string
	Handle    string
	OwnerType string
	OwnerID   string
	CreatedAt int64
	UpdatedAt int64
}

func handleItemFrom(id *store.PublicUserID, createdAt, updatedAt int64) *handleItem {
	return &handleItem{
		PK: pkHandle(id.UserID), SK: skMeta, Entity: entityHandle,
		Handle: id.UserID, OwnerType: string(store.OwnerTypeUser), OwnerID: id.InternalUserID,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

func publicUserIDFromItem(it *handleItem) *store.PublicUserID {
	return &store.PublicUserID{
		UserID: it.Handle, InternalUserID: it.OwnerID,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

func (r *handleRepo) Create(ctx context.Context, id *store.PublicUserID) error {
	now := nowUnix()
	item, err := marshalMap(handleItemFrom(id, now, now))
	if err != nil {
		return err
	}
	if err := r.s.putItemIfNotExists(ctx, item); err != nil {
		return err
	}
	id.CreatedAt, id.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *handleRepo) ByUserID(ctx context.Context, userID string) (*store.PublicUserID, error) {
	item, err := r.s.getItem(ctx, pkHandle(userID), skMeta)
	if err != nil {
		return nil, err
	}
	var it handleItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	if store.OwnerType(it.OwnerType) != store.OwnerTypeUser {
		return nil, store.ErrNotFound
	}
	return publicUserIDFromItem(&it), nil
}

// ByOwner has no owner->handle lookup pointer item in the single-table
// layout (only the handle string itself is a partition key), so this is a
// full-table Scan with a FilterExpression; acceptable at funcbox's expected
// scale (each user has at most one public User ID, so results are always
// a single item). See this package's doc comment.
func (r *handleRepo) ByOwner(ctx context.Context, internalUserID string) (*store.PublicUserID, error) {
	var found *handleItem
	err := r.s.scanPages(ctx, "Entity = :e AND OwnerType = :ot AND OwnerID = :oid", map[string]types.AttributeValue{
		":e":   &types.AttributeValueMemberS{Value: entityHandle},
		":ot":  &types.AttributeValueMemberS{Value: string(store.OwnerTypeUser)},
		":oid": &types.AttributeValueMemberS{Value: internalUserID},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it handleItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		found = &it
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, store.ErrNotFound
	}
	return publicUserIDFromItem(found), nil
}

// Rename moves the old User ID's item to the new User ID atomically: the old item is
// read (to preserve OwnerType/OwnerID/CreatedAt), then a TransactWriteItems
// call puts the new item (conditioned on non-existence, so a
// already-claimed new User ID fails with store.ErrConflict) and deletes the
// old one (conditioned on existence, catching a concurrent delete/rename
// racing this one).
func (r *handleRepo) Rename(ctx context.Context, oldUserID, newUserID string) error {
	old, err := r.ByUserID(ctx, oldUserID)
	if err != nil {
		return err
	}
	now := nowUnix()
	newItem, err := marshalMap(handleItemFrom(&store.PublicUserID{UserID: newUserID, InternalUserID: old.InternalUserID}, toUnix(old.CreatedAt), now))
	if err != nil {
		return err
	}

	txErr := r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: newItem, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Delete: &types.Delete{TableName: aws.String(r.s.table), Key: key(pkHandle(oldUserID), skMeta), ConditionExpression: aws.String("attribute_exists(PK)")}},
	})
	if conditionalCheckFailedAt(txErr, 0) {
		return store.ErrConflict
	}
	if conditionalCheckFailedAt(txErr, 1) {
		return store.ErrNotFound
	}
	return txErr
}

func (r *handleRepo) Delete(ctx context.Context, userID string) error {
	return r.s.deleteItem(ctx, pkHandle(userID), skMeta)
}
