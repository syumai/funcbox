package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/internal/store"
)

// handleRepo implements store.HandleRepo. Handles live at PK=HANDLE#<handle>
// SK=META; uniqueness of the handle string (shared by users and
// workspaces, per tmp/06-data-model.md's design notes) is enforced by a
// conditional PutItem.
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

func handleItemFrom(h *store.Handle, createdAt, updatedAt int64) *handleItem {
	return &handleItem{
		PK: pkHandle(h.Handle), SK: skMeta, Entity: entityHandle,
		Handle: h.Handle, OwnerType: string(h.OwnerType), OwnerID: h.OwnerID,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

func handleFromItem(it *handleItem) *store.Handle {
	return &store.Handle{
		Handle: it.Handle, OwnerType: store.OwnerType(it.OwnerType), OwnerID: it.OwnerID,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

func (r *handleRepo) Create(ctx context.Context, h *store.Handle) error {
	now := nowUnix()
	item, err := marshalMap(handleItemFrom(h, now, now))
	if err != nil {
		return err
	}
	if err := r.s.putItemIfNotExists(ctx, item); err != nil {
		return err
	}
	h.CreatedAt, h.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *handleRepo) ByHandle(ctx context.Context, handle string) (*store.Handle, error) {
	item, err := r.s.getItem(ctx, pkHandle(handle), skMeta)
	if err != nil {
		return nil, err
	}
	var it handleItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return handleFromItem(&it), nil
}

// ByOwner has no owner->handle lookup pointer item in the single-table
// layout (only the handle string itself is a partition key), so this is a
// full-table Scan with a FilterExpression; acceptable at funcbox's expected
// scale (each user/workspace has at most one handle, so results are always
// a single item). See this package's doc comment.
func (r *handleRepo) ByOwner(ctx context.Context, ownerType store.OwnerType, ownerID string) (*store.Handle, error) {
	var found *handleItem
	err := r.s.scanPages(ctx, "Entity = :e AND OwnerType = :ot AND OwnerID = :oid", map[string]types.AttributeValue{
		":e":   &types.AttributeValueMemberS{Value: entityHandle},
		":ot":  &types.AttributeValueMemberS{Value: string(ownerType)},
		":oid": &types.AttributeValueMemberS{Value: ownerID},
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
	return handleFromItem(found), nil
}

// Rename moves oldHandle's item to newHandle atomically: the old item is
// read (to preserve OwnerType/OwnerID/CreatedAt), then a TransactWriteItems
// call puts the new item (conditioned on non-existence, so a
// already-claimed newHandle fails with store.ErrConflict) and deletes the
// old one (conditioned on existence, catching a concurrent delete/rename
// racing this one).
func (r *handleRepo) Rename(ctx context.Context, oldHandle, newHandle string) error {
	old, err := r.ByHandle(ctx, oldHandle)
	if err != nil {
		return err
	}
	now := nowUnix()
	newItem, err := marshalMap(handleItemFrom(&store.Handle{Handle: newHandle, OwnerType: old.OwnerType, OwnerID: old.OwnerID}, toUnix(old.CreatedAt), now))
	if err != nil {
		return err
	}

	txErr := r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: newItem, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Delete: &types.Delete{TableName: aws.String(r.s.table), Key: key(pkHandle(oldHandle), skMeta), ConditionExpression: aws.String("attribute_exists(PK)")}},
	})
	if conditionalCheckFailedAt(txErr, 0) {
		return store.ErrConflict
	}
	if conditionalCheckFailedAt(txErr, 1) {
		return store.ErrNotFound
	}
	return txErr
}

func (r *handleRepo) Delete(ctx context.Context, handle string) error {
	return r.s.deleteItem(ctx, pkHandle(handle), skMeta)
}
