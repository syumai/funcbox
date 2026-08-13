package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// userRepo implements store.UserRepo. Each user is stored as a primary
// item at PK=USER#<id> SK=META, plus a "GSI-substitute" pointer item at
// PK=USER#SUB#<google_sub> SK=META (holding just the id) that makes
// ByGoogleSub a single GetItem instead of a Scan; see tmp/06-data-model.md.
type userRepo struct{ s *Store }

type userItem struct {
	PK        string
	SK        string
	Entity    string
	ID        string
	GoogleSub string
	Email     string
	Name      string
	Role      string
	Disabled  bool
	CreatedAt int64
	UpdatedAt int64
}

type userSubPointerItem struct {
	PK     string
	SK     string
	Entity string
	UserID string
}

func userItemFrom(u *store.User, now int64) *userItem {
	return &userItem{
		PK: pkUser(u.ID), SK: skMeta, Entity: entityUser,
		ID: u.ID, GoogleSub: u.GoogleSub, Email: u.Email, Name: u.Name,
		Role: string(u.Role), Disabled: u.Disabled, CreatedAt: toUnix(u.CreatedAt), UpdatedAt: now,
	}
}

func userFromItem(it *userItem) *store.User {
	return &store.User{
		ID: it.ID, GoogleSub: it.GoogleSub, Email: it.Email, Name: it.Name,
		Role: store.Role(it.Role), Disabled: it.Disabled,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

// Create writes the user's primary item and its google_sub lookup pointer
// atomically via TransactWriteItems, both conditioned on non-existence, so
// a racing duplicate id or google_sub fails the whole write with
// store.ErrConflict rather than leaving a dangling pointer.
func (r *userRepo) Create(ctx context.Context, u *store.User) error {
	if u.ID == "" {
		u.ID = store.NewID()
	}
	now := nowUnix()
	u.CreatedAt = fromUnix(now)

	userItemMap, err := marshalMap(userItemFrom(u, now))
	if err != nil {
		return err
	}
	ptr := &userSubPointerItem{PK: pkUserSub(u.GoogleSub), SK: skMeta, Entity: entityUserSubPointer, UserID: u.ID}
	ptrItemMap, err := marshalMap(ptr)
	if err != nil {
		return err
	}

	err = r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: userItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: ptrItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	})
	if transactionConditionFailed(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	u.UpdatedAt = fromUnix(now)
	return nil
}

func (r *userRepo) ByID(ctx context.Context, id string) (*store.User, error) {
	item, err := r.s.getItem(ctx, pkUser(id), skMeta)
	if err != nil {
		return nil, err
	}
	var it userItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return userFromItem(&it), nil
}

func (r *userRepo) ByGoogleSub(ctx context.Context, sub string) (*store.User, error) {
	item, err := r.s.getItem(ctx, pkUserSub(sub), skMeta)
	if err != nil {
		return nil, err
	}
	var ptr userSubPointerItem
	if err := unmarshalMap(item, &ptr); err != nil {
		return nil, err
	}
	return r.ByID(ctx, ptr.UserID)
}

// ByEmail has no lookup-pointer item in the single-table layout (see
// tmp/06-data-model.md: users only get a google_sub pointer, since that's
// the identity actually used to look a user up during login), so this is a
// full-table Scan with a FilterExpression. Acceptable at funcbox's expected
// scale; a real high-traffic deployment would add a GSI on email instead.
func (r *userRepo) ByEmail(ctx context.Context, email string) (*store.User, error) {
	var found *userItem
	err := r.s.scanPages(ctx, "Entity = :e AND Email = :email", map[string]types.AttributeValue{
		":e":     &types.AttributeValueMemberS{Value: entityUser},
		":email": &types.AttributeValueMemberS{Value: email},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it userItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		found = &it
		return false, nil // stop after first match
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, store.ErrNotFound
	}
	return userFromItem(found), nil
}

// Update overwrites the user's primary item. If GoogleSub is changing, the
// old USER#SUB#<old> pointer item is deleted and a new one created in the
// same TransactWriteItems call, keeping ByGoogleSub consistent; if it
// fails because the new google_sub is already claimed, that maps to
// store.ErrConflict same as Create's race handling.
func (r *userRepo) Update(ctx context.Context, u *store.User) error {
	existing, err := r.ByID(ctx, u.ID)
	if err != nil {
		return err
	}

	now := nowUnix()
	it := userItemFrom(u, now)
	it.CreatedAt = toUnix(existing.CreatedAt)
	userItemMap, err := marshalMap(it)
	if err != nil {
		return err
	}

	if existing.GoogleSub == u.GoogleSub {
		if err := r.s.putItemIfExists(ctx, userItemMap); err != nil {
			return err
		}
		u.CreatedAt, u.UpdatedAt = existing.CreatedAt, fromUnix(now)
		return nil
	}

	ptr := &userSubPointerItem{PK: pkUserSub(u.GoogleSub), SK: skMeta, Entity: entityUserSubPointer, UserID: u.ID}
	ptrItemMap, err := marshalMap(ptr)
	if err != nil {
		return err
	}
	txErr := r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: userItemMap, ConditionExpression: aws.String("attribute_exists(PK)")}},
		{Delete: &types.Delete{TableName: aws.String(r.s.table), Key: key(pkUserSub(existing.GoogleSub), skMeta)}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: ptrItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	})
	if conditionalCheckFailedAt(txErr, 0) {
		return store.ErrNotFound
	}
	if conditionalCheckFailedAt(txErr, 2) {
		return store.ErrConflict
	}
	if txErr != nil {
		return txErr
	}
	u.CreatedAt, u.UpdatedAt = existing.CreatedAt, fromUnix(now)
	return nil
}

func (r *userRepo) List(ctx context.Context) ([]*store.User, error) {
	var out []*store.User
	err := r.s.scanPages(ctx, "Entity = :e", map[string]types.AttributeValue{
		":e": &types.AttributeValueMemberS{Value: entityUser},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it userItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		out = append(out, userFromItem(&it))
		return true, nil
	})
	return out, err
}

// scanPages runs a full-table Scan with filterExpr/filterValues, paging
// through every segment and invoking visit for each matching item until it
// returns false or the scan is exhausted. Shared by every Scan-based list
// operation in this package (see the package doc comment for why they
// exist).
func (s *Store) scanPages(ctx context.Context, filterExpr string, values map[string]types.AttributeValue, visit func(item map[string]types.AttributeValue) (bool, error)) error {
	var startKey map[string]types.AttributeValue
	for {
		out, err := s.client.Scan(ctx, &dynamodb.ScanInput{
			TableName:                 aws.String(s.table),
			FilterExpression:          aws.String(filterExpr),
			ExpressionAttributeValues: values,
			ExclusiveStartKey:         startKey,
		})
		if err != nil {
			return err
		}
		for _, item := range out.Items {
			cont, err := visit(item)
			if err != nil {
				return err
			}
			if !cont {
				return nil
			}
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		startKey = out.LastEvaluatedKey
	}
}
