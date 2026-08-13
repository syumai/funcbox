package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/internal/store"
)

// BootstrapFirstUser atomically creates the singleton organization and
// promotes u to admin, but only for the very first caller — see this
// method's doc comment on store.Store for the exact concurrency contract
// it must satisfy (storetest's BootstrapFirstUserConcurrent races 8
// callers and requires exactly 1 success).
//
// DynamoDB has no cross-partition "is the users table empty" check
// equivalent to SQL's SELECT COUNT(*) inside a transaction, so this uses a
// dedicated singleton lock item (PK=ORG SK=BOOTSTRAP_LOCK — this package's
// addition beyond tmp/06-data-model.md's table, called out in the task
// this package was built against) as the race's single point of
// arbitration: a TransactWriteItems call puts the lock item conditioned on
// attribute_not_exists(PK) as its first operation, alongside creating the
// organization and the user. TransactWriteItems is all-or-nothing, so only
// the caller whose lock-item Put wins the race gets its org/user Puts
// applied too; every other caller's whole transaction is cancelled with a
// ConditionalCheckFailedException on that first item, mapped to
// store.ErrConflict. No further condition is needed on the org/user Puts
// themselves (they're unconditioned): by the time a transaction reaches
// them, the lock condition already proved this is the unique winner, so a
// second admin can never "sneak through" this path — the separate,
// non-racy path of Users().Create being called again afterward is exactly
// the ordinary duplicate-google_sub/email conflict path that method's own
// TransactWriteItems handles.
func (s *Store) BootstrapFirstUser(ctx context.Context, u *store.User, orgName string) error {
	now := nowUnix()

	lockItem, err := marshalMap(struct {
		PK, SK, Entity string
	}{pkOrg, skBootstrapLock, entityBootstrapLock})
	if err != nil {
		return err
	}

	orgItemMap, err := marshalMap(&orgItem{
		PK: pkOrg, SK: skMeta, Entity: entityOrganization,
		ID: "org", Name: orgName, Settings: []byte("{}"), SettingsGen: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}

	if u.ID == "" {
		u.ID = store.NewID()
	}
	u.Role = store.RoleAdmin
	userItemMap, err := marshalMap(userItemFrom(u, now))
	if err != nil {
		return err
	}
	ptrItemMap, err := marshalMap(&userSubPointerItem{PK: pkUserSub(u.GoogleSub), SK: skMeta, Entity: entityUserSubPointer, UserID: u.ID})
	if err != nil {
		return err
	}

	err = s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(s.table), Item: lockItem, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(s.table), Item: orgItemMap}},
		{Put: &types.Put{TableName: aws.String(s.table), Item: userItemMap}},
		{Put: &types.Put{TableName: aws.String(s.table), Item: ptrItemMap}},
	})
	if transactionConditionFailed(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	u.CreatedAt, u.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

// ActivateVersion verifies versionID belongs to funcID and repoints
// Function.ActiveVersionID at it.
//
// This reads the version outside of any transaction (Functions().Version,
// a plain GetItem on the global VER#<id> pointer item) and then issues a
// single conditional UpdateItem on the function's own item — not a
// multi-item TransactWriteItems. That's sufficient for the atomicity
// storetest actually requires (activating a version belonging to a
// *different* function must return ErrNotFound and must leave the
// function's active_version_id untouched): FunctionVersion rows are
// immutable once created (see that type's doc comment), so there is no
// concurrent write that could change which function a version belongs to
// between the read and the conditional write. The UpdateItem's own
// ConditionExpression (attribute_exists(PK)) still atomically guards
// against funcID not existing (or having been deleted concurrently),
// which is the only genuinely racy part of this operation.
func (s *Store) ActivateVersion(ctx context.Context, funcID, versionID string) error {
	v, err := s.functions.Version(ctx, versionID)
	if err != nil {
		return err
	}
	if v.FunctionID != funcID {
		return store.ErrNotFound
	}

	now := nowUnix()
	upd := expression.Set(expression.Name("ActiveVersionID"), expression.Value(versionID)).
		Set(expression.Name("UpdatedAt"), expression.Value(now))
	return s.updateItemIfExists(ctx, pkFunc(funcID), skMeta, upd)
}

// CreateWorkspace atomically creates ws, claims handle for it, and adds
// creatorUserID as an admin member, via a single TransactWriteItems call.
// The handle Put is conditioned on non-existence (attribute_not_exists(PK)),
// the same conditional-write pattern HandleRepo.Create uses standalone —
// this is what makes storetest's handle-uniqueness test pass here too
// (claiming a handle already used by a user, or by another workspace,
// fails this whole call with store.ErrConflict, leaving no partially
// created workspace behind).
func (s *Store) CreateWorkspace(ctx context.Context, ws *store.Workspace, handle string, creatorUserID string) error {
	if ws.ID == "" {
		ws.ID = store.NewID()
	}
	now := nowUnix()

	wsItemMap, err := marshalMap(workspaceItemFrom(ws, now, now))
	if err != nil {
		return err
	}
	handleItemMap, err := marshalMap(handleItemFrom(&store.Handle{Handle: handle, OwnerType: store.OwnerTypeWorkspace, OwnerID: ws.ID}, now, now))
	if err != nil {
		return err
	}
	memberItemMap, err := marshalMap(&workspaceMemberItem{
		PK: pkWorkspace(ws.ID), SK: skMember(creatorUserID), Entity: entityWorkspaceMember,
		WorkspaceID: ws.ID, UserID: creatorUserID, Role: string(store.RoleAdmin), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}

	err = s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(s.table), Item: wsItemMap}},
		{Put: &types.Put{TableName: aws.String(s.table), Item: handleItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(s.table), Item: memberItemMap}},
	})
	if transactionConditionFailed(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	ws.CreatedAt, ws.UpdatedAt = fromUnix(now), fromUnix(now)
	if ws.Settings == nil {
		ws.Settings = []byte("{}")
	}
	if ws.SettingsGen == 0 {
		ws.SettingsGen = 1
	}
	return nil
}
