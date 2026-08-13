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

// cliCredentialRepo implements store.CLICredentialRepo. Credentials live
// at PK=CLICRED#<hash> is handed only an id (Touch/Delete), so a lookup
// pointer item at PK=CLICREDID#<id> SK=META (this package's addition; see
// pkCLICredentialID's doc comment) makes those a GetItem too instead of a
// Scan -- the same pattern the retired api_token repo used.
type cliCredentialRepo struct{ s *Store }

type cliCredentialItem struct {
	PK, SK, Entity string
	ID             string
	UserID         string
	Name           string
	SecretHash     string
	CreatedAt      int64
	UpdatedAt      int64
	LastUsedAt     int64 // 0 means "never used" (CLICredential.LastUsedAt zero value)
}

type cliCredentialIDPointerItem struct {
	PK, SK, Entity string
	SecretHash     string
}

func cliCredentialFromItem(it *cliCredentialItem) *store.CLICredential {
	c := &store.CLICredential{
		ID: it.ID, UserID: it.UserID, Name: it.Name, SecretHash: it.SecretHash,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
	if it.LastUsedAt != 0 {
		c.LastUsedAt = fromUnix(it.LastUsedAt)
	}
	return c
}

// Create writes the primary CLICRED#<hash> item and its CLICREDID#<id>
// lookup pointer atomically via TransactWriteItems, both conditioned on
// non-existence -- mirrors the retired tokenRepo.Create.
func (r *cliCredentialRepo) Create(ctx context.Context, cred *store.CLICredential) error {
	if cred.ID == "" {
		cred.ID = store.NewID()
	}
	now := nowUnix()
	credItemMap, err := marshalMap(&cliCredentialItem{
		PK: pkCLICredential(cred.SecretHash), SK: skMeta, Entity: entityCLICredential,
		ID: cred.ID, UserID: cred.UserID, Name: cred.Name, SecretHash: cred.SecretHash,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	ptrItemMap, err := marshalMap(&cliCredentialIDPointerItem{
		PK: pkCLICredentialID(cred.ID), SK: skMeta, Entity: entityCLICredential, SecretHash: cred.SecretHash,
	})
	if err != nil {
		return err
	}

	err = r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: credItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: ptrItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	})
	if transactionConditionFailed(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	cred.CreatedAt, cred.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *cliCredentialRepo) ByHash(ctx context.Context, secretHash string) (*store.CLICredential, error) {
	item, err := r.s.getItem(ctx, pkCLICredential(secretHash), skMeta)
	if err != nil {
		return nil, err
	}
	var it cliCredentialItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return cliCredentialFromItem(&it), nil
}

// ListByUser has no user->credentials index in the single-table layout, so
// this is a full-table Scan with a FilterExpression -- acceptable at
// funcbox's expected scale (a handful of devices per user), same as the
// retired tokenRepo.ListByUser.
func (r *cliCredentialRepo) ListByUser(ctx context.Context, userID string) ([]*store.CLICredential, error) {
	var out []*store.CLICredential
	err := r.s.scanPages(ctx, "Entity = :e AND UserID = :uid", map[string]types.AttributeValue{
		":e":   &types.AttributeValueMemberS{Value: entityCLICredential},
		":uid": &types.AttributeValueMemberS{Value: userID},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it cliCredentialItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		out = append(out, cliCredentialFromItem(&it))
		return true, nil
	})
	return out, err
}

// Touch advances the primary item's LastUsedAt via the by-id pointer.
func (r *cliCredentialRepo) Touch(ctx context.Context, id string, now time.Time) error {
	ptr, err := r.pointer(ctx, id)
	if err != nil {
		return err
	}
	nowU := toUnix(now)
	upd := expression.Set(expression.Name("LastUsedAt"), expression.Value(nowU)).
		Set(expression.Name("UpdatedAt"), expression.Value(nowU))
	return r.s.updateItemIfExists(ctx, pkCLICredential(ptr.SecretHash), skMeta, upd)
}

// Delete removes both the primary and pointer items. A nonexistent id is a
// silent no-op, matching the SQL backends.
func (r *cliCredentialRepo) Delete(ctx context.Context, id string) error {
	ptr, err := r.pointer(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	writes := []types.WriteRequest{
		{DeleteRequest: &types.DeleteRequest{Key: key(pkCLICredential(ptr.SecretHash), skMeta)}},
		{DeleteRequest: &types.DeleteRequest{Key: key(pkCLICredentialID(id), skMeta)}},
	}
	return r.s.batchWrite(ctx, writes)
}

func (r *cliCredentialRepo) pointer(ctx context.Context, id string) (*cliCredentialIDPointerItem, error) {
	item, err := r.s.getItem(ctx, pkCLICredentialID(id), skMeta)
	if err != nil {
		return nil, err
	}
	var ptr cliCredentialIDPointerItem
	if err := unmarshalMap(item, &ptr); err != nil {
		return nil, err
	}
	return &ptr, nil
}
