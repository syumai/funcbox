package dynamodb

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// entity type markers, stored on every item as the "Entity" attribute.
// They exist so Scan-based list operations (documented as an acceptable
// simplification at funcbox's scale; see this package's doc comment) can
// tell items apart with a FilterExpression, since several entities share
// an SK value ("META") or a PK prefix ("FUNC#...").
const (
	entityOrganization     = "organization"
	entityLoginRule        = "login_rule"
	entityBootstrapLock    = "bootstrap_lock"
	entityUser             = "user"
	entityUserSubPointer   = "user_sub"
	entityHandle           = "handle"
	entityWorkspace        = "workspace"
	entityWorkspaceMember  = "workspace_member"
	entityFunction         = "function"
	entityFunctionPointer  = "function_ptr"
	entityFunctionName     = "function_name"
	entityFunctionListItem = "function_list"
	entityFunctionVersion  = "function_version"
	entityEnvVar           = "env_var"
	entitySession          = "session"
	entityInvokeAuthCode   = "invoke_auth_code"
	entityAPIToken         = "api_token"
	entityAuditLog         = "audit_log"
	entityInvocationLog    = "invocation_log"
)

// nowUnix returns the current time as Unix seconds (UTC), the storage
// representation used for every timestamp attribute — mirroring the SQL
// backends' convention (see internal/store/sqlite/helpers.go's nowUnix)
// without importing sqlcommon, which is SQL-specific.
func nowUnix() int64 { return time.Now().UTC().Unix() }

// toUnix converts a time.Time to its storage representation.
func toUnix(t time.Time) int64 { return t.UTC().Unix() }

// fromUnix converts a storage timestamp back to a time.Time in UTC.
func fromUnix(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

// stringAV wraps a string as a DynamoDB String AttributeValue, for
// building ExpressionAttributeValues maps by hand (FilterExpressions
// mixing a String and a Number comparison, where a single marshalMap call
// on a Go map wouldn't infer the right DynamoDB types).
func stringAV(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

// numberAV wraps an int64 as a DynamoDB Number AttributeValue.
func numberAV(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

// key returns the AttributeValue map identifying a single item by its
// partition/sort key.
func key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"PK": &types.AttributeValueMemberS{Value: pk},
		"SK": &types.AttributeValueMemberS{Value: sk},
	}
}

// getItem fetches a single item, returning store.ErrNotFound if it doesn't
// exist.
func (s *Store) getItem(ctx context.Context, pk, sk string) (map[string]types.AttributeValue, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key:       key(pk, sk),
	})
	if err != nil {
		return nil, err
	}
	if len(out.Item) == 0 {
		return nil, store.ErrNotFound
	}
	return out.Item, nil
}

// putItem writes item unconditionally (upsert).
func (s *Store) putItem(ctx context.Context, item map[string]types.AttributeValue) error {
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      item,
	})
	return err
}

// putItemIfNotExists writes item, failing with store.ErrConflict if an item
// with the same PK/SK already exists. Used everywhere this package needs
// SQL's "INSERT ... UNIQUE constraint" semantics (public User IDs, the
// google_sub/owner+name lookup pointers, ...).
func (s *Store) putItemIfNotExists(ctx context.Context, item map[string]types.AttributeValue) error {
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	if conditionalCheckFailed(err) {
		return store.ErrConflict
	}
	return err
}

// updateItemIfExists applies a partial UpdateExpression built from upd,
// conditioned on the item already existing (attribute_exists(PK)), mapping
// a failed condition to store.ErrNotFound. Used for partial updates
// (touching only some attributes) where a full-item PutItem would clobber
// attributes the caller isn't setting — e.g. SessionRepo.Refresh only
// wants to change expires_at/updated_at, not re-specify user_id.
func (s *Store) updateItemIfExists(ctx context.Context, pk, sk string, upd expression.UpdateBuilder) error {
	cond := expression.AttributeExists(expression.Name("PK"))
	expr, err := expression.NewBuilder().WithUpdate(upd).WithCondition(cond).Build()
	if err != nil {
		return err
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(pk, sk),
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	if conditionalCheckFailed(err) {
		return store.ErrNotFound
	}
	return err
}

// upsertItem applies a partial UpdateExpression unconditionally (creating
// the item if it doesn't exist, updating it otherwise) — DynamoDB's native
// UpdateItem semantics, matching SQL's "INSERT ... ON CONFLICT DO UPDATE".
func (s *Store) upsertItem(ctx context.Context, pk, sk string, upd expression.UpdateBuilder) error {
	expr, err := expression.NewBuilder().WithUpdate(upd).Build()
	if err != nil {
		return err
	}
	_, err = s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(pk, sk),
		UpdateExpression:          expr.Update(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	})
	return err
}

// putItemIfExists overwrites item, failing with store.ErrNotFound if no
// item with the same PK/SK currently exists. Used by Update-style methods
// whose store.*Repo doc comment (mirroring the SQL backends'
// RowsAffected==0 check) requires ErrNotFound on a missing row.
func (s *Store) putItemIfExists(ctx context.Context, item map[string]types.AttributeValue) error {
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(s.table),
		Item:                item,
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	if conditionalCheckFailed(err) {
		return store.ErrNotFound
	}
	return err
}

// deleteItem deletes a single item unconditionally (a no-op if it doesn't
// exist, matching the SQL backends' DELETE ... WHERE semantics used by
// e.g. PublicUserIDRepo.Delete/SessionRepo.Delete).
func (s *Store) deleteItem(ctx context.Context, pk, sk string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key(pk, sk),
	})
	return err
}

// deleteItemIfExists deletes a single item, failing with store.ErrNotFound
// if it doesn't exist. Used by methods whose store.*Repo doc comment
// requires ErrNotFound on a missing row (e.g. WorkspaceRepo.RemoveMember).
func (s *Store) deleteItemIfExists(ctx context.Context, pk, sk string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:           aws.String(s.table),
		Key:                 key(pk, sk),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	if conditionalCheckFailed(err) {
		return store.ErrNotFound
	}
	return err
}

// batchWrite issues writes via BatchWriteItem, chunked at DynamoDB's
// 25-item-per-call limit, retrying any UnprocessedItems (BatchWriteItem
// silently drops writes past its internal throughput budget rather than
// erroring, so a caller that ignores UnprocessedItems can silently lose
// writes).
func (s *Store) batchWrite(ctx context.Context, writes []types.WriteRequest) error {
	const maxBatch = 25
	for i := 0; i < len(writes); i += maxBatch {
		end := min(i+maxBatch, len(writes))
		chunk := writes[i:end]
		reqItems := map[string][]types.WriteRequest{s.table: chunk}
		for len(reqItems[s.table]) > 0 {
			out, err := s.client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: reqItems})
			if err != nil {
				return err
			}
			reqItems = out.UnprocessedItems
		}
	}
	return nil
}

// batchGetItems fetches keys via BatchGetItem, chunked at DynamoDB's
// 100-key-per-call limit, retrying UnprocessedKeys the same way batchWrite
// retries UnprocessedItems.
func (s *Store) batchGetItems(ctx context.Context, keys []map[string]types.AttributeValue) ([]map[string]types.AttributeValue, error) {
	const maxBatch = 100
	var out []map[string]types.AttributeValue
	for i := 0; i < len(keys); i += maxBatch {
		end := min(i+maxBatch, len(keys))
		reqItems := map[string]types.KeysAndAttributes{s.table: {Keys: keys[i:end]}}
		for len(reqItems[s.table].Keys) > 0 {
			resp, err := s.client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: reqItems})
			if err != nil {
				return nil, err
			}
			out = append(out, resp.Responses[s.table]...)
			reqItems = resp.UnprocessedKeys
		}
	}
	return out, nil
}

// conditionalCheckFailed reports whether err is a DynamoDB
// ConditionalCheckFailedException (a single-item PutItem/UpdateItem/
// DeleteItem's ConditionExpression evaluated to false).
func conditionalCheckFailed(err error) bool {
	if err == nil {
		return false
	}
	var ccf *types.ConditionalCheckFailedException
	return errors.As(err, &ccf)
}

// transactionConditionFailed reports whether err is a
// TransactionCanceledException with at least one item cancelled for
// ConditionalCheckFailed (as opposed to some other cancellation reason,
// e.g. a capacity/throttling issue, which callers should surface as-is
// rather than mis-map to ErrConflict/ErrNotFound).
func transactionConditionFailed(err error) bool {
	if err == nil {
		return false
	}
	var tce *types.TransactionCanceledException
	if !errors.As(err, &tce) {
		return false
	}
	for _, r := range tce.CancellationReasons {
		if aws.ToString(r.Code) == "ConditionalCheckFailed" {
			return true
		}
	}
	return false
}

// transactWrite issues a TransactWriteItems call. Callers inspect the
// returned error with transactionConditionFailed / conditionalCheckFailedAt
// to map a cancelled condition check back to store.ErrConflict/ErrNotFound.
func (s *Store) transactWrite(ctx context.Context, items []types.TransactWriteItem) error {
	_, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	return err
}

// conditionalCheckFailedAt reports whether err is a
// TransactionCanceledException whose CancellationReasons[index] is
// ConditionalCheckFailed, letting a caller that built a TransactWriteItems
// call from several ConditionChecks/Puts/Deletes at known indices
// distinguish which one caused the abort.
func conditionalCheckFailedAt(err error, index int) bool {
	var tce *types.TransactionCanceledException
	if !errors.As(err, &tce) {
		return false
	}
	if index < 0 || index >= len(tce.CancellationReasons) {
		return false
	}
	return aws.ToString(tce.CancellationReasons[index].Code) == "ConditionalCheckFailed"
}

// marshalMap wraps attributevalue.MarshalMap, the one place this package
// centralizes struct->item marshaling errors (which should never actually
// happen for the plain structs this package defines, but panicking on a
// programmer error here — a field type MarshalMap can't handle — would be
// worse than a clear wrapped error).
func marshalMap(v any) (map[string]types.AttributeValue, error) {
	return attributevalue.MarshalMap(v)
}

func unmarshalMap(item map[string]types.AttributeValue, out any) error {
	return attributevalue.UnmarshalMap(item, out)
}
