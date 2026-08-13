package dynamodb

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

type cliAuthCodeRepo struct{ s *Store }

type cliAuthCodeItem struct {
	PK, SK, Entity       string
	ID, UserID, Name     string
	Challenge            string
	ExpiresAt, CreatedAt int64
	TTL                  int64 `dynamodbav:"ttl"`
}

func cliAuthCodeFromItem(it *cliAuthCodeItem) *store.CLIAuthCode {
	return &store.CLIAuthCode{ID: it.ID, UserID: it.UserID, Name: it.Name,
		Challenge: it.Challenge, ExpiresAt: fromUnix(it.ExpiresAt), CreatedAt: fromUnix(it.CreatedAt)}
}

func (r *cliAuthCodeRepo) Create(ctx context.Context, code *store.CLIAuthCode) error {
	now, expiry := nowUnix(), toUnix(code.ExpiresAt)
	item, err := marshalMap(&cliAuthCodeItem{PK: pkCLIAuthCode(code.ID), SK: skMeta,
		Entity: entityCLIAuthCode, ID: code.ID, UserID: code.UserID, Name: code.Name,
		Challenge: code.Challenge, ExpiresAt: expiry, CreatedAt: now, TTL: expiry})
	if err != nil {
		return err
	}
	if err := r.s.putItemIfNotExists(ctx, item); err != nil {
		return err
	}
	code.CreatedAt = fromUnix(now)
	return nil
}

func (r *cliAuthCodeRepo) Consume(ctx context.Context, id string, now time.Time) (*store.CLIAuthCode, error) {
	cond := expression.Name("ExpiresAt").GreaterThan(expression.Value(toUnix(now)))
	expr, err := expression.NewBuilder().WithCondition(cond).Build()
	if err != nil {
		return nil, err
	}
	out, err := r.s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(r.s.table),
		Key: key(pkCLIAuthCode(id), skMeta), ConditionExpression: expr.Condition(),
		ExpressionAttributeNames: expr.Names(), ExpressionAttributeValues: expr.Values(),
		ReturnValues: types.ReturnValueAllOld})
	if conditionalCheckFailed(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(out.Attributes) == 0 {
		return nil, store.ErrNotFound
	}
	var it cliAuthCodeItem
	if err := unmarshalMap(out.Attributes, &it); err != nil {
		return nil, err
	}
	return cliAuthCodeFromItem(&it), nil
}

func (r *cliAuthCodeRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	var writes []types.WriteRequest
	err := r.s.scanPages(ctx, "Entity = :e AND ExpiresAt <= :now", map[string]types.AttributeValue{
		":e": stringAV(entityCLIAuthCode), ":now": numberAV(toUnix(now)),
	}, func(item map[string]types.AttributeValue) (bool, error) {
		pk, sk := itemKeyStrings(item)
		writes = append(writes, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: key(pk, sk)}})
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	if err := r.s.batchWrite(ctx, writes); err != nil {
		return 0, err
	}
	return int64(len(writes)), nil
}
