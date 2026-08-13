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

type invokeAuthCodeRepo struct{ s *Store }

type invokeAuthCodeItem struct {
	PK, SK, Entity               string
	ID, UserID, FunctionID, Host string
	ReturnTo                     string
	ExpiresAt, CreatedAt         int64
	TTL                          int64 `dynamodbav:"ttl"`
}

func invokeAuthCodeFromItem(it *invokeAuthCodeItem) *store.InvokeAuthCode {
	return &store.InvokeAuthCode{ID: it.ID, UserID: it.UserID, FunctionID: it.FunctionID,
		Host: it.Host, ReturnTo: it.ReturnTo, ExpiresAt: fromUnix(it.ExpiresAt), CreatedAt: fromUnix(it.CreatedAt)}
}

func (r *invokeAuthCodeRepo) Create(ctx context.Context, code *store.InvokeAuthCode) error {
	now, expiry := nowUnix(), toUnix(code.ExpiresAt)
	item, err := marshalMap(&invokeAuthCodeItem{PK: pkInvokeAuthCode(code.ID), SK: skMeta,
		Entity: entityInvokeAuthCode, ID: code.ID, UserID: code.UserID, FunctionID: code.FunctionID,
		Host: code.Host, ReturnTo: code.ReturnTo, ExpiresAt: expiry, CreatedAt: now, TTL: expiry})
	if err != nil {
		return err
	}
	if err := r.s.putItemIfNotExists(ctx, item); err != nil {
		return err
	}
	code.CreatedAt = fromUnix(now)
	return nil
}

func (r *invokeAuthCodeRepo) Consume(ctx context.Context, id, functionID, host string, now time.Time) (*store.InvokeAuthCode, error) {
	cond := expression.Name("FunctionID").Equal(expression.Value(functionID)).And(
		expression.Name("Host").Equal(expression.Value(host))).And(
		expression.Name("ExpiresAt").GreaterThan(expression.Value(toUnix(now))))
	expr, err := expression.NewBuilder().WithCondition(cond).Build()
	if err != nil {
		return nil, err
	}
	out, err := r.s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(r.s.table),
		Key: key(pkInvokeAuthCode(id), skMeta), ConditionExpression: expr.Condition(),
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
	var it invokeAuthCodeItem
	if err := unmarshalMap(out.Attributes, &it); err != nil {
		return nil, err
	}
	return invokeAuthCodeFromItem(&it), nil
}

func (r *invokeAuthCodeRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	var writes []types.WriteRequest
	err := r.s.scanPages(ctx, "Entity = :e AND ExpiresAt <= :now", map[string]types.AttributeValue{
		":e": stringAV(entityInvokeAuthCode), ":now": numberAV(toUnix(now)),
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
