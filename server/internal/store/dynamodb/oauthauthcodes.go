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

type oauthAuthCodeRepo struct{ s *Store }

type oauthAuthCodeItem struct {
	PK, SK, Entity         string
	ID, UserID, ClientID   string
	RedirectURI, Challenge string
	Resource               string
	ExpiresAt, CreatedAt   int64
	TTL                    int64 `dynamodbav:"ttl"`
}

func oauthAuthCodeFromItem(it *oauthAuthCodeItem) *store.OAuthAuthCode {
	return &store.OAuthAuthCode{
		ID: it.ID, UserID: it.UserID, ClientID: it.ClientID, RedirectURI: it.RedirectURI,
		Challenge: it.Challenge, Resource: it.Resource,
		ExpiresAt: fromUnix(it.ExpiresAt), CreatedAt: fromUnix(it.CreatedAt),
	}
}

func (r *oauthAuthCodeRepo) Create(ctx context.Context, code *store.OAuthAuthCode) error {
	now, expiry := nowUnix(), toUnix(code.ExpiresAt)
	item, err := marshalMap(&oauthAuthCodeItem{
		PK: pkOAuthAuthCode(code.ID), SK: skMeta, Entity: entityOAuthAuthCode,
		ID: code.ID, UserID: code.UserID, ClientID: code.ClientID, RedirectURI: code.RedirectURI,
		Challenge: code.Challenge, Resource: code.Resource, ExpiresAt: expiry, CreatedAt: now, TTL: expiry,
	})
	if err != nil {
		return err
	}
	if err := r.s.putItemIfNotExists(ctx, item); err != nil {
		return err
	}
	code.CreatedAt = fromUnix(now)
	return nil
}

func (r *oauthAuthCodeRepo) Consume(ctx context.Context, id string, now time.Time) (*store.OAuthAuthCode, error) {
	cond := expression.Name("ExpiresAt").GreaterThan(expression.Value(toUnix(now)))
	expr, err := expression.NewBuilder().WithCondition(cond).Build()
	if err != nil {
		return nil, err
	}
	out, err := r.s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(r.s.table),
		Key: key(pkOAuthAuthCode(id), skMeta), ConditionExpression: expr.Condition(),
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
	var it oauthAuthCodeItem
	if err := unmarshalMap(out.Attributes, &it); err != nil {
		return nil, err
	}
	return oauthAuthCodeFromItem(&it), nil
}

func (r *oauthAuthCodeRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	var writes []types.WriteRequest
	err := r.s.scanPages(ctx, "Entity = :e AND ExpiresAt <= :now", map[string]types.AttributeValue{
		":e": stringAV(entityOAuthAuthCode), ":now": numberAV(toUnix(now)),
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
