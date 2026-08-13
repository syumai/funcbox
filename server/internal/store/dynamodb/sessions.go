package dynamodb

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// sessionRepo implements store.SessionRepo. Sessions live at
// PK=SESSION#<id> SK=META with the ttl attribute set to ExpiresAt, per
// tmp/06-data-model.md ("TTL 属性で自動失効"). DynamoDB's own TTL sweep is
// only eventually consistent (items can survive up to ~48h past
// expiration before physical deletion), so Get additionally filters
// expired-but-not-yet-swept items itself against the caller-supplied now,
// and DeleteExpired actively deletes rather than waiting on TTL — both
// needed for the deterministic behavior storetest's
// SessionExpiryFilter/SessionRefresh subtests require.
type sessionRepo struct{ s *Store }

type sessionItem struct {
	PK        string
	SK        string
	Entity    string
	ID        string
	UserID    string
	ExpiresAt int64
	CreatedAt int64
	UpdatedAt int64
	TTL       int64 `dynamodbav:"ttl"`
}

func sessionFromItem(it *sessionItem) *store.Session {
	return &store.Session{
		ID: it.ID, UserID: it.UserID, ExpiresAt: fromUnix(it.ExpiresAt),
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

func (r *sessionRepo) Create(ctx context.Context, s *store.Session) error {
	if s.ID == "" {
		s.ID = store.NewID()
	}
	now := nowUnix()
	expiresAt := toUnix(s.ExpiresAt)
	item, err := marshalMap(&sessionItem{
		PK: pkSession(s.ID), SK: skMeta, Entity: entitySession,
		ID: s.ID, UserID: s.UserID, ExpiresAt: expiresAt, CreatedAt: now, UpdatedAt: now, TTL: expiresAt,
	})
	if err != nil {
		return err
	}
	if err := r.s.putItem(ctx, item); err != nil {
		return err
	}
	s.CreatedAt, s.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *sessionRepo) Refresh(ctx context.Context, id string, newExpiresAt time.Time) error {
	now := nowUnix()
	expiresAt := toUnix(newExpiresAt)
	upd := expression.Set(expression.Name("ExpiresAt"), expression.Value(expiresAt)).
		Set(expression.Name("ttl"), expression.Value(expiresAt)).
		Set(expression.Name("UpdatedAt"), expression.Value(now))
	return r.s.updateItemIfExists(ctx, pkSession(id), skMeta, upd)
}

func (r *sessionRepo) Get(ctx context.Context, id string, now time.Time) (*store.Session, error) {
	item, err := r.s.getItem(ctx, pkSession(id), skMeta)
	if err != nil {
		return nil, err
	}
	var it sessionItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	if !fromUnix(it.ExpiresAt).After(now) {
		return nil, store.ErrNotFound
	}
	return sessionFromItem(&it), nil
}

func (r *sessionRepo) Delete(ctx context.Context, id string) error {
	return r.s.deleteItem(ctx, pkSession(id), skMeta)
}

// DeleteExpired actively Scans for and deletes every session with
// ExpiresAt <= now; see this repo's doc comment for why it can't rely on
// DynamoDB's own (eventually-consistent) TTL sweep here.
func (r *sessionRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	var writes []types.WriteRequest
	err := r.s.scanPages(ctx, "Entity = :e AND ExpiresAt <= :now", map[string]types.AttributeValue{
		":e":   stringAV(entitySession),
		":now": numberAV(toUnix(now)),
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
