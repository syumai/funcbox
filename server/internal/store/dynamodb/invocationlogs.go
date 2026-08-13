package dynamodb

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// invocationLogRepo implements store.InvocationLogRepo. Entries live at
// PK=INVLOG#<function_id> SK=<ulid>, a single partition per function
// the entity but not a key shape — so this package picks the natural
// per-function partition, matching List's function-scoped signature and
// keeping ListVersions/ListEnv/List's Query pattern consistent across this
// package).
//
// Retention: unlike SQL backends (which actively DELETE rows older than a
// cutoff, see DeleteOlderThan), this repo relies on the table's TTL
// attribute (ttlAttribute) set at write time to a fixed horizon from
// CreatedAt — settings.DefaultLogRetentionDays (7 days) — rather than
// looking up the organization's live log_retention_days setting on every
// Append. This is the documented simplification
// InvocationLogRepo.DeleteOlderThan's doc comment calls for: a DynamoDB
// backend "enforces retention via a TTL attribute set at write time
// instead" of a periodic sweep, and a fixed default horizon is
// specifically sanctioned as acceptable rather than a live per-write
// settings lookup.
type invocationLogRepo struct{ s *Store }

// invocationLogRetention is the fixed TTL horizon applied at write time;
// see this repo's doc comment for why it isn't looked up per-write from
// the live organization setting.
const invocationLogRetention = settings.DefaultLogRetentionDays * 24 * time.Hour

type invocationLogItem struct {
	PK             string
	SK             string
	Entity         string
	ID             string
	FunctionID     string
	VersionID      string
	Method         string
	Path           string
	Status         int
	DurationMS     int64
	Stdout         string
	Stderr         string
	FetchDecisions []byte
	CreatedAt      int64
	TTL            int64 `dynamodbav:"ttl"`
}

func (r *invocationLogRepo) Append(ctx context.Context, l *store.InvocationLog) error {
	if l.ID == "" {
		l.ID = store.NewID()
	}
	now := nowUnix()
	item, err := marshalMap(&invocationLogItem{
		PK: pkInvocationLog(l.FunctionID), SK: l.ID, Entity: entityInvocationLog,
		ID: l.ID, FunctionID: l.FunctionID, VersionID: l.VersionID, Method: l.Method, Path: l.Path,
		Status: l.Status, DurationMS: l.DurationMS, Stdout: l.Stdout, Stderr: l.Stderr, FetchDecisions: l.FetchDecisions,
		CreatedAt: now, TTL: now + int64(invocationLogRetention.Seconds()),
	})
	if err != nil {
		return err
	}
	if err := r.s.putItem(ctx, item); err != nil {
		return err
	}
	l.CreatedAt = fromUnix(now)
	return nil
}

func (r *invocationLogRepo) List(ctx context.Context, functionID string, cursor string, limit int) ([]*store.InvocationLog, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	in := &dynamodb.QueryInput{
		TableName:        aws.String(r.s.table),
		ScanIndexForward: aws.Bool(false), // ULIDs sort lexically = chronologically, so this is newest-first
		Limit:            aws.Int32(int32(limit)),
	}
	if cursor == "" {
		in.KeyConditionExpression = aws.String("PK = :pk")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkInvocationLog(functionID)},
		}
	} else {
		in.KeyConditionExpression = aws.String("PK = :pk AND SK < :cursor")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{
			":pk":     &types.AttributeValueMemberS{Value: pkInvocationLog(functionID)},
			":cursor": &types.AttributeValueMemberS{Value: cursor},
		}
	}
	out, err := r.s.client.Query(ctx, in)
	if err != nil {
		return nil, err
	}
	logs := make([]*store.InvocationLog, 0, len(out.Items))
	for _, item := range out.Items {
		var it invocationLogItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		logs = append(logs, &store.InvocationLog{
			ID: it.ID, FunctionID: it.FunctionID, VersionID: it.VersionID, Method: it.Method, Path: it.Path,
			Status: it.Status, DurationMS: it.DurationMS, Stdout: it.Stdout, Stderr: it.Stderr,
			FetchDecisions: it.FetchDecisions, CreatedAt: fromUnix(it.CreatedAt),
		})
	}
	return logs, nil
}

// DeleteOlderThan is a documented no-op: see this repo's doc comment and
// store.InvocationLogRepo.DeleteOlderThan's doc comment. Retention is
// enforced by the ttl attribute set at write time instead.
func (r *invocationLogRepo) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	return 0, nil
}
