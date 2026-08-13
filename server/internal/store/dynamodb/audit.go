package dynamodb

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// auditRepo implements store.AuditRepo. Entries are partitioned by month
// (PK=AUDIT#<yyyymm>, SK=<ulid>) per tmp/06-data-model.md, so a single
// month's worth of entries is always one partition's worth of Query
// throughput; List walks backward across month partitions as needed to
// fill out a page (see List's doc comment).
type auditRepo struct{ s *Store }

const defaultListLimit = 50

type auditItem struct {
	PK        string
	SK        string
	Entity    string
	ID        string
	ActorID   string
	Action    string
	Target    string
	Detail    []byte
	CreatedAt int64
	UpdatedAt int64
}

func (r *auditRepo) Append(ctx context.Context, a *store.AuditLog) error {
	if a.ID == "" {
		a.ID = store.NewID()
	}
	now := nowUnix()
	item, err := marshalMap(&auditItem{
		PK: pkAudit(monthFromULID(a.ID)), SK: a.ID, Entity: entityAuditLog,
		ID: a.ID, ActorID: a.ActorID, Action: a.Action, Target: a.Target, Detail: a.Detail,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	if err := r.s.putItem(ctx, item); err != nil {
		return err
	}
	a.CreatedAt, a.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

// List returns entries newest-first, walking backward across month
// partitions when the starting month's partition is exhausted before
// limit entries have been collected. The starting month is derived from
// cursor's embedded ULID timestamp (or the current UTC month if cursor is
// empty); every month visited after the first is queried in full (no SK
// cursor, since a cursor only ever applies to the month it was issued
// from). The walk is bounded by monthFloor, so a table with sparse or no
// audit data still terminates in a bounded number of (cheap, empty) Query
// calls rather than scanning indefinitely.
func (r *auditRepo) List(ctx context.Context, cursor string, limit int) ([]*store.AuditLog, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}

	month := monthKey(time.Now())
	skCursor := ""
	if cursor != "" {
		month = monthFromULID(cursor)
		skCursor = cursor
	}

	var out []*store.AuditLog
	for month >= monthFloor && len(out) < limit {
		items, err := r.queryMonth(ctx, month, skCursor, limit-len(out))
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		month = prevMonthKey(month)
		skCursor = "" // only the very first (cursor's) month partition has a mid-partition start point
	}
	return out, nil
}

func (r *auditRepo) queryMonth(ctx context.Context, month, cursor string, limit int) ([]*store.AuditLog, error) {
	in := &dynamodb.QueryInput{
		TableName:        aws.String(r.s.table),
		ScanIndexForward: aws.Bool(false), // ULIDs sort lexically = chronologically, so this is newest-first
		Limit:            aws.Int32(int32(limit)),
	}
	if cursor == "" {
		in.KeyConditionExpression = aws.String("PK = :pk")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkAudit(month)},
		}
	} else {
		in.KeyConditionExpression = aws.String("PK = :pk AND SK < :cursor")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{
			":pk":     &types.AttributeValueMemberS{Value: pkAudit(month)},
			":cursor": &types.AttributeValueMemberS{Value: cursor},
		}
	}
	out, err := r.s.client.Query(ctx, in)
	if err != nil {
		return nil, err
	}
	logs := make([]*store.AuditLog, 0, len(out.Items))
	for _, item := range out.Items {
		var it auditItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		logs = append(logs, &store.AuditLog{
			ID: it.ID, ActorID: it.ActorID, Action: it.Action, Target: it.Target, Detail: it.Detail,
			CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
		})
	}
	return logs, nil
}
