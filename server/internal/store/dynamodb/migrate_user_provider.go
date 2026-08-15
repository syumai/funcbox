package dynamodb

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// legacyGoogleSubItem reads just the pre-generalization GoogleSub attribute
// off a primary user item; see migrateUserProviderPointers. userItem no
// longer declares this field, so a plain unmarshalMap into it would silently
// drop the value.
type legacyGoogleSubItem struct {
	GoogleSub string
}

// migrateUserProviderPointers is the one-time, idempotent migration off the
// pre-generalization "USER#SUB#<google_sub>" lookup-pointer key shape (see
// keys.go's pkUserSubLegacy) onto "USER#PROVIDER#<provider>#<subject>"
// (pkUserProviderSubject).
//
// It scans every primary user item; one with no Provider attribute is a
// legacy row (every pre-migration user was necessarily a Google account), so
// it's rewritten in place with Provider="google" / ProviderSubject=<its old
// GoogleSub value>, its new pointer item is created, and its old USER#SUB#
// pointer item is removed. Already-migrated rows (Provider already set) are
// left untouched, which is what makes repeated calls -- every process start,
// per this package's Migrate convention -- cheap no-ops.
func (s *Store) migrateUserProviderPointers(ctx context.Context) error {
	return s.scanPages(ctx, "Entity = :e", map[string]types.AttributeValue{
		":e": &types.AttributeValueMemberS{Value: entityUser},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it userItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		if it.Provider != "" {
			return true, nil // already migrated
		}
		var legacy legacyGoogleSubItem
		if err := unmarshalMap(item, &legacy); err != nil {
			return false, err
		}
		if legacy.GoogleSub == "" {
			// No recognizable legacy identity to migrate from; leave it
			// alone rather than guess.
			return true, nil
		}

		it.Provider = string(store.ProviderGoogle)
		it.ProviderSubject = legacy.GoogleSub
		userItemMap, err := marshalMap(&it)
		if err != nil {
			return false, err
		}
		ptrItemMap, err := marshalMap(&userProviderSubjectPointerItem{
			PK: pkUserProviderSubject(store.ProviderGoogle, legacy.GoogleSub), SK: skMeta,
			Entity: entityUserProviderSubjectPointer, UserID: it.ID,
		})
		if err != nil {
			return false, err
		}

		if err := s.putItemIfExists(ctx, userItemMap); err != nil {
			return false, err
		}
		if err := s.putItemIfNotExists(ctx, ptrItemMap); err != nil && !errors.Is(err, store.ErrConflict) {
			return false, err
		}
		if _, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(s.table),
			Key:       key(pkUserSubLegacy(legacy.GoogleSub), skMeta),
		}); err != nil {
			return false, err
		}
		return true, nil
	})
}
