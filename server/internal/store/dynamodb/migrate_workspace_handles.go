package dynamodb

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// removeLegacyWorkspaceHandles removes handle items created before
// workspaces switched to immutable IDs. Each delete re-checks the entity and
// owner type so a concurrently replaced user ID item cannot be removed.
func (s *Store) removeLegacyWorkspaceHandles(ctx context.Context) error {
	return s.scanPages(ctx, "Entity = :entity AND OwnerType = :ownerType", map[string]types.AttributeValue{
		":entity":    &types.AttributeValueMemberS{Value: entityHandle},
		":ownerType": &types.AttributeValueMemberS{Value: string(store.OwnerTypeWorkspace)},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		pk, pkOK := item["PK"].(*types.AttributeValueMemberS)
		sk, skOK := item["SK"].(*types.AttributeValueMemberS)
		if !pkOK || !skOK || pk.Value == "" || sk.Value == "" {
			return false, fmt.Errorf("dynamodb: legacy workspace handle has invalid key")
		}

		_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName:           aws.String(s.table),
			Key:                 key(pk.Value, sk.Value),
			ConditionExpression: aws.String("#entity = :entity AND OwnerType = :ownerType"),
			ExpressionAttributeNames: map[string]string{
				"#entity": "Entity",
			},
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":entity":    &types.AttributeValueMemberS{Value: entityHandle},
				":ownerType": &types.AttributeValueMemberS{Value: string(store.OwnerTypeWorkspace)},
			},
		})
		if conditionalCheckFailed(err) {
			return true, nil
		}
		return true, err
	})
}
