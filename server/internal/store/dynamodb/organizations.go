package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// organizationRepo implements store.OrganizationRepo. It stores the
// singleton Organization at PK=ORG SK=META and its ordered LoginRules at
// PK=ORG SK=RULE#<0-padded ord>, per tmp/06-data-model.md.
type organizationRepo struct{ s *Store }

type orgItem struct {
	PK          string
	SK          string
	Entity      string
	ID          string
	Name        string
	Settings    []byte
	SettingsGen int
	CreatedAt   int64
	UpdatedAt   int64
}

type loginRuleItem struct {
	PK        string
	SK        string
	Entity    string
	ID        string
	Ord       int
	RuleType  string
	Value     string
	Action    string
	CreatedAt int64
	UpdatedAt int64
}

func (r *organizationRepo) Get(ctx context.Context) (*store.Organization, error) {
	item, err := r.s.getItem(ctx, pkOrg, skMeta)
	if err != nil {
		return nil, err
	}
	var it orgItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return orgFromItem(&it), nil
}

func (r *organizationRepo) Update(ctx context.Context, o *store.Organization) error {
	now := nowUnix()
	it := &orgItem{
		PK: pkOrg, SK: skMeta, Entity: entityOrganization,
		ID: "org", Name: o.Name, Settings: o.Settings, SettingsGen: o.SettingsGen,
		CreatedAt: toUnix(o.CreatedAt), UpdatedAt: now,
	}
	item, err := marshalMap(it)
	if err != nil {
		return err
	}
	if err := r.s.putItemIfExists(ctx, item); err != nil {
		return err
	}
	o.UpdatedAt = fromUnix(now)
	return nil
}

func (r *organizationRepo) ListLoginRules(ctx context.Context) ([]*store.LoginRule, error) {
	out, err := r.s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :pfx)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":  &types.AttributeValueMemberS{Value: pkOrg},
			":pfx": &types.AttributeValueMemberS{Value: "RULE#"},
		},
		ScanIndexForward: aws.Bool(true), // SK is zero-padded ord, so lexical order == Ord ascending
	})
	if err != nil {
		return nil, err
	}
	rules := make([]*store.LoginRule, 0, len(out.Items))
	for _, item := range out.Items {
		var it loginRuleItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		rules = append(rules, loginRuleFromItem(&it))
	}
	return rules, nil
}

// ReplaceLoginRules atomically replaces the entire login rule list: it
// first Queries the existing RULE# items (there are at most a handful, so
// no pagination concerns), then issues one BatchWriteItem to delete them
// and PutItem calls for the new set. This isn't a single atomic
// TransactWriteItems (login rules aren't read alongside anything else that
// needs cross-entity atomicity, unlike BootstrapFirstUser/ActivateVersion/
// CreateWorkspace), so a crash mid-replace could in principle leave a
// mixed set; acceptable for an organization-admin-only settings operation
// with no concurrent writers in practice.
func (r *organizationRepo) ReplaceLoginRules(ctx context.Context, rules []*store.LoginRule) error {
	existing, err := r.s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :pfx)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":  &types.AttributeValueMemberS{Value: pkOrg},
			":pfx": &types.AttributeValueMemberS{Value: "RULE#"},
		},
	})
	if err != nil {
		return err
	}

	var writes []types.WriteRequest
	for _, item := range existing.Items {
		var it loginRuleItem
		if err := unmarshalMap(item, &it); err != nil {
			return err
		}
		writes = append(writes, types.WriteRequest{
			DeleteRequest: &types.DeleteRequest{Key: key(it.PK, it.SK)},
		})
	}

	now := nowUnix()
	for _, lr := range rules {
		if lr.ID == "" {
			lr.ID = store.NewID()
		}
		it := &loginRuleItem{
			PK: pkOrg, SK: skLoginRule(lr.Ord), Entity: entityLoginRule,
			ID: lr.ID, Ord: lr.Ord, RuleType: string(lr.RuleType), Value: lr.Value, Action: string(lr.Action),
			CreatedAt: now, UpdatedAt: now,
		}
		item, err := marshalMap(it)
		if err != nil {
			return err
		}
		writes = append(writes, types.WriteRequest{PutRequest: &types.PutRequest{Item: item}})
		lr.CreatedAt, lr.UpdatedAt = fromUnix(now), fromUnix(now)
	}

	if err := r.s.batchWrite(ctx, writes); err != nil {
		return err
	}
	return nil
}

func orgFromItem(it *orgItem) *store.Organization {
	return &store.Organization{
		ID: it.ID, Name: it.Name, Settings: it.Settings, SettingsGen: it.SettingsGen,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

func loginRuleFromItem(it *loginRuleItem) *store.LoginRule {
	return &store.LoginRule{
		ID: it.ID, Ord: it.Ord, RuleType: store.LoginRuleType(it.RuleType), Value: it.Value,
		Action: store.LoginRuleAction(it.Action), CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}
