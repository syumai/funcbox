package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/internal/store"
)

// workspaceRepo implements store.WorkspaceRepo. A workspace is stored at
// PK=WS#<id> SK=META; its members at PK=WS#<id> SK=MEMBER#<user_id>, per
// tmp/06-data-model.md.
type workspaceRepo struct{ s *Store }

type workspaceItem struct {
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

type workspaceMemberItem struct {
	PK          string
	SK          string
	Entity      string
	WorkspaceID string
	UserID      string
	Role        string
	CreatedAt   int64
	UpdatedAt   int64
}

func workspaceItemFrom(w *store.Workspace, createdAt, updatedAt int64) *workspaceItem {
	settings := w.Settings
	if settings == nil {
		settings = []byte("{}")
	}
	gen := w.SettingsGen
	if gen == 0 {
		gen = 1
	}
	return &workspaceItem{
		PK: pkWorkspace(w.ID), SK: skMeta, Entity: entityWorkspace,
		ID: w.ID, Name: w.Name, Settings: settings, SettingsGen: gen,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

func workspaceFromItem(it *workspaceItem) *store.Workspace {
	return &store.Workspace{
		ID: it.ID, Name: it.Name, Settings: it.Settings, SettingsGen: it.SettingsGen,
		CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

func (r *workspaceRepo) Create(ctx context.Context, w *store.Workspace) error {
	if w.ID == "" {
		w.ID = store.NewID()
	}
	now := nowUnix()
	item, err := marshalMap(workspaceItemFrom(w, now, now))
	if err != nil {
		return err
	}
	if err := r.s.putItem(ctx, item); err != nil {
		return err
	}
	w.CreatedAt, w.UpdatedAt = fromUnix(now), fromUnix(now)
	if w.Settings == nil {
		w.Settings = []byte("{}")
	}
	if w.SettingsGen == 0 {
		w.SettingsGen = 1
	}
	return nil
}

func (r *workspaceRepo) ByID(ctx context.Context, id string) (*store.Workspace, error) {
	item, err := r.s.getItem(ctx, pkWorkspace(id), skMeta)
	if err != nil {
		return nil, err
	}
	var it workspaceItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return workspaceFromItem(&it), nil
}

func (r *workspaceRepo) Update(ctx context.Context, w *store.Workspace) error {
	now := nowUnix()
	item, err := marshalMap(workspaceItemFrom(w, toUnix(w.CreatedAt), now))
	if err != nil {
		return err
	}
	if err := r.s.putItemIfExists(ctx, item); err != nil {
		return err
	}
	w.UpdatedAt = fromUnix(now)
	return nil
}

// Delete removes the workspace META item and every MEMBER# item under its
// partition (mirroring the SQL backends' cascading DELETE FROM
// workspace_members).
func (r *workspaceRepo) Delete(ctx context.Context, id string) error {
	out, err := r.s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkWorkspace(id)},
		},
	})
	if err != nil {
		return err
	}
	var writes []types.WriteRequest
	for _, item := range out.Items {
		pk, sk := itemKeyStrings(item)
		writes = append(writes, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: key(pk, sk)}})
	}
	return r.s.batchWrite(ctx, writes)
}

func (r *workspaceRepo) AddMember(ctx context.Context, m *store.WorkspaceMember) error {
	now := nowUnix()
	item, err := marshalMap(&workspaceMemberItem{
		PK: pkWorkspace(m.WorkspaceID), SK: skMember(m.UserID), Entity: entityWorkspaceMember,
		WorkspaceID: m.WorkspaceID, UserID: m.UserID, Role: string(m.Role),
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	if err := r.s.putItem(ctx, item); err != nil {
		return err
	}
	m.CreatedAt, m.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *workspaceRepo) RemoveMember(ctx context.Context, workspaceID, userID string) error {
	return r.s.deleteItemIfExists(ctx, pkWorkspace(workspaceID), skMember(userID))
}

func (r *workspaceRepo) UpdateMemberRole(ctx context.Context, workspaceID, userID string, role store.Role) error {
	upd := expression.Set(expression.Name("Role"), expression.Value(string(role))).
		Set(expression.Name("UpdatedAt"), expression.Value(nowUnix()))
	return r.s.updateItemIfExists(ctx, pkWorkspace(workspaceID), skMember(userID), upd)
}

func (r *workspaceRepo) ListMembers(ctx context.Context, workspaceID string) ([]*store.WorkspaceMember, error) {
	out, err := r.s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :pfx)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":  &types.AttributeValueMemberS{Value: pkWorkspace(workspaceID)},
			":pfx": &types.AttributeValueMemberS{Value: "MEMBER#"},
		},
		ScanIndexForward: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	members := make([]*store.WorkspaceMember, 0, len(out.Items))
	for _, item := range out.Items {
		var it workspaceMemberItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		members = append(members, &store.WorkspaceMember{
			WorkspaceID: it.WorkspaceID, UserID: it.UserID, Role: store.Role(it.Role),
			CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
		})
	}
	return members, nil
}

// ListForUser has no reverse (user -> workspaces) index in the
// single-table layout (workspace_member items are only reachable by
// querying a known workspace's partition), so this is a full-table Scan
// with a FilterExpression; acceptable at funcbox's expected scale (a user
// belongs to a small number of workspaces). See this package's doc
// comment.
func (r *workspaceRepo) ListForUser(ctx context.Context, userID string) ([]*store.Workspace, error) {
	var wsIDs []string
	err := r.s.scanPages(ctx, "Entity = :e AND UserID = :uid", map[string]types.AttributeValue{
		":e":   &types.AttributeValueMemberS{Value: entityWorkspaceMember},
		":uid": &types.AttributeValueMemberS{Value: userID},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it workspaceMemberItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		wsIDs = append(wsIDs, it.WorkspaceID)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]*store.Workspace, 0, len(wsIDs))
	for _, id := range wsIDs {
		w, err := r.ByID(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, nil
}

// ListAll Scans the whole table filtered to workspace META items;
// acceptable since it's only used for the org-admin's unrestricted
// workspace list (tmp/05-auth-and-permissions.md §5.3).
func (r *workspaceRepo) ListAll(ctx context.Context) ([]*store.Workspace, error) {
	var out []*store.Workspace
	err := r.s.scanPages(ctx, "Entity = :e", map[string]types.AttributeValue{
		":e": &types.AttributeValueMemberS{Value: entityWorkspace},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it workspaceItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		out = append(out, workspaceFromItem(&it))
		return true, nil
	})
	return out, err
}
