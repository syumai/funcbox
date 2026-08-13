package dynamodb

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/syumai/funcbox/server/internal/store"
)

// functionRepo implements store.FunctionRepo. Its layout (see
// additions beyond that table):
//
//   - PK=FUNC#<id> SK=META: the function's primary item. Also the
//     partition that holds its VER#/ENV# children, so Delete can remove a
//     whole function in one Query + BatchWriteItem.
//   - PK=FUNC#<ownerType>:<ownerID>#<name> SK=META: an owner+name lookup
//     pointer (id only), giving ByOwnerAndName a GetItem and enforcing
//     (owner, name) uniqueness via a conditional Put.
//   - PK=FUNCLIST#<ownerType>:<ownerID> SK=<function_id>: an
//     application-maintained index (this package's addition) so
//     ListByOwner is an efficient Query instead of a Scan, as suggested by
//   - PK=VER#<version_id> SK=META: a duplicate copy of a FUNC#<id>
//     VER#<version_id> item (this package's addition), needed because
//     FunctionRepo.Version(ctx, id) is handed only a version id with no
//     function id to Query by. Duplicating is safe because
//     FunctionVersion is immutable once created (see its doc comment) —
//     there's no update path that could let the two copies drift.
type functionRepo struct{ s *Store }

type functionItem struct {
	PK              string
	SK              string
	Entity          string
	ID              string
	OwnerType       string
	OwnerID         string
	Name            string
	Description     string
	ActiveVersionID *string
	CreatedAt       int64
	UpdatedAt       int64
}

type functionPointerItem struct {
	PK         string
	SK         string
	Entity     string
	FunctionID string
}

type versionItem struct {
	PK           string
	SK           string
	Entity       string
	ID           string
	FunctionID   string
	Manifest     []byte
	MainPath     string
	BundleHash   string
	BundleSize   int64
	UnpackedSize int64
	Files        []byte
	CreatedBy    string
	Note         string
	CreatedAt    int64
	UpdatedAt    int64
}

type envVarItem struct {
	PK         string
	SK         string
	Entity     string
	FunctionID string
	EnvKey     string
	ValueEnc   []byte
	CreatedAt  int64
	UpdatedAt  int64
}

func functionItemFrom(f *store.Function, createdAt, updatedAt int64) *functionItem {
	return &functionItem{
		PK: pkFunc(f.ID), SK: skMeta, Entity: entityFunction,
		ID: f.ID, OwnerType: string(f.OwnerType), OwnerID: f.OwnerID, Name: f.Name, Description: f.Description,
		ActiveVersionID: f.ActiveVersionID, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

func functionFromItem(it *functionItem) *store.Function {
	return &store.Function{
		ID: it.ID, OwnerType: store.OwnerType(it.OwnerType), OwnerID: it.OwnerID, Name: it.Name, Description: it.Description,
		ActiveVersionID: it.ActiveVersionID, CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

func versionFromItem(it *versionItem) *store.FunctionVersion {
	return &store.FunctionVersion{
		ID: it.ID, FunctionID: it.FunctionID, Manifest: it.Manifest, MainPath: it.MainPath,
		BundleHash: it.BundleHash, BundleSize: it.BundleSize, UnpackedSize: it.UnpackedSize, Files: it.Files,
		CreatedBy: it.CreatedBy, Note: it.Note, CreatedAt: fromUnix(it.CreatedAt), UpdatedAt: fromUnix(it.UpdatedAt),
	}
}

// Create writes the function's primary item, its owner+name lookup
// pointer, and its FUNCLIST index entry atomically via TransactWriteItems.
// The pointer is conditioned on non-existence, so a duplicate (owner,
// name) fails the whole write with store.ErrConflict — this is the only
// realistic failure among the three (the other two key on a fresh ULID
// id).
func (r *functionRepo) Create(ctx context.Context, f *store.Function) error {
	if f.ID == "" {
		f.ID = store.NewID()
	}
	now := nowUnix()

	funcItemMap, err := marshalMap(functionItemFrom(f, now, now))
	if err != nil {
		return err
	}
	ptrItemMap, err := marshalMap(&functionPointerItem{
		PK: pkFuncPtr(string(f.OwnerType), f.OwnerID, f.Name), SK: skMeta, Entity: entityFunctionPointer, FunctionID: f.ID,
	})
	if err != nil {
		return err
	}
	listItemMap, err := marshalMap(&functionPointerItem{
		PK: pkFuncList(string(f.OwnerType), f.OwnerID), SK: f.ID, Entity: entityFunctionListItem, FunctionID: f.ID,
	})
	if err != nil {
		return err
	}

	err = r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: funcItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: ptrItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: listItemMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	})
	if transactionConditionFailed(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	f.CreatedAt, f.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *functionRepo) ByID(ctx context.Context, id string) (*store.Function, error) {
	item, err := r.s.getItem(ctx, pkFunc(id), skMeta)
	if err != nil {
		return nil, err
	}
	var it functionItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return functionFromItem(&it), nil
}

func (r *functionRepo) ByOwnerAndName(ctx context.Context, ownerType store.OwnerType, ownerID, name string) (*store.Function, error) {
	item, err := r.s.getItem(ctx, pkFuncPtr(string(ownerType), ownerID, name), skMeta)
	if err != nil {
		return nil, err
	}
	var ptr functionPointerItem
	if err := unmarshalMap(item, &ptr); err != nil {
		return nil, err
	}
	return r.ByID(ctx, ptr.FunctionID)
}

// ListByOwner Queries the FUNCLIST#<ownerType>:<ownerID> index (an
// efficient, single-partition Query) to get the ordered set of function
// ids, then BatchGetItems the primary FUNC#<id> META items. Because
// function ids are ULIDs (time-sortable) and the index's sort key is the
// id itself, a forward Query already yields ascending creation order,
// matching the SQL backends' ORDER BY created_at ASC.
func (r *functionRepo) ListByOwner(ctx context.Context, ownerType store.OwnerType, ownerID string) ([]*store.Function, error) {
	out, err := r.s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkFuncList(string(ownerType), ownerID)},
		},
		ScanIndexForward: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	if len(out.Items) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(out.Items))
	keys := make([]map[string]types.AttributeValue, 0, len(out.Items))
	for _, item := range out.Items {
		var it functionPointerItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		ids = append(ids, it.FunctionID)
		keys = append(keys, key(pkFunc(it.FunctionID), skMeta))
	}

	items, err := r.s.batchGetItems(ctx, keys)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*store.Function, len(items))
	for _, item := range items {
		var it functionItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		byID[it.ID] = functionFromItem(&it)
	}

	out2 := make([]*store.Function, 0, len(ids))
	for _, id := range ids {
		if f, ok := byID[id]; ok {
			out2 = append(out2, f)
		}
	}
	return out2, nil
}

// ListVisibleTo composes ListByOwner(user) with ListByOwner(workspace) for
// every workspace userID is a member of, per this method's doc comment.
func (r *functionRepo) ListVisibleTo(ctx context.Context, userID string) ([]*store.Function, error) {
	out, err := r.ListByOwner(ctx, store.OwnerTypeUser, userID)
	if err != nil {
		return nil, err
	}
	workspaces, err := r.s.workspaces.ListForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, ws := range workspaces {
		fns, err := r.ListByOwner(ctx, store.OwnerTypeWorkspace, ws.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, fns...)
	}
	return out, nil
}

// ListAll Scans the whole table filtered to function primary items;
// acceptable since it's only used for the org-admin's unrestricted
func (r *functionRepo) ListAll(ctx context.Context) ([]*store.Function, error) {
	var out []*store.Function
	err := r.s.scanPages(ctx, "Entity = :e", map[string]types.AttributeValue{
		":e": &types.AttributeValueMemberS{Value: entityFunction},
	}, func(item map[string]types.AttributeValue) (bool, error) {
		var it functionItem
		if err := unmarshalMap(item, &it); err != nil {
			return false, err
		}
		out = append(out, functionFromItem(&it))
		return true, nil
	})
	return out, err
}

// Update overwrites the function's primary item. If Name is changing, the
// owner+name lookup pointer is moved atomically (old deleted, new created
// conditioned on non-existence) in the same TransactWriteItems call the
// same way userRepo.Update handles a changing GoogleSub; a rename to an
// already-taken name fails with store.ErrConflict.
func (r *functionRepo) Update(ctx context.Context, f *store.Function) error {
	existing, err := r.ByID(ctx, f.ID)
	if err != nil {
		return err
	}

	now := nowUnix()
	it := functionItemFrom(f, toUnix(existing.CreatedAt), now)
	funcItemMap, err := marshalMap(it)
	if err != nil {
		return err
	}

	if existing.Name == f.Name && existing.OwnerType == f.OwnerType && existing.OwnerID == f.OwnerID {
		if err := r.s.putItemIfExists(ctx, funcItemMap); err != nil {
			return err
		}
		f.CreatedAt, f.UpdatedAt = existing.CreatedAt, fromUnix(now)
		return nil
	}

	newPtrMap, err := marshalMap(&functionPointerItem{
		PK: pkFuncPtr(string(f.OwnerType), f.OwnerID, f.Name), SK: skMeta, Entity: entityFunctionPointer, FunctionID: f.ID,
	})
	if err != nil {
		return err
	}
	txErr := r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: funcItemMap, ConditionExpression: aws.String("attribute_exists(PK)")}},
		{Delete: &types.Delete{TableName: aws.String(r.s.table), Key: key(pkFuncPtr(string(existing.OwnerType), existing.OwnerID, existing.Name), skMeta)}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: newPtrMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	})
	if conditionalCheckFailedAt(txErr, 0) {
		return store.ErrNotFound
	}
	if conditionalCheckFailedAt(txErr, 2) {
		return store.ErrConflict
	}
	if txErr != nil {
		return txErr
	}
	f.CreatedAt, f.UpdatedAt = existing.CreatedAt, fromUnix(now)
	return nil
}

// Delete removes the function's primary item, every VER#/ENV# child item
// under its partition, its owner+name pointer, and its FUNCLIST index
// entry — mirroring the SQL backends' cascading DELETE FROM env_vars /
// function_versions / functions. A nonexistent id is a silent no-op,
// matching the SQL backends (a DELETE affecting zero rows is not an
// error).
func (r *functionRepo) Delete(ctx context.Context, id string) error {
	f, err := r.ByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	out, err := r.s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: pkFunc(id)},
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
	writes = append(writes,
		types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: key(pkFuncPtr(string(f.OwnerType), f.OwnerID, f.Name), skMeta)}},
		types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: key(pkFuncList(string(f.OwnerType), f.OwnerID), id)}},
	)
	return r.s.batchWrite(ctx, writes)
}

// CreateVersion writes the function-scoped item (FUNC#<id> VER#<version>,
// used by ListVersions) and the global by-id duplicate (VER#<version>
// META, used by Version; see this repo's doc comment) in one
// TransactWriteItems call.
func (r *functionRepo) CreateVersion(ctx context.Context, v *store.FunctionVersion) error {
	if v.ID == "" {
		v.ID = store.NewID()
	}
	now := nowUnix()
	base := &versionItem{
		Entity: entityFunctionVersion, ID: v.ID, FunctionID: v.FunctionID, Manifest: v.Manifest, MainPath: v.MainPath,
		BundleHash: v.BundleHash, BundleSize: v.BundleSize, UnpackedSize: v.UnpackedSize, Files: v.Files,
		CreatedBy: v.CreatedBy, Note: v.Note, CreatedAt: now, UpdatedAt: now,
	}
	scoped := *base
	scoped.PK, scoped.SK = pkFunc(v.FunctionID), skVersion(v.ID)
	scopedMap, err := marshalMap(&scoped)
	if err != nil {
		return err
	}
	global := *base
	global.PK, global.SK = pkVersion(v.ID), skMeta
	globalMap, err := marshalMap(&global)
	if err != nil {
		return err
	}

	if err := r.s.transactWrite(ctx, []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: scopedMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
		{Put: &types.Put{TableName: aws.String(r.s.table), Item: globalMap, ConditionExpression: aws.String("attribute_not_exists(PK)")}},
	}); err != nil {
		return err
	}
	v.CreatedAt, v.UpdatedAt = fromUnix(now), fromUnix(now)
	return nil
}

func (r *functionRepo) Version(ctx context.Context, id string) (*store.FunctionVersion, error) {
	item, err := r.s.getItem(ctx, pkVersion(id), skMeta)
	if err != nil {
		return nil, err
	}
	var it versionItem
	if err := unmarshalMap(item, &it); err != nil {
		return nil, err
	}
	return versionFromItem(&it), nil
}

func (r *functionRepo) ListVersions(ctx context.Context, funcID string, limit int) ([]*store.FunctionVersion, error) {
	in := &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :pfx)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":  &types.AttributeValueMemberS{Value: pkFunc(funcID)},
			":pfx": &types.AttributeValueMemberS{Value: "VER#"},
		},
		ScanIndexForward: aws.Bool(false), // ULIDs sort lexically = chronologically, so this is newest-first
	}
	if limit > 0 {
		in.Limit = aws.Int32(int32(limit))
	}
	out, err := r.s.client.Query(ctx, in)
	if err != nil {
		return nil, err
	}
	versions := make([]*store.FunctionVersion, 0, len(out.Items))
	for _, item := range out.Items {
		var it versionItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		versions = append(versions, versionFromItem(&it))
	}
	return versions, nil
}

// SetEnv upserts the env var via a partial UpdateExpression: ValueEnc and
// UpdatedAt are always overwritten, while Entity/FunctionID/EnvKey/CreatedAt
// use if_not_exists so a first-time SetEnv (insert) and a later SetEnv
// (overwrite/rotate, per this method's doc comment) both do the right
// thing in one call, matching the SQL backends'
// "ON CONFLICT DO UPDATE" upsert.
func (r *functionRepo) SetEnv(ctx context.Context, funcID, key string, valueEnc []byte) error {
	now := nowUnix()
	upd := expression.Set(expression.Name("ValueEnc"), expression.Value(valueEnc)).
		Set(expression.Name("UpdatedAt"), expression.Value(now)).
		Set(expression.Name("CreatedAt"), expression.IfNotExists(expression.Name("CreatedAt"), expression.Value(now))).
		Set(expression.Name("Entity"), expression.IfNotExists(expression.Name("Entity"), expression.Value(entityEnvVar))).
		Set(expression.Name("FunctionID"), expression.IfNotExists(expression.Name("FunctionID"), expression.Value(funcID))).
		Set(expression.Name("EnvKey"), expression.IfNotExists(expression.Name("EnvKey"), expression.Value(key)))
	return r.s.upsertItem(ctx, pkFunc(funcID), skEnv(key), upd)
}

func (r *functionRepo) DeleteEnv(ctx context.Context, funcID, key string) error {
	return r.s.deleteItem(ctx, pkFunc(funcID), skEnv(key))
}

func (r *functionRepo) ListEnv(ctx context.Context, funcID string) (map[string][]byte, error) {
	out, err := r.s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(r.s.table),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :pfx)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":  &types.AttributeValueMemberS{Value: pkFunc(funcID)},
			":pfx": &types.AttributeValueMemberS{Value: "ENV#"},
		},
	})
	if err != nil {
		return nil, err
	}
	env := make(map[string][]byte, len(out.Items))
	for _, item := range out.Items {
		var it envVarItem
		if err := unmarshalMap(item, &it); err != nil {
			return nil, err
		}
		env[it.EnvKey] = it.ValueEnc
	}
	return env, nil
}

// itemKeyStrings extracts the PK/SK string values from a raw item map, for
// building a DeleteRequest key from a Query result.
func itemKeyStrings(item map[string]types.AttributeValue) (pk, sk string) {
	if v, ok := item["PK"].(*types.AttributeValueMemberS); ok {
		pk = v.Value
	}
	if v, ok := item["SK"].(*types.AttributeValueMemberS); ok {
		sk = v.Value
	}
	return pk, sk
}
