package dynamodb

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
)

func TestRemoveLegacyWorkspaceHandles(t *testing.T) {
	endpoint := os.Getenv("FUNCBOX_TEST_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("FUNCBOX_TEST_DYNAMODB_ENDPOINT not set")
	}

	ctx := context.Background()
	s, err := Open(ctx, Options{
		TableName: "funcbox_workspace_handle_migration_" + store.NewID(),
		Endpoint:  endpoint,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}

	now := nowUnix()
	legacy, err := marshalMap(&handleItem{
		PK: pkHandle("legacy-workspace"), SK: skMeta, Entity: entityHandle,
		Handle: "legacy-workspace", OwnerType: string(store.OwnerTypeWorkspace), OwnerID: "ws-1",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("marshal legacy handle: %v", err)
	}
	if err := s.putItem(ctx, legacy); err != nil {
		t.Fatalf("put legacy handle: %v", err)
	}
	if err := s.PublicUserIDs().Create(ctx, &store.PublicUserID{
		UserID: "alice", InternalUserID: "user-1",
	}); err != nil {
		t.Fatalf("create public User ID: %v", err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	if _, err := s.getItem(ctx, pkHandle("legacy-workspace"), skMeta); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy workspace handle lookup error = %v, want ErrNotFound", err)
	}
	if _, err := s.PublicUserIDs().ByUserID(ctx, "alice"); err != nil {
		t.Fatalf("public User ID removed by migration: %v", err)
	}
}
