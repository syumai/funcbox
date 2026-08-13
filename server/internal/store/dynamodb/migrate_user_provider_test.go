package dynamodb

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
)

// legacyUserItem is the shape a primary user item had before this package
// generalized google_sub/disabled into provider/provider_subject/status
// (tmp/13-public-mode.md §13.2/§13.3). It's used only to seed
// TestMigrateUserProviderPointers with a realistic pre-migration item;
// production code never constructs this again.
type legacyUserItem struct {
	PK        string
	SK        string
	Entity    string
	ID        string
	GoogleSub string
	Email     string
	Name      string
	Role      string
	Disabled  bool
	Language  string
	CreatedAt int64
	UpdatedAt int64
}

// legacyUserSubPointerItem is the pre-migration lookup-pointer shape at
// PK=USER#SUB#<google_sub>.
type legacyUserSubPointerItem struct {
	PK     string
	SK     string
	Entity string
	UserID string
}

func TestMigrateUserProviderPointers(t *testing.T) {
	endpoint := os.Getenv("FUNCBOX_TEST_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("FUNCBOX_TEST_DYNAMODB_ENDPOINT not set")
	}

	ctx := context.Background()
	s, err := Open(ctx, Options{
		TableName: "funcbox_user_provider_migration_" + store.NewID(),
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
	legacyItemMap, err := marshalMap(&legacyUserItem{
		PK: pkUser("legacy-user"), SK: skMeta, Entity: entityUser,
		ID: "legacy-user", GoogleSub: "legacy-sub", Email: "legacy@example.com", Name: "Legacy",
		Role: string(store.RoleMember), Disabled: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("marshal legacy user: %v", err)
	}
	if err := s.putItem(ctx, legacyItemMap); err != nil {
		t.Fatalf("put legacy user: %v", err)
	}
	legacyPtrMap, err := marshalMap(&legacyUserSubPointerItem{
		PK: pkUserSubLegacy("legacy-sub"), SK: skMeta, Entity: entityUserProviderSubjectPointer, UserID: "legacy-user",
	})
	if err != nil {
		t.Fatalf("marshal legacy pointer: %v", err)
	}
	if err := s.putItem(ctx, legacyPtrMap); err != nil {
		t.Fatalf("put legacy pointer: %v", err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Idempotency: a second call must not error or change the outcome.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	got, err := s.Users().ByProviderSubject(ctx, store.ProviderGoogle, "legacy-sub")
	if err != nil {
		t.Fatalf("ByProviderSubject(after migration): %v", err)
	}
	if got.ID != "legacy-user" {
		t.Fatalf("got.ID = %q, want %q", got.ID, "legacy-user")
	}
	if got.Status != store.UserStatusDisabled {
		t.Fatalf("got.Status = %q, want %q", got.Status, store.UserStatusDisabled)
	}

	// The old USER#SUB# pointer item must be gone.
	if _, err := s.getItem(ctx, pkUserSubLegacy("legacy-sub"), skMeta); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("legacy pointer lookup error = %v, want ErrNotFound", err)
	}
}

func TestBackfillFunctionCreatedBy(t *testing.T) {
	endpoint := os.Getenv("FUNCBOX_TEST_DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("FUNCBOX_TEST_DYNAMODB_ENDPOINT not set")
	}

	ctx := context.Background()
	s, err := Open(ctx, Options{
		TableName: "funcbox_created_by_backfill_" + store.NewID(),
		Endpoint:  endpoint,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}

	owner := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "owner-sub", Email: "owner@example.com", Name: "Owner", Status: store.UserStatusActive}
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	other := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "other-sub", Email: "other@example.com", Name: "Other", Status: store.UserStatusActive}
	if err := s.Users().Create(ctx, other); err != nil {
		t.Fatalf("Users().Create(other): %v", err)
	}

	// A "legacy" function with no CreatedBy (as if migrated from a
	// pre-0009 database), plus two versions -- the OLDER one's creator
	// must win the backfill.
	fn := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "backfill-target"}
	if err := s.Functions().Create(ctx, fn); err != nil {
		t.Fatalf("Functions().Create: %v", err)
	}
	older := &store.FunctionVersion{FunctionID: fn.ID, Manifest: []byte("{}"), MainPath: "index.js", BundleHash: "a", CreatedBy: owner.ID}
	if err := s.Functions().CreateVersion(ctx, older); err != nil {
		t.Fatalf("CreateVersion(older): %v", err)
	}
	newer := &store.FunctionVersion{FunctionID: fn.ID, Manifest: []byte("{}"), MainPath: "index.js", BundleHash: "b", CreatedBy: other.ID}
	if err := s.Functions().CreateVersion(ctx, newer); err != nil {
		t.Fatalf("CreateVersion(newer): %v", err)
	}

	// A function with no versions at all: nothing to backfill from, must
	// stay nil.
	noVersions := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "no-versions"}
	if err := s.Functions().Create(ctx, noVersions); err != nil {
		t.Fatalf("Functions().Create(noVersions): %v", err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	got, err := s.Functions().ByID(ctx, fn.ID)
	if err != nil {
		t.Fatalf("Functions().ByID: %v", err)
	}
	if got.CreatedBy == nil || *got.CreatedBy != owner.ID {
		t.Fatalf("fn.CreatedBy = %v, want %q (the older version's creator)", got.CreatedBy, owner.ID)
	}

	gotNoVersions, err := s.Functions().ByID(ctx, noVersions.ID)
	if err != nil {
		t.Fatalf("Functions().ByID(noVersions): %v", err)
	}
	if gotNoVersions.CreatedBy != nil {
		t.Fatalf("noVersions.CreatedBy = %v, want nil", gotNoVersions.CreatedBy)
	}
}
