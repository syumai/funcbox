package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func claimUserIDForTest(t *testing.T, st store.Store, userID string) {
	t.Helper()
	u := &store.User{GoogleSub: "sub-" + userID, Email: userID + "@example.com", Name: userID}
	if err := st.Users().Create(context.Background(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.PublicUserIDs().Create(context.Background(), &store.PublicUserID{
		UserID: userID, InternalUserID: u.ID,
	}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
}

func TestDeriveUserID_Basic(t *testing.T) {
	st := newTestStore(t)
	got, err := DeriveUserID(context.Background(), st, "alice@example.com")
	if err != nil {
		t.Fatalf("DeriveUserID: %v", err)
	}
	if got != "alice" {
		t.Fatalf("DeriveUserID = %q, want %q", got, "alice")
	}
}

func TestDeriveUserID_Sanitizes(t *testing.T) {
	st := newTestStore(t)
	got, err := DeriveUserID(context.Background(), st, "Alice.Smith+dev@example.com")
	if err != nil {
		t.Fatalf("DeriveUserID: %v", err)
	}
	// '.', '+' aren't DNS-label characters and should become '-'.
	if got != "alice-smith-dev" {
		t.Fatalf("DeriveUserID = %q, want %q", got, "alice-smith-dev")
	}
}

func TestDeriveUserID_CollisionAppendsSuffix(t *testing.T) {
	st := newTestStore(t)
	claimUserIDForTest(t, st, "alice")

	got, err := DeriveUserID(context.Background(), st, "alice@other.com")
	if err != nil {
		t.Fatalf("DeriveUserID: %v", err)
	}
	if got != "alice-2" {
		t.Fatalf("DeriveUserID = %q, want %q", got, "alice-2")
	}
}

func TestDeriveUserID_MultipleCollisionsIncrementSuffix(t *testing.T) {
	st := newTestStore(t)
	claimUserIDForTest(t, st, "bob")
	claimUserIDForTest(t, st, "bob-2")
	claimUserIDForTest(t, st, "bob-3")

	got, err := DeriveUserID(context.Background(), st, "bob@other.com")
	if err != nil {
		t.Fatalf("DeriveUserID: %v", err)
	}
	if got != "bob-4" {
		t.Fatalf("DeriveUserID = %q, want %q", got, "bob-4")
	}
}

func TestDeriveUserID_ReservedNameSkipped(t *testing.T) {
	st := newTestStore(t)
	// "api" is a reserved top-level route name (manifest.ReservedNames).
	got, err := DeriveUserID(context.Background(), st, "api@example.com")
	if err != nil {
		t.Fatalf("DeriveUserID: %v", err)
	}
	if got == "api" {
		t.Fatalf("DeriveUserID returned the reserved name %q", got)
	}
	if got != "api-2" {
		t.Fatalf("DeriveUserID = %q, want %q", got, "api-2")
	}
}

func TestDeriveUserID_EmptyLocalPartFallsBackToUser(t *testing.T) {
	st := newTestStore(t)
	got, err := DeriveUserID(context.Background(), st, "+++@example.com")
	if err != nil {
		t.Fatalf("DeriveUserID: %v", err)
	}
	if !strings.HasPrefix(got, "user") {
		t.Fatalf("DeriveUserID = %q, want it to fall back to \"user\"-prefixed", got)
	}
}

func TestDeriveUserID_ResultIsAlwaysValid(t *testing.T) {
	st := newTestStore(t)
	longLocal := strings.Repeat("a", 100)
	got, err := DeriveUserID(context.Background(), st, longLocal+"@example.com")
	if err != nil {
		t.Fatalf("DeriveUserID: %v", err)
	}
	if len(got) > 63 {
		t.Fatalf("DeriveUserID returned a %d-character User ID, want <= 63", len(got))
	}
}
