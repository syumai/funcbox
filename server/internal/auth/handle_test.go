package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/internal/store/sqlite"
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

func claimHandleForTest(t *testing.T, st store.Store, handle string) {
	t.Helper()
	u := &store.User{GoogleSub: "sub-" + handle, Email: handle + "@example.com", Name: handle}
	if err := st.Users().Create(context.Background(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.Handles().Create(context.Background(), &store.Handle{
		Handle: handle, OwnerType: store.OwnerTypeUser, OwnerID: u.ID,
	}); err != nil {
		t.Fatalf("Handles().Create: %v", err)
	}
}

func TestDeriveHandle_Basic(t *testing.T) {
	st := newTestStore(t)
	got, err := DeriveHandle(context.Background(), st, "alice@example.com")
	if err != nil {
		t.Fatalf("DeriveHandle: %v", err)
	}
	if got != "alice" {
		t.Fatalf("DeriveHandle = %q, want %q", got, "alice")
	}
}

func TestDeriveHandle_Sanitizes(t *testing.T) {
	st := newTestStore(t)
	got, err := DeriveHandle(context.Background(), st, "Alice.Smith+dev@example.com")
	if err != nil {
		t.Fatalf("DeriveHandle: %v", err)
	}
	// '.', '+' aren't DNS-label characters and should become '-'.
	if got != "alice-smith-dev" {
		t.Fatalf("DeriveHandle = %q, want %q", got, "alice-smith-dev")
	}
}

func TestDeriveHandle_CollisionAppendsSuffix(t *testing.T) {
	st := newTestStore(t)
	claimHandleForTest(t, st, "alice")

	got, err := DeriveHandle(context.Background(), st, "alice@other.com")
	if err != nil {
		t.Fatalf("DeriveHandle: %v", err)
	}
	if got != "alice-2" {
		t.Fatalf("DeriveHandle = %q, want %q", got, "alice-2")
	}
}

func TestDeriveHandle_MultipleCollisionsIncrementSuffix(t *testing.T) {
	st := newTestStore(t)
	claimHandleForTest(t, st, "bob")
	claimHandleForTest(t, st, "bob-2")
	claimHandleForTest(t, st, "bob-3")

	got, err := DeriveHandle(context.Background(), st, "bob@other.com")
	if err != nil {
		t.Fatalf("DeriveHandle: %v", err)
	}
	if got != "bob-4" {
		t.Fatalf("DeriveHandle = %q, want %q", got, "bob-4")
	}
}

func TestDeriveHandle_ReservedNameSkipped(t *testing.T) {
	st := newTestStore(t)
	// "api" is a reserved top-level route name (manifest.ReservedNames).
	got, err := DeriveHandle(context.Background(), st, "api@example.com")
	if err != nil {
		t.Fatalf("DeriveHandle: %v", err)
	}
	if got == "api" {
		t.Fatalf("DeriveHandle returned the reserved name %q", got)
	}
	if got != "api-2" {
		t.Fatalf("DeriveHandle = %q, want %q", got, "api-2")
	}
}

func TestDeriveHandle_EmptyLocalPartFallsBackToUser(t *testing.T) {
	st := newTestStore(t)
	got, err := DeriveHandle(context.Background(), st, "+++@example.com")
	if err != nil {
		t.Fatalf("DeriveHandle: %v", err)
	}
	if !strings.HasPrefix(got, "user") {
		t.Fatalf("DeriveHandle = %q, want it to fall back to \"user\"-prefixed", got)
	}
}

func TestDeriveHandle_ResultIsAlwaysValid(t *testing.T) {
	st := newTestStore(t)
	longLocal := strings.Repeat("a", 100)
	got, err := DeriveHandle(context.Background(), st, longLocal+"@example.com")
	if err != nil {
		t.Fatalf("DeriveHandle: %v", err)
	}
	if len(got) > 63 {
		t.Fatalf("DeriveHandle returned a %d-char handle, want <= 63", len(got))
	}
}
