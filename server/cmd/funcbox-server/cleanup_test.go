package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

func newCleanupTestStore(t *testing.T) store.Store {
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

// TestOAuthCleanupSweep_WiresClientTTLAndAuthCodeExpiryTogether runs
// runOAuthCleanup's sweep exactly once (a pre-canceled context makes the
// ticker loop return immediately after that first call) against a real
// sqlite store, confirming it wires both halves of the DCR storage-
// exhaustion defense's periodic sweep (security review finding A)
// correctly: an expired oauth_auth_code is gone afterward, and a
// just-registered (therefore far younger than oauthClientUnusedTTL)
// client survives regardless of whether it has a grant.
//
// The TTL-vs-grant deletion DECISION itself (an old, unused client is
// swept; one with a grant is kept regardless of age) is exercised more
// directly, and independent of any real-clock TTL, by
// storetest.testOAuthClientDeleteUnusedOlderThan -- this test's job is
// only to confirm this package's goroutine actually calls that store
// method (and OAuthAuthCodes().DeleteExpired) with sane arguments.
func TestOAuthCleanupSweep_WiresClientTTLAndAuthCodeExpiryTogether(t *testing.T) {
	st := newCleanupTestStore(t)
	ctx := context.Background()

	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sweep-test-sub", Email: "sweep@example.com", Role: store.RoleMember, Status: store.UserStatusActive}
	if err := st.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	freshUnused := &store.OAuthClient{Name: "fresh-unused", RedirectURIs: []string{"https://unused.example.com/cb"}}
	if err := st.OAuthClients().Create(ctx, freshUnused); err != nil {
		t.Fatal(err)
	}
	withGrant := &store.OAuthClient{Name: "with-grant", RedirectURIs: []string{"https://active.example.com/cb"}}
	if err := st.OAuthClients().Create(ctx, withGrant); err != nil {
		t.Fatal(err)
	}
	grant := &store.OAuthGrant{UserID: u.ID, ClientID: withGrant.ID, SecretHash: "cleanup-test-grant-hash"}
	if err := st.OAuthGrants().Create(ctx, grant); err != nil {
		t.Fatalf("OAuthGrants().Create: %v", err)
	}
	expiredCode := &store.OAuthAuthCode{ID: "cleanup-test-code-hash", UserID: u.ID, ClientID: withGrant.ID,
		RedirectURI: "https://active.example.com/cb", Challenge: "chal", ExpiresAt: time.Now().Add(-time.Minute)}
	if err := st.OAuthAuthCodes().Create(ctx, expiredCode); err != nil {
		t.Fatalf("OAuthAuthCodes().Create: %v", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // run exactly one sweep(), then return immediately
	runOAuthCleanup(cancelCtx, st, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Both clients were created moments ago, far younger than
	// oauthClientUnusedTTL (30 days) -- neither is swept yet, regardless
	// of grant status.
	if _, err := st.OAuthClients().ByID(ctx, freshUnused.ID); err != nil {
		t.Fatalf("ByID(freshUnused) after sweep: %v, want it to survive (younger than oauthClientUnusedTTL)", err)
	}
	if _, err := st.OAuthClients().ByID(ctx, withGrant.ID); err != nil {
		t.Fatalf("ByID(withGrant) after sweep: %v, want it to survive", err)
	}
	// The expired auth code, however, has no TTL grace period -- it must
	// be gone (Consume treats "gone" and "never existed" identically, so
	// this also confirms Create's own opportunistic cleanup didn't
	// already remove it before the sweep had a chance to).
	if _, err := st.OAuthAuthCodes().Consume(ctx, expiredCode.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Consume(expired code) after sweep = %v, want ErrNotFound", err)
	}
}
