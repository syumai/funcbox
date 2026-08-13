// Package storetest provides a conformance test suite that every
// store.Store implementation should pass. Backend packages call TestStore
// from their own tests, supplying a constructor for a fresh, already
// migrated store.
package storetest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syumai/funcbox/internal/store"
)

// TestStore runs the store.Store conformance suite against the store
// produced by newStore. newStore is called once per subtest (and, within
// the concurrency subtest, exactly once for that subtest — the concurrent
// calls all race against the single returned Store) and must return a
// fresh store with its schema already migrated (i.e. Migrate has been
// called).
func TestStore(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()

	t.Run("BootstrapFirstUser", func(t *testing.T) { testBootstrapFirstUser(t, newStore) })
	t.Run("BootstrapFirstUserConcurrent", func(t *testing.T) { testBootstrapFirstUserConcurrent(t, newStore) })
	t.Run("HandleUniqueness", func(t *testing.T) { testHandleUniqueness(t, newStore) })
	t.Run("CreateWorkspace", func(t *testing.T) { testCreateWorkspace(t, newStore) })
	t.Run("FunctionCRUDAndVersions", func(t *testing.T) { testFunctionCRUDAndVersions(t, newStore) })
	t.Run("EnvVars", func(t *testing.T) { testEnvVars(t, newStore) })
	t.Run("SessionExpiryFilter", func(t *testing.T) { testSessionExpiryFilter(t, newStore) })
	t.Run("SessionRefresh", func(t *testing.T) { testSessionRefresh(t, newStore) })
	t.Run("TokenLookupByHash", func(t *testing.T) { testTokenLookupByHash(t, newStore) })
	t.Run("AuditAppendAndList", func(t *testing.T) { testAuditAppendAndList(t, newStore) })
	t.Run("InvocationLogAppendAndList", func(t *testing.T) { testInvocationLogAppendAndList(t, newStore) })
	t.Run("InvocationLogDeleteOlderThan", func(t *testing.T) { testInvocationLogDeleteOlderThan(t, newStore) })
}

// uniqueUser returns a User with randomized GoogleSub/Email so tests can
// create as many as they need without colliding on the unique constraints.
func uniqueUser(name string) *store.User {
	id := store.NewID()
	return &store.User{
		GoogleSub: "sub-" + id,
		Email:     "user-" + id + "@example.com",
		Name:      name,
	}
}

func testBootstrapFirstUser(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	u := uniqueUser("Admin")
	if err := s.BootstrapFirstUser(ctx, u, "Acme Corp"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if u.Role != store.RoleAdmin {
		t.Fatalf("bootstrapped user role = %q, want %q", u.Role, store.RoleAdmin)
	}
	if u.ID == "" {
		t.Fatal("bootstrapped user ID is empty")
	}
	if u.CreatedAt.IsZero() {
		t.Fatal("bootstrapped user CreatedAt is zero")
	}

	org, err := s.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	if org.Name != "Acme Corp" {
		t.Fatalf("org.Name = %q, want %q", org.Name, "Acme Corp")
	}

	got, err := s.Users().ByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if got.Role != store.RoleAdmin {
		t.Fatalf("stored user role = %q, want %q", got.Role, store.RoleAdmin)
	}

	// A second bootstrap attempt must fail: the org already has a user.
	u2 := uniqueUser("Second")
	err = s.BootstrapFirstUser(ctx, u2, "Other Org")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second BootstrapFirstUser error = %v, want ErrConflict", err)
	}

	users, err := s.Users().List(ctx)
	if err != nil {
		t.Fatalf("Users().List: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("len(Users().List()) = %d, want 1", len(users))
	}
}

func testBootstrapFirstUserConcurrent(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	const n = 8
	var wg sync.WaitGroup
	var successes int32
	errs := make([]error, n)
	users := make([]*store.User, n)
	for i := 0; i < n; i++ {
		users[i] = uniqueUser("Candidate")
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.BootstrapFirstUser(ctx, users[i], "Race Corp")
			if errs[i] == nil {
				atomic.AddInt32(&successes, 1)
			}
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successful BootstrapFirstUser calls = %d, want exactly 1", successes)
	}
	for i, err := range errs {
		if err != nil && !errors.Is(err, store.ErrConflict) {
			t.Fatalf("call %d: unexpected error %v (want nil or ErrConflict)", i, err)
		}
	}

	all, err := s.Users().List(ctx)
	if err != nil {
		t.Fatalf("Users().List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("len(Users().List()) = %d, want exactly 1 admin", len(all))
	}
	if all[0].Role != store.RoleAdmin {
		t.Fatalf("the single user's role = %q, want %q", all[0].Role, store.RoleAdmin)
	}
}

func testHandleUniqueness(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	u1 := uniqueUser("Alice")
	if err := s.Users().Create(ctx, u1); err != nil {
		t.Fatalf("Users().Create(u1): %v", err)
	}
	u2 := uniqueUser("Alice2")
	if err := s.Users().Create(ctx, u2); err != nil {
		t.Fatalf("Users().Create(u2): %v", err)
	}

	h1 := &store.Handle{Handle: "alice", OwnerType: store.OwnerTypeUser, OwnerID: u1.ID}
	if err := s.Handles().Create(ctx, h1); err != nil {
		t.Fatalf("Handles().Create(h1): %v", err)
	}

	// Same handle string, different user: must conflict.
	h2 := &store.Handle{Handle: "alice", OwnerType: store.OwnerTypeUser, OwnerID: u2.ID}
	if err := s.Handles().Create(ctx, h2); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Handles().Create(duplicate handle, different user) error = %v, want ErrConflict", err)
	}

	// Same handle string, this time claimed by a workspace: must also
	// conflict, proving users and workspaces share one namespace.
	ws := &store.Workspace{Name: "Alice's Team"}
	if err := s.CreateWorkspace(ctx, ws, "alice", u1.ID); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("CreateWorkspace(duplicate handle) error = %v, want ErrConflict", err)
	}

	got, err := s.Handles().ByHandle(ctx, "alice")
	if err != nil {
		t.Fatalf("Handles().ByHandle: %v", err)
	}
	if got.OwnerID != u1.ID {
		t.Fatalf("handle owner = %q, want %q (the original claimant)", got.OwnerID, u1.ID)
	}

	byOwner, err := s.Handles().ByOwner(ctx, store.OwnerTypeUser, u1.ID)
	if err != nil {
		t.Fatalf("Handles().ByOwner: %v", err)
	}
	if byOwner.Handle != "alice" {
		t.Fatalf("Handles().ByOwner.Handle = %q, want %q", byOwner.Handle, "alice")
	}
}

func testCreateWorkspace(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	creator := uniqueUser("Creator")
	if err := s.Users().Create(ctx, creator); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	ws := &store.Workspace{Name: "Platform Team"}
	if err := s.CreateWorkspace(ctx, ws, "platform", creator.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	if ws.ID == "" {
		t.Fatal("CreateWorkspace did not assign an ID")
	}

	h, err := s.Handles().ByHandle(ctx, "platform")
	if err != nil {
		t.Fatalf("Handles().ByHandle: %v", err)
	}
	if h.OwnerType != store.OwnerTypeWorkspace || h.OwnerID != ws.ID {
		t.Fatalf("handle owner = (%q, %q), want (%q, %q)", h.OwnerType, h.OwnerID, store.OwnerTypeWorkspace, ws.ID)
	}

	members, err := s.Workspaces().ListMembers(ctx, ws.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].UserID != creator.ID || members[0].Role != store.RoleAdmin {
		t.Fatalf("members = %+v, want exactly [{%q admin}]", members, creator.ID)
	}

	wsList, err := s.Workspaces().ListForUser(ctx, creator.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(wsList) != 1 || wsList[0].ID != ws.ID {
		t.Fatalf("ListForUser = %+v, want exactly [%q]", wsList, ws.ID)
	}

	allWS, err := s.Workspaces().ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(allWS) != 1 || allWS[0].ID != ws.ID {
		t.Fatalf("ListAll = %+v, want exactly [%q]", allWS, ws.ID)
	}

	// Membership management.
	member2 := uniqueUser("Member2")
	if err := s.Users().Create(ctx, member2); err != nil {
		t.Fatalf("Users().Create(member2): %v", err)
	}
	if err := s.Workspaces().AddMember(ctx, &store.WorkspaceMember{WorkspaceID: ws.ID, UserID: member2.ID, Role: store.RoleMember}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := s.Workspaces().UpdateMemberRole(ctx, ws.ID, member2.ID, store.RoleAdmin); err != nil {
		t.Fatalf("UpdateMemberRole: %v", err)
	}
	members, err = s.Workspaces().ListMembers(ctx, ws.ID)
	if err != nil {
		t.Fatalf("ListMembers (after add): %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("len(members) = %d, want 2", len(members))
	}
	if err := s.Workspaces().RemoveMember(ctx, ws.ID, member2.ID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	members, err = s.Workspaces().ListMembers(ctx, ws.ID)
	if err != nil {
		t.Fatalf("ListMembers (after remove): %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("len(members) after remove = %d, want 1", len(members))
	}
}

func testFunctionCRUDAndVersions(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Owner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	f := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "hello"}
	if err := s.Functions().Create(ctx, f); err != nil {
		t.Fatalf("Functions().Create: %v", err)
	}
	if f.ActiveVersionID != nil {
		t.Fatalf("new function ActiveVersionID = %v, want nil", f.ActiveVersionID)
	}

	// Duplicate (owner, name) must conflict.
	dup := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "hello"}
	if err := s.Functions().Create(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate Functions().Create error = %v, want ErrConflict", err)
	}

	got, err := s.Functions().ByOwnerAndName(ctx, store.OwnerTypeUser, owner.ID, "hello")
	if err != nil {
		t.Fatalf("ByOwnerAndName: %v", err)
	}
	if got.ID != f.ID {
		t.Fatalf("ByOwnerAndName.ID = %q, want %q", got.ID, f.ID)
	}

	v1 := &store.FunctionVersion{
		FunctionID:   f.ID,
		Manifest:     []byte(`{"name":"hello"}`),
		MainPath:     "index.js",
		BundleHash:   "deadbeef",
		BundleSize:   100,
		UnpackedSize: 200,
		Files:        []byte(`[{"path":"index.js","size":200}]`),
		CreatedBy:    owner.ID,
		Note:         "initial",
	}
	if err := s.Functions().CreateVersion(ctx, v1); err != nil {
		t.Fatalf("CreateVersion(v1): %v", err)
	}
	if v1.ID == "" {
		t.Fatal("CreateVersion did not assign an ID")
	}

	v2 := &store.FunctionVersion{
		FunctionID:   f.ID,
		Manifest:     []byte(`{"name":"hello","v":2}`),
		MainPath:     "index.js",
		BundleHash:   "cafebabe",
		BundleSize:   150,
		UnpackedSize: 250,
		Files:        []byte(`[{"path":"index.js","size":250}]`),
		CreatedBy:    owner.ID,
		Note:         "v2",
	}
	if err := s.Functions().CreateVersion(ctx, v2); err != nil {
		t.Fatalf("CreateVersion(v2): %v", err)
	}

	gotV, err := s.Functions().Version(ctx, v1.ID)
	if err != nil {
		t.Fatalf("Version(v1): %v", err)
	}
	if gotV.BundleHash != "deadbeef" {
		t.Fatalf("gotV.BundleHash = %q, want %q", gotV.BundleHash, "deadbeef")
	}

	versions, err := s.Functions().ListVersions(ctx, f.ID, 0)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("len(ListVersions) = %d, want 2", len(versions))
	}

	// ActivateVersion: activating v1 on f must succeed and be visible.
	if err := s.ActivateVersion(ctx, f.ID, v1.ID); err != nil {
		t.Fatalf("ActivateVersion(f, v1): %v", err)
	}
	got, err = s.Functions().ByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("ByID (after activate): %v", err)
	}
	if got.ActiveVersionID == nil || *got.ActiveVersionID != v1.ID {
		t.Fatalf("ActiveVersionID = %v, want %q", got.ActiveVersionID, v1.ID)
	}

	// ActivateVersion atomicity: activating a version that belongs to a
	// *different* function must fail and must not change f's active
	// version.
	f2 := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "other"}
	if err := s.Functions().Create(ctx, f2); err != nil {
		t.Fatalf("Functions().Create(f2): %v", err)
	}
	v3 := &store.FunctionVersion{
		FunctionID: f2.ID, Manifest: []byte(`{}`), MainPath: "index.js",
		BundleHash: "f00d", BundleSize: 1, UnpackedSize: 1, Files: []byte(`[]`), CreatedBy: owner.ID,
	}
	if err := s.Functions().CreateVersion(ctx, v3); err != nil {
		t.Fatalf("CreateVersion(v3): %v", err)
	}
	if err := s.ActivateVersion(ctx, f.ID, v3.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ActivateVersion(f, v3-belongs-to-f2) error = %v, want ErrNotFound", err)
	}
	got, err = s.Functions().ByID(ctx, f.ID)
	if err != nil {
		t.Fatalf("ByID (after failed activate): %v", err)
	}
	if got.ActiveVersionID == nil || *got.ActiveVersionID != v1.ID {
		t.Fatalf("ActiveVersionID after failed activate = %v, want unchanged %q", got.ActiveVersionID, v1.ID)
	}

	byOwner, err := s.Functions().ListByOwner(ctx, store.OwnerTypeUser, owner.ID)
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}
	if len(byOwner) != 2 {
		t.Fatalf("len(ListByOwner) = %d, want 2", len(byOwner))
	}

	visible, err := s.Functions().ListVisibleTo(ctx, owner.ID)
	if err != nil {
		t.Fatalf("ListVisibleTo: %v", err)
	}
	if len(visible) != 2 {
		t.Fatalf("len(ListVisibleTo) = %d, want 2", len(visible))
	}

	all, err := s.Functions().ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("len(ListAll) = %d, want 2", len(all))
	}

	if err := s.Functions().Delete(ctx, f2.ID); err != nil {
		t.Fatalf("Delete(f2): %v", err)
	}
	if _, err := s.Functions().ByID(ctx, f2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ByID(deleted f2) error = %v, want ErrNotFound", err)
	}
}

func testEnvVars(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Owner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	f := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "envfn"}
	if err := s.Functions().Create(ctx, f); err != nil {
		t.Fatalf("Functions().Create: %v", err)
	}

	if err := s.Functions().SetEnv(ctx, f.ID, "API_KEY", []byte("enc1")); err != nil {
		t.Fatalf("SetEnv(API_KEY): %v", err)
	}
	if err := s.Functions().SetEnv(ctx, f.ID, "DEBUG", []byte("enc2")); err != nil {
		t.Fatalf("SetEnv(DEBUG): %v", err)
	}

	env, err := s.Functions().ListEnv(ctx, f.ID)
	if err != nil {
		t.Fatalf("ListEnv: %v", err)
	}
	if len(env) != 2 || string(env["API_KEY"]) != "enc1" || string(env["DEBUG"]) != "enc2" {
		t.Fatalf("ListEnv = %v, want API_KEY=enc1, DEBUG=enc2", env)
	}

	// SetEnv on an existing key overwrites (upsert), not duplicates.
	if err := s.Functions().SetEnv(ctx, f.ID, "API_KEY", []byte("enc1-rotated")); err != nil {
		t.Fatalf("SetEnv(API_KEY, rotate): %v", err)
	}
	env, err = s.Functions().ListEnv(ctx, f.ID)
	if err != nil {
		t.Fatalf("ListEnv (after rotate): %v", err)
	}
	if len(env) != 2 || string(env["API_KEY"]) != "enc1-rotated" {
		t.Fatalf("ListEnv (after rotate) = %v, want API_KEY=enc1-rotated", env)
	}

	if err := s.Functions().DeleteEnv(ctx, f.ID, "DEBUG"); err != nil {
		t.Fatalf("DeleteEnv(DEBUG): %v", err)
	}
	env, err = s.Functions().ListEnv(ctx, f.ID)
	if err != nil {
		t.Fatalf("ListEnv (after delete): %v", err)
	}
	if len(env) != 1 {
		t.Fatalf("len(ListEnv) after delete = %d, want 1", len(env))
	}
	if _, ok := env["DEBUG"]; ok {
		t.Fatal("DEBUG still present after DeleteEnv")
	}
}

func testSessionExpiryFilter(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Owner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	live := &store.Session{UserID: owner.ID, ExpiresAt: now.Add(1 * time.Hour)}
	if err := s.Sessions().Create(ctx, live); err != nil {
		t.Fatalf("Sessions().Create(live): %v", err)
	}
	expired := &store.Session{UserID: owner.ID, ExpiresAt: now.Add(-1 * time.Hour)}
	if err := s.Sessions().Create(ctx, expired); err != nil {
		t.Fatalf("Sessions().Create(expired): %v", err)
	}

	got, err := s.Sessions().Get(ctx, live.ID, now)
	if err != nil {
		t.Fatalf("Sessions().Get(live): %v", err)
	}
	if got.ID != live.ID {
		t.Fatalf("got.ID = %q, want %q", got.ID, live.ID)
	}

	if _, err := s.Sessions().Get(ctx, expired.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Sessions().Get(expired) error = %v, want ErrNotFound", err)
	}

	n, err := s.Sessions().DeleteExpired(ctx, now)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 1 {
		t.Fatalf("DeleteExpired removed %d, want 1", n)
	}

	// The live session must survive DeleteExpired.
	if _, err := s.Sessions().Get(ctx, live.ID, now); err != nil {
		t.Fatalf("Sessions().Get(live) after DeleteExpired: %v", err)
	}
}

func testSessionRefresh(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Owner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	sess := &store.Session{UserID: owner.ID, ExpiresAt: now.Add(1 * time.Hour)}
	if err := s.Sessions().Create(ctx, sess); err != nil {
		t.Fatalf("Sessions().Create: %v", err)
	}

	newExpiry := now.Add(7 * 24 * time.Hour)
	if err := s.Sessions().Refresh(ctx, sess.ID, newExpiry); err != nil {
		t.Fatalf("Sessions().Refresh: %v", err)
	}

	// The session must still be valid just after its original (now
	// stale) expiry, since Refresh pushed the deadline out.
	got, err := s.Sessions().Get(ctx, sess.ID, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("Sessions().Get (after refresh, past original expiry): %v", err)
	}
	if !got.ExpiresAt.Equal(newExpiry) {
		t.Fatalf("got.ExpiresAt = %v, want %v", got.ExpiresAt, newExpiry)
	}

	if err := s.Sessions().Refresh(ctx, "no-such-session", newExpiry); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Sessions().Refresh(unknown id) error = %v, want ErrNotFound", err)
	}
}

func testTokenLookupByHash(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Owner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	tok := &store.APIToken{
		UserID:    owner.ID,
		TokenHash: "hash-abc123",
		Name:      "ci",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.Tokens().Create(ctx, tok); err != nil {
		t.Fatalf("Tokens().Create: %v", err)
	}

	got, err := s.Tokens().ByHash(ctx, "hash-abc123")
	if err != nil {
		t.Fatalf("Tokens().ByHash: %v", err)
	}
	if got.ID != tok.ID {
		t.Fatalf("got.ID = %q, want %q", got.ID, tok.ID)
	}

	if _, err := s.Tokens().ByHash(ctx, "no-such-hash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Tokens().ByHash(unknown) error = %v, want ErrNotFound", err)
	}

	list, err := s.Tokens().ListByUser(ctx, owner.ID)
	if err != nil {
		t.Fatalf("Tokens().ListByUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != tok.ID {
		t.Fatalf("ListByUser = %+v, want exactly [%q]", list, tok.ID)
	}

	if err := s.Tokens().Delete(ctx, tok.ID); err != nil {
		t.Fatalf("Tokens().Delete: %v", err)
	}
	if _, err := s.Tokens().ByHash(ctx, "hash-abc123"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Tokens().ByHash(deleted) error = %v, want ErrNotFound", err)
	}
}

func testAuditAppendAndList(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Actor")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	const total = 5
	ids := make([]string, total)
	for i := 0; i < total; i++ {
		a := &store.AuditLog{
			ActorID: owner.ID,
			Action:  "function.deploy",
			Target:  "function:test",
			Detail:  []byte(`{}`),
		}
		if err := s.Audit().Append(ctx, a); err != nil {
			t.Fatalf("Audit().Append #%d: %v", i, err)
		}
		ids[i] = a.ID
	}

	page1, err := s.Audit().List(ctx, "", 3)
	if err != nil {
		t.Fatalf("Audit().List (page 1): %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("len(page1) = %d, want 3", len(page1))
	}
	// Newest first: page1[0] should be the last one appended.
	if page1[0].ID != ids[total-1] {
		t.Fatalf("page1[0].ID = %q, want %q (most recently appended)", page1[0].ID, ids[total-1])
	}

	page2, err := s.Audit().List(ctx, page1[len(page1)-1].ID, 3)
	if err != nil {
		t.Fatalf("Audit().List (page 2): %v", err)
	}
	if len(page2) != total-3 {
		t.Fatalf("len(page2) = %d, want %d", len(page2), total-3)
	}

	seen := map[string]bool{}
	for _, a := range append(page1, page2...) {
		if seen[a.ID] {
			t.Fatalf("id %q appeared on both pages", a.ID)
		}
		seen[a.ID] = true
	}
	if len(seen) != total {
		t.Fatalf("total distinct entries seen across pages = %d, want %d", len(seen), total)
	}
}

// invocationLogFunction is a small shared setup helper: create a user and a
// function so tests only need a valid FunctionID.
func invocationLogFunction(t *testing.T, ctx context.Context, s store.Store) *store.Function {
	t.Helper()
	owner := uniqueUser("InvokeOwner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	f := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "logfn-" + store.NewID()}
	if err := s.Functions().Create(ctx, f); err != nil {
		t.Fatalf("Functions().Create: %v", err)
	}
	return f
}

func testInvocationLogAppendAndList(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)
	f := invocationLogFunction(t, ctx, s)

	const total = 5
	ids := make([]string, total)
	for i := 0; i < total; i++ {
		l := &store.InvocationLog{
			FunctionID:     f.ID,
			VersionID:      "ver-1",
			Method:         "GET",
			Path:           "/",
			Status:         200,
			DurationMS:     int64(10 + i),
			Stdout:         "hello",
			Stderr:         "",
			FetchDecisions: []byte(`[{"host":"example.com","allowed":true,"stage":"dial"}]`),
		}
		if err := s.InvocationLogs().Append(ctx, l); err != nil {
			t.Fatalf("InvocationLogs().Append #%d: %v", i, err)
		}
		if l.ID == "" {
			t.Fatalf("Append #%d did not assign an ID", i)
		}
		if l.CreatedAt.IsZero() {
			t.Fatalf("Append #%d did not set CreatedAt", i)
		}
		ids[i] = l.ID
	}

	// A log for a different function must not show up in f's list.
	other := invocationLogFunction(t, ctx, s)
	if err := s.InvocationLogs().Append(ctx, &store.InvocationLog{FunctionID: other.ID, Method: "GET", Path: "/", Status: 200}); err != nil {
		t.Fatalf("InvocationLogs().Append (other function): %v", err)
	}

	page1, err := s.InvocationLogs().List(ctx, f.ID, "", 3)
	if err != nil {
		t.Fatalf("InvocationLogs().List (page 1): %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("len(page1) = %d, want 3", len(page1))
	}
	if page1[0].ID != ids[total-1] {
		t.Fatalf("page1[0].ID = %q, want %q (most recently appended)", page1[0].ID, ids[total-1])
	}
	if page1[0].Stdout != "hello" {
		t.Fatalf("page1[0].Stdout = %q, want %q", page1[0].Stdout, "hello")
	}

	page2, err := s.InvocationLogs().List(ctx, f.ID, page1[len(page1)-1].ID, 3)
	if err != nil {
		t.Fatalf("InvocationLogs().List (page 2): %v", err)
	}
	if len(page2) != total-3 {
		t.Fatalf("len(page2) = %d, want %d", len(page2), total-3)
	}

	seen := map[string]bool{}
	for _, l := range append(page1, page2...) {
		if seen[l.ID] {
			t.Fatalf("id %q appeared on both pages", l.ID)
		}
		seen[l.ID] = true
	}
	if len(seen) != total {
		t.Fatalf("total distinct entries seen across pages = %d, want %d", len(seen), total)
	}
}

// testInvocationLogDeleteOlderThan exercises DeleteOlderThan against both
// documented behaviors an implementation may have (see
// store.InvocationLogRepo.DeleteOlderThan's doc comment): a SQL backend
// actively deletes rows older than cutoff, while a DynamoDB backend is a
// documented no-op that relies on a TTL attribute instead. Rather than
// assume one or the other, this asserts internal consistency: whatever
// DeleteOlderThan reports removing must match what List subsequently
// observes.
func testInvocationLogDeleteOlderThan(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)
	f := invocationLogFunction(t, ctx, s)

	const total = 3
	for i := 0; i < total; i++ {
		if err := s.InvocationLogs().Append(ctx, &store.InvocationLog{FunctionID: f.ID, Method: "GET", Path: "/", Status: 200}); err != nil {
			t.Fatalf("InvocationLogs().Append #%d: %v", i, err)
		}
	}

	// A cutoff in the past: nothing is older than it, so every
	// implementation (active-delete or TTL no-op) must report/leave 0
	// removed.
	n, err := s.InvocationLogs().DeleteOlderThan(ctx, time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("DeleteOlderThan (past cutoff): %v", err)
	}
	if n != 0 {
		t.Fatalf("DeleteOlderThan (past cutoff) removed %d, want 0", n)
	}
	got, err := s.InvocationLogs().List(ctx, f.ID, "", 0)
	if err != nil {
		t.Fatalf("List (after past-cutoff delete): %v", err)
	}
	if len(got) != total {
		t.Fatalf("len(List) after past-cutoff delete = %d, want %d (nothing removed)", len(got), total)
	}

	// A cutoff in the future: everything is older than it. An active-delete
	// backend removes all rows and reports it; a TTL no-op backend removes
	// none and reports 0. Either is valid, but the reported count and what
	// List subsequently sees must agree.
	n, err = s.InvocationLogs().DeleteOlderThan(ctx, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("DeleteOlderThan (future cutoff): %v", err)
	}
	got, err = s.InvocationLogs().List(ctx, f.ID, "", 0)
	if err != nil {
		t.Fatalf("List (after future-cutoff delete): %v", err)
	}
	switch n {
	case int64(total):
		if len(got) != 0 {
			t.Fatalf("DeleteOlderThan reported removing all %d, but List still returns %d", total, len(got))
		}
	case 0:
		if len(got) != total {
			t.Fatalf("DeleteOlderThan reported removing 0, but List returns %d, want %d", len(got), total)
		}
	default:
		t.Fatalf("DeleteOlderThan (future cutoff) removed %d, want 0 or %d", n, total)
	}
}
