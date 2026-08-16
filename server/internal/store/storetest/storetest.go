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

	"github.com/syumai/funcbox/server/internal/store"
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
	t.Run("UserLanguage", func(t *testing.T) { testUserLanguage(t, newStore) })
	t.Run("UserByProviderSubject", func(t *testing.T) { testUserByProviderSubject(t, newStore) })
	t.Run("UserStatusTransitions", func(t *testing.T) { testUserStatusTransitions(t, newStore) })
	t.Run("BootstrapFirstUserConcurrent", func(t *testing.T) { testBootstrapFirstUserConcurrent(t, newStore) })
	t.Run("PublicUserIDUniqueness", func(t *testing.T) { testPublicUserIDUniqueness(t, newStore) })
	t.Run("CreateWorkspace", func(t *testing.T) { testCreateWorkspace(t, newStore) })
	t.Run("FunctionCRUDAndVersions", func(t *testing.T) { testFunctionCRUDAndVersions(t, newStore) })
	t.Run("FunctionGlobalClaimConcurrent", func(t *testing.T) { testFunctionGlobalClaimConcurrent(t, newStore) })
	t.Run("FunctionCreatedByAndCounts", func(t *testing.T) { testFunctionCreatedByAndCounts(t, newStore) })
	t.Run("EnvVars", func(t *testing.T) { testEnvVars(t, newStore) })
	t.Run("SessionExpiryFilter", func(t *testing.T) { testSessionExpiryFilter(t, newStore) })
	t.Run("SessionRefresh", func(t *testing.T) { testSessionRefresh(t, newStore) })
	t.Run("InvokeAuthCodeConsume", func(t *testing.T) { testInvokeAuthCodeConsume(t, newStore) })
	t.Run("CLIAuthCodeConsume", func(t *testing.T) { testCLIAuthCodeConsume(t, newStore) })
	t.Run("CLICredentialLifecycle", func(t *testing.T) { testCLICredentialLifecycle(t, newStore) })
	t.Run("OAuthClientRegistration", func(t *testing.T) { testOAuthClientRegistration(t, newStore) })
	t.Run("OAuthAuthCodeConsume", func(t *testing.T) { testOAuthAuthCodeConsume(t, newStore) })
	t.Run("OAuthGrantLifecycle", func(t *testing.T) { testOAuthGrantLifecycle(t, newStore) })
	t.Run("AuditAppendAndList", func(t *testing.T) { testAuditAppendAndList(t, newStore) })
	t.Run("InvocationLogAppendAndList", func(t *testing.T) { testInvocationLogAppendAndList(t, newStore) })
	t.Run("InvocationLogDeleteOlderThan", func(t *testing.T) { testInvocationLogDeleteOlderThan(t, newStore) })
}

func testInvokeAuthCodeConsume(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)
	u := uniqueUser("Invoke code")
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	fn := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: u.ID, Name: "invoke-code"}
	if err := s.Functions().Create(ctx, fn); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	code := &store.InvokeAuthCode{ID: "hashed-code", UserID: u.ID, FunctionID: fn.ID,
		Host: "invoke-code.run.example.com", ReturnTo: "/items?q=1", ExpiresAt: now.Add(time.Minute)}
	if err := s.InvokeAuthCodes().Create(ctx, code); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.InvokeAuthCodes().Consume(ctx, code.ID, "wrong-function", code.Host, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong function Consume = %v", err)
	}
	if _, err := s.InvokeAuthCodes().Consume(ctx, code.ID, fn.ID, "wrong.example.com", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong host Consume = %v", err)
	}
	got, err := s.InvokeAuthCodes().Consume(ctx, code.ID, fn.ID, code.Host, now)
	if err != nil || got.UserID != u.ID || got.ReturnTo != code.ReturnTo {
		t.Fatalf("Consume = %#v, %v", got, err)
	}
	if _, err := s.InvokeAuthCodes().Consume(ctx, code.ID, fn.ID, code.Host, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replay Consume = %v", err)
	}
	expired := *code
	expired.ID = "expired"
	expired.ExpiresAt = now
	if err := s.InvokeAuthCodes().Create(ctx, &expired); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InvokeAuthCodes().Consume(ctx, expired.ID, fn.ID, expired.Host, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired Consume = %v", err)
	}
}

func testFunctionGlobalClaimConcurrent(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)
	const racers = 8
	owners := make([]*store.User, racers)
	for i := range owners {
		owners[i] = uniqueUser("Global claimant")
		if err := s.Users().Create(ctx, owners[i]); err != nil {
			t.Fatalf("Users().Create(%d): %v", i, err)
		}
	}

	var successes atomic.Int32
	errCh := make(chan error, racers)
	var wg sync.WaitGroup
	for _, owner := range owners {
		wg.Add(1)
		go func(owner *store.User) {
			defer wg.Done()
			err := s.Functions().Create(ctx, &store.Function{
				OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "first-claim",
			})
			if err == nil {
				successes.Add(1)
				return
			}
			if !errors.Is(err, store.ErrConflict) {
				errCh <- err
			}
		}(owner)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("unexpected concurrent claim error: %v", err)
	}
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful global claims = %d, want 1", got)
	}
	if _, err := s.Functions().ByName(ctx, "first-claim"); err != nil {
		t.Fatalf("ByName after concurrent claim: %v", err)
	}
}

func testUserLanguage(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)
	u := uniqueUser("Language")
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if got, err := s.Users().ByID(ctx, u.ID); err != nil || got.Language != "" {
		t.Fatalf("new user language = %q, %v; want empty inherited preference", got.Language, err)
	}
	u.Language = "ja"
	if err := s.Users().Update(ctx, u); err != nil {
		t.Fatalf("Users().Update: %v", err)
	}
	got, err := s.Users().ByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if got.Language != "ja" {
		t.Fatalf("stored user language = %q, want %q", got.Language, "ja")
	}
}

// uniqueUser returns a User with randomized ProviderSubject/Email so tests
// can create as many as they need without colliding on the unique
// constraints.
func uniqueUser(name string) *store.User {
	id := store.NewID()
	return &store.User{
		Provider:        store.ProviderGoogle,
		ProviderSubject: "sub-" + id,
		Email:           "user-" + id + "@example.com",
		Name:            name,
		Status:          store.UserStatusActive,
	}
}

func testUserByProviderSubject(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	u := uniqueUser("Provider")
	u.Provider = store.ProviderGoogle
	u.ProviderSubject = "provider-sub-" + store.NewID()
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	got, err := s.Users().ByProviderSubject(ctx, store.ProviderGoogle, u.ProviderSubject)
	if err != nil {
		t.Fatalf("ByProviderSubject: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("ByProviderSubject.ID = %q, want %q", got.ID, u.ID)
	}

	// A different provider with the same subject string must not match --
	// uniqueness is the (provider, subject) pair, not the subject alone.
	if _, err := s.Users().ByProviderSubject(ctx, store.ProviderGitHub, u.ProviderSubject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ByProviderSubject(different provider, same subject) error = %v, want ErrNotFound", err)
	}
	if _, err := s.Users().ByProviderSubject(ctx, store.ProviderGoogle, "no-such-subject"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ByProviderSubject(unknown subject) error = %v, want ErrNotFound", err)
	}

	// Duplicate (provider, subject) under a different user must conflict.
	dup := uniqueUser("Provider dup")
	dup.Provider = store.ProviderGoogle
	dup.ProviderSubject = u.ProviderSubject
	if err := s.Users().Create(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate (provider, subject) Create error = %v, want ErrConflict", err)
	}

	// Changing (provider, subject) via Update must move the lookup pointer.
	newSubject := "provider-sub-moved-" + store.NewID()
	u.ProviderSubject = newSubject
	if err := s.Users().Update(ctx, u); err != nil {
		t.Fatalf("Users().Update (move provider subject): %v", err)
	}
	if _, err := s.Users().ByProviderSubject(ctx, store.ProviderGoogle, newSubject); err != nil {
		t.Fatalf("ByProviderSubject (after move): %v", err)
	}
}

func testUserStatusTransitions(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	u := uniqueUser("Status")
	u.Status = store.UserStatusActive
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if got, err := s.Users().ByID(ctx, u.ID); err != nil || got.Status != store.UserStatusActive {
		t.Fatalf("new user status = %q, %v; want %q", got.Status, err, store.UserStatusActive)
	}

	for _, status := range []store.UserStatus{store.UserStatusPending, store.UserStatusDisabled, store.UserStatusActive} {
		u.Status = status
		if err := s.Users().Update(ctx, u); err != nil {
			t.Fatalf("Users().Update(status=%q): %v", status, err)
		}
		got, err := s.Users().ByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("Users().ByID(status=%q): %v", status, err)
		}
		if got.Status != status {
			t.Fatalf("stored status = %q, want %q", got.Status, status)
		}
	}
}

func testFunctionCreatedByAndCounts(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	creator := uniqueUser("Creator")
	if err := s.Users().Create(ctx, creator); err != nil {
		t.Fatalf("Users().Create(creator): %v", err)
	}
	member := uniqueUser("Member")
	if err := s.Users().Create(ctx, member); err != nil {
		t.Fatalf("Users().Create(member): %v", err)
	}

	// Personal scope: CreatedBy is persisted and CountByOwner counts by
	// ownership (owner == creator in personal scope; see
	// store.Function.CreatedBy's doc comment).
	if n, err := s.Functions().CountByOwner(ctx, store.OwnerTypeUser, creator.ID); err != nil || n != 0 {
		t.Fatalf("CountByOwner (before create) = %d, %v; want 0", n, err)
	}
	f1 := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: creator.ID, Name: "created-by-1", CreatedBy: &creator.ID}
	if err := s.Functions().Create(ctx, f1); err != nil {
		t.Fatalf("Functions().Create(f1): %v", err)
	}
	f2 := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: creator.ID, Name: "created-by-2", CreatedBy: &creator.ID}
	if err := s.Functions().Create(ctx, f2); err != nil {
		t.Fatalf("Functions().Create(f2): %v", err)
	}

	got, err := s.Functions().ByID(ctx, f1.ID)
	if err != nil {
		t.Fatalf("Functions().ByID(f1): %v", err)
	}
	if got.CreatedBy == nil || *got.CreatedBy != creator.ID {
		t.Fatalf("f1.CreatedBy = %v, want %q", got.CreatedBy, creator.ID)
	}

	if n, err := s.Functions().CountByOwner(ctx, store.OwnerTypeUser, creator.ID); err != nil || n != 2 {
		t.Fatalf("CountByOwner (personal) = %d, %v; want 2", n, err)
	}
	if n, err := s.Functions().CountByOwner(ctx, store.OwnerTypeUser, member.ID); err != nil || n != 0 {
		t.Fatalf("CountByOwner (other user) = %d, %v; want 0", n, err)
	}

	// A function created with a nil CreatedBy (e.g. a pre-migration row
	// with nothing to backfill from) must round-trip as nil, not "".
	noCreator := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: creator.ID, Name: "no-creator"}
	if err := s.Functions().Create(ctx, noCreator); err != nil {
		t.Fatalf("Functions().Create(noCreator): %v", err)
	}
	got, err = s.Functions().ByID(ctx, noCreator.ID)
	if err != nil {
		t.Fatalf("Functions().ByID(noCreator): %v", err)
	}
	if got.CreatedBy != nil {
		t.Fatalf("noCreator.CreatedBy = %v, want nil", got.CreatedBy)
	}

	// Workspace scope: CountByWorkspaceAndCreator counts by CreatedBy, not
	// by ownership (the workspace owns every function; members create a
	// subset each).
	ws := &store.Workspace{Name: "Counting WS"}
	if err := s.CreateWorkspace(ctx, ws, creator.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	if err := s.Workspaces().AddMember(ctx, &store.WorkspaceMember{WorkspaceID: ws.ID, UserID: member.ID, Role: store.RoleMember}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	wsF1 := &store.Function{OwnerType: store.OwnerTypeWorkspace, OwnerID: ws.ID, Name: "ws-fn-1", CreatedBy: &creator.ID}
	if err := s.Functions().Create(ctx, wsF1); err != nil {
		t.Fatalf("Functions().Create(wsF1): %v", err)
	}
	wsF2 := &store.Function{OwnerType: store.OwnerTypeWorkspace, OwnerID: ws.ID, Name: "ws-fn-2", CreatedBy: &member.ID}
	if err := s.Functions().Create(ctx, wsF2); err != nil {
		t.Fatalf("Functions().Create(wsF2): %v", err)
	}
	wsF3 := &store.Function{OwnerType: store.OwnerTypeWorkspace, OwnerID: ws.ID, Name: "ws-fn-3", CreatedBy: &member.ID}
	if err := s.Functions().Create(ctx, wsF3); err != nil {
		t.Fatalf("Functions().Create(wsF3): %v", err)
	}

	if n, err := s.Functions().CountByWorkspaceAndCreator(ctx, ws.ID, creator.ID); err != nil || n != 1 {
		t.Fatalf("CountByWorkspaceAndCreator(creator) = %d, %v; want 1", n, err)
	}
	if n, err := s.Functions().CountByWorkspaceAndCreator(ctx, ws.ID, member.ID); err != nil || n != 2 {
		t.Fatalf("CountByWorkspaceAndCreator(member) = %d, %v; want 2", n, err)
	}
	// CountByOwner on the workspace itself counts every function
	// regardless of creator (all 3), unlike CountByWorkspaceAndCreator.
	if n, err := s.Functions().CountByOwner(ctx, store.OwnerTypeWorkspace, ws.ID); err != nil || n != 3 {
		t.Fatalf("CountByOwner(workspace) = %d, %v; want 3", n, err)
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

func testPublicUserIDUniqueness(t *testing.T, newStore func(t *testing.T) store.Store) {
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

	id1 := &store.PublicUserID{UserID: "alice", InternalUserID: u1.ID}
	if err := s.PublicUserIDs().Create(ctx, id1); err != nil {
		t.Fatalf("PublicUserIDs().Create(id1): %v", err)
	}

	// Same public User ID, different user: must conflict.
	id2 := &store.PublicUserID{UserID: "alice", InternalUserID: u2.ID}
	if err := s.PublicUserIDs().Create(ctx, id2); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("PublicUserIDs().Create(duplicate ID, different user) error = %v, want ErrConflict", err)
	}

	got, err := s.PublicUserIDs().ByUserID(ctx, "alice")
	if err != nil {
		t.Fatalf("PublicUserIDs().ByUserID: %v", err)
	}
	if got.InternalUserID != u1.ID {
		t.Fatalf("internal user ID = %q, want %q (the original claimant)", got.InternalUserID, u1.ID)
	}

	byOwner, err := s.PublicUserIDs().ByOwner(ctx, u1.ID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByOwner: %v", err)
	}
	if byOwner.UserID != "alice" {
		t.Fatalf("PublicUserIDs().ByOwner.UserID = %q, want %q", byOwner.UserID, "alice")
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
	if err := s.CreateWorkspace(ctx, ws, creator.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	if ws.ID == "" {
		t.Fatal("CreateWorkspace did not assign an ID")
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

	// Duplicate name under the same owner must conflict.
	dup := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: owner.ID, Name: "hello"}
	if err := s.Functions().Create(ctx, dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate Functions().Create error = %v, want ErrConflict", err)
	}

	otherOwner := uniqueUser("Other Owner")
	if err := s.Users().Create(ctx, otherOwner); err != nil {
		t.Fatalf("Users().Create(other): %v", err)
	}
	globalDup := &store.Function{OwnerType: store.OwnerTypeUser, OwnerID: otherOwner.ID, Name: "hello"}
	if err := s.Functions().Create(ctx, globalDup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("global duplicate Functions().Create error = %v, want ErrConflict", err)
	}

	global, err := s.Functions().ByName(ctx, "hello")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	if global.ID != f.ID {
		t.Fatalf("ByName.ID = %q, want %q", global.ID, f.ID)
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

// testCLIAuthCodeConsume covers store.CLIAuthCodeRepo: single-use
// consumption and expiry, mirroring testInvokeAuthCodeConsume's shape
// (Consume deletes-and-returns, a replay 404s, an expired code 404s).
func testCLIAuthCodeConsume(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)
	u := uniqueUser("CLI auth code")
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	code := &store.CLIAuthCode{ID: "hashed-cli-code", UserID: u.ID, Name: "laptop",
		Challenge: "challenge-abc", ExpiresAt: now.Add(5 * time.Minute)}
	if err := s.CLIAuthCodes().Create(ctx, code); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.CLIAuthCodes().Consume(ctx, code.ID, now)
	if err != nil || got.UserID != u.ID || got.Name != code.Name || got.Challenge != code.Challenge {
		t.Fatalf("Consume = %#v, %v", got, err)
	}
	if _, err := s.CLIAuthCodes().Consume(ctx, code.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replay Consume = %v, want ErrNotFound", err)
	}

	expired := &store.CLIAuthCode{ID: "expired-cli-code", UserID: u.ID, Name: "laptop",
		Challenge: "challenge-xyz", ExpiresAt: now}
	if err := s.CLIAuthCodes().Create(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CLIAuthCodes().Consume(ctx, expired.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired Consume = %v, want ErrNotFound", err)
	}
}

// testCLICredentialLifecycle covers store.CLICredentialRepo: lookup by
// hash, listing by user, Touch advancing LastUsedAt (the sliding-expiry
// renewal §14.4 relies on), and Delete (device revocation).
func testCLICredentialLifecycle(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Device owner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}

	cred := &store.CLICredential{UserID: owner.ID, Name: "laptop", SecretHash: "hash-cli-abc123"}
	if err := s.CLICredentials().Create(ctx, cred); err != nil {
		t.Fatalf("CLICredentials().Create: %v", err)
	}
	if !cred.LastUsedAt.IsZero() {
		t.Fatalf("freshly created credential LastUsedAt = %v, want zero", cred.LastUsedAt)
	}

	got, err := s.CLICredentials().ByHash(ctx, "hash-cli-abc123")
	if err != nil {
		t.Fatalf("CLICredentials().ByHash: %v", err)
	}
	if got.ID != cred.ID || !got.LastUsedAt.IsZero() {
		t.Fatalf("got = %+v, want ID %q and zero LastUsedAt", got, cred.ID)
	}

	if _, err := s.CLICredentials().ByHash(ctx, "no-such-hash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("CLICredentials().ByHash(unknown) error = %v, want ErrNotFound", err)
	}

	list, err := s.CLICredentials().ListByUser(ctx, owner.ID)
	if err != nil {
		t.Fatalf("CLICredentials().ListByUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != cred.ID {
		t.Fatalf("ListByUser = %+v, want exactly [%q]", list, cred.ID)
	}

	touchedAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := s.CLICredentials().Touch(ctx, cred.ID, touchedAt); err != nil {
		t.Fatalf("CLICredentials().Touch: %v", err)
	}
	got, err = s.CLICredentials().ByHash(ctx, "hash-cli-abc123")
	if err != nil {
		t.Fatalf("CLICredentials().ByHash after touch: %v", err)
	}
	if !got.LastUsedAt.Equal(touchedAt) {
		t.Fatalf("LastUsedAt after Touch = %v, want %v", got.LastUsedAt, touchedAt)
	}

	if err := s.CLICredentials().Touch(ctx, "no-such-id", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch(unknown id) error = %v, want ErrNotFound", err)
	}

	if err := s.CLICredentials().Delete(ctx, cred.ID); err != nil {
		t.Fatalf("CLICredentials().Delete: %v", err)
	}
	if _, err := s.CLICredentials().ByHash(ctx, "hash-cli-abc123"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("CLICredentials().ByHash(deleted) error = %v, want ErrNotFound", err)
	}
	// Deleting an already-deleted credential is a silent no-op, matching
	// TokenRepo.Delete's historical contract.
	if err := s.CLICredentials().Delete(ctx, cred.ID); err != nil {
		t.Fatalf("CLICredentials().Delete(already deleted): %v", err)
	}
}

// testOAuthClientRegistration covers store.OAuthClientRepo: Create assigns
// an ID when none is given and round-trips RedirectURIs (a []string,
// persisted as JSON by the SQL backends -- this is the one place that
// round trip could silently corrupt), and ByID 404s for an unknown id.
func testOAuthClientRegistration(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	cl := &store.OAuthClient{Name: "Test MCP Client", RedirectURIs: []string{
		"https://client.example.com/callback", "http://127.0.0.1:33418/callback",
	}}
	if err := s.OAuthClients().Create(ctx, cl); err != nil {
		t.Fatalf("OAuthClients().Create: %v", err)
	}
	if cl.ID == "" {
		t.Fatal("Create did not assign an ID")
	}

	got, err := s.OAuthClients().ByID(ctx, cl.ID)
	if err != nil {
		t.Fatalf("OAuthClients().ByID: %v", err)
	}
	if got.Name != cl.Name {
		t.Fatalf("got.Name = %q, want %q", got.Name, cl.Name)
	}
	if len(got.RedirectURIs) != 2 || got.RedirectURIs[0] != cl.RedirectURIs[0] || got.RedirectURIs[1] != cl.RedirectURIs[1] {
		t.Fatalf("got.RedirectURIs = %v, want %v", got.RedirectURIs, cl.RedirectURIs)
	}

	if _, err := s.OAuthClients().ByID(ctx, "no-such-client"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("OAuthClients().ByID(unknown) error = %v, want ErrNotFound", err)
	}
}

// testOAuthAuthCodeConsume covers store.OAuthAuthCodeRepo: single-use
// consumption and expiry, mirroring testCLIAuthCodeConsume's shape plus
// this entity's extra client_id/redirect_uri/resource bindings.
func testOAuthAuthCodeConsume(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)
	u := uniqueUser("OAuth auth code")
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	cl := &store.OAuthClient{Name: "client", RedirectURIs: []string{"https://client.example.com/cb"}}
	if err := s.OAuthClients().Create(ctx, cl); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	code := &store.OAuthAuthCode{ID: "hashed-oauth-code", UserID: u.ID, ClientID: cl.ID,
		RedirectURI: "https://client.example.com/cb", Challenge: "challenge-abc",
		Resource: "https://control.example.com/mcp", ExpiresAt: now.Add(10 * time.Minute)}
	if err := s.OAuthAuthCodes().Create(ctx, code); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.OAuthAuthCodes().Consume(ctx, code.ID, now)
	if err != nil || got.UserID != u.ID || got.ClientID != cl.ID || got.RedirectURI != code.RedirectURI ||
		got.Challenge != code.Challenge || got.Resource != code.Resource {
		t.Fatalf("Consume = %#v, %v", got, err)
	}
	if _, err := s.OAuthAuthCodes().Consume(ctx, code.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replay Consume = %v, want ErrNotFound", err)
	}

	expired := &store.OAuthAuthCode{ID: "expired-oauth-code", UserID: u.ID, ClientID: cl.ID,
		RedirectURI: "https://client.example.com/cb", Challenge: "challenge-xyz", ExpiresAt: now}
	if err := s.OAuthAuthCodes().Create(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OAuthAuthCodes().Consume(ctx, expired.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired Consume = %v, want ErrNotFound", err)
	}
}

// testOAuthGrantLifecycle covers store.OAuthGrantRepo: lookup by hash,
// listing by user, Touch advancing LastUsedAt (the sliding-expiry renewal
// a refresh_token grant relies on), and Delete (grant revocation) --
// mirroring testCLICredentialLifecycle's shape exactly, plus this
// entity's ClientID binding.
func testOAuthGrantLifecycle(t *testing.T, newStore func(t *testing.T) store.Store) {
	ctx := context.Background()
	s := newStore(t)

	owner := uniqueUser("Grant owner")
	if err := s.Users().Create(ctx, owner); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	cl := &store.OAuthClient{Name: "client", RedirectURIs: []string{"https://client.example.com/cb"}}
	if err := s.OAuthClients().Create(ctx, cl); err != nil {
		t.Fatal(err)
	}

	g := &store.OAuthGrant{UserID: owner.ID, ClientID: cl.ID, SecretHash: "hash-oauth-abc123"}
	if err := s.OAuthGrants().Create(ctx, g); err != nil {
		t.Fatalf("OAuthGrants().Create: %v", err)
	}
	if !g.LastUsedAt.IsZero() {
		t.Fatalf("freshly created grant LastUsedAt = %v, want zero", g.LastUsedAt)
	}

	got, err := s.OAuthGrants().ByHash(ctx, "hash-oauth-abc123")
	if err != nil {
		t.Fatalf("OAuthGrants().ByHash: %v", err)
	}
	if got.ID != g.ID || got.ClientID != cl.ID || !got.LastUsedAt.IsZero() {
		t.Fatalf("got = %+v, want ID %q, ClientID %q and zero LastUsedAt", got, g.ID, cl.ID)
	}

	if _, err := s.OAuthGrants().ByHash(ctx, "no-such-hash"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("OAuthGrants().ByHash(unknown) error = %v, want ErrNotFound", err)
	}

	list, err := s.OAuthGrants().ListByUser(ctx, owner.ID)
	if err != nil {
		t.Fatalf("OAuthGrants().ListByUser: %v", err)
	}
	if len(list) != 1 || list[0].ID != g.ID {
		t.Fatalf("ListByUser = %+v, want exactly [%q]", list, g.ID)
	}

	touchedAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := s.OAuthGrants().Touch(ctx, g.ID, touchedAt); err != nil {
		t.Fatalf("OAuthGrants().Touch: %v", err)
	}
	got, err = s.OAuthGrants().ByHash(ctx, "hash-oauth-abc123")
	if err != nil {
		t.Fatalf("OAuthGrants().ByHash after touch: %v", err)
	}
	if !got.LastUsedAt.Equal(touchedAt) {
		t.Fatalf("LastUsedAt after Touch = %v, want %v", got.LastUsedAt, touchedAt)
	}

	if err := s.OAuthGrants().Touch(ctx, "no-such-id", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Touch(unknown id) error = %v, want ErrNotFound", err)
	}

	if err := s.OAuthGrants().Delete(ctx, g.ID); err != nil {
		t.Fatalf("OAuthGrants().Delete: %v", err)
	}
	if _, err := s.OAuthGrants().ByHash(ctx, "hash-oauth-abc123"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("OAuthGrants().ByHash(deleted) error = %v, want ErrNotFound", err)
	}
	// Deleting an already-deleted grant is a silent no-op, matching
	// CLICredentialRepo.Delete's contract.
	if err := s.OAuthGrants().Delete(ctx, g.ID); err != nil {
		t.Fatalf("OAuthGrants().Delete(already deleted): %v", err)
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
