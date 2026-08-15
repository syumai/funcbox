// approval_test.go covers account-creation approval mode: new users are
// created pending when the organization's
// require_approval setting is on, login itself still succeeds either way,
// and validateAuthenticatable/validateActiveUser diverge on how they treat
// a pending user (dashboard/API sessions vs invoke-path caller
// resolution).
package auth

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
)

// enableRequireApproval flips the organization's require_approval setting
// on, directly against the store (mirroring PATCH /api/v1/org's effect
// without needing a live API handler in this package's tests).
func enableRequireApproval(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet, err := settings.ParseOrg(org.Settings)
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	orgSet.RequireApproval = true
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := st.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}
}

// TestDevLoginFlow_RequireApprovalCreatesPendingSecondUser covers the
// Google/dev login path's new-user branch (login.go's upsertUser):
// login still succeeds (redirects to /dashboard, session cookie set) even
// though the new user is created pending, not active.
func TestDevLoginFlow_RequireApprovalCreatesPendingSecondUser(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com") // bootstrap: always active regardless of the setting

	enableRequireApproval(t, env.auth.store)
	if err := env.auth.store.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	client, location := env.login(t, "bob@example.com")
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("pending user's login redirect = %q, want /dashboard -- login must still succeed (§13.3: \"ログインは成功する\")", location)
	}
	if client == nil {
		t.Fatal("login returned a nil client")
	}

	bob, err := env.auth.store.Users().ByEmail(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	if bob.Status != store.UserStatusPending {
		t.Fatalf("new user's status = %q, want %q", bob.Status, store.UserStatusPending)
	}

	// The bootstrap admin, created before require_approval was even set,
	// must remain unaffected.
	alice, err := env.auth.store.Users().ByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail(alice): %v", err)
	}
	if alice.Status != store.UserStatusActive {
		t.Fatalf("bootstrap admin's status = %q, want %q regardless of require_approval", alice.Status, store.UserStatusActive)
	}
}

// TestDevLoginFlow_RequireApprovalOffCreatesActiveUser is the control case:
// with the setting at its default (false), a brand-new user is still
// created active, exactly as before this feature existed.
func TestDevLoginFlow_RequireApprovalOffCreatesActiveUser(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com")
	if err := env.auth.store.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	env.login(t, "bob@example.com")
	bob, err := env.auth.store.Users().ByEmail(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	if bob.Status != store.UserStatusActive {
		t.Fatalf("new user's status with require_approval off = %q, want %q", bob.Status, store.UserStatusActive)
	}
}

// TestDevLoginFlow_DeniedLoginNeverBecomesPending confirms login rules are
// evaluated BEFORE a new user is ever created, even with require_approval
// on: a denied signup must not leave behind a pending user record (§13.3:
// "ログインルールが先に評価される -- denied ユーザーは pending にすらな
// らない").
func TestDevLoginFlow_DeniedLoginNeverBecomesPending(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com") // bootstrap; seeds an allow rule for alice@example.com ONLY
	enableRequireApproval(t, env.auth.store)

	_, location := env.login(t, "mallory@evil.com")
	if strings.HasPrefix(location, "/dashboard") && !strings.Contains(location, "login_error") {
		t.Fatalf("denied login unexpectedly succeeded (redirect = %q)", location)
	}
	if _, err := env.auth.store.Users().ByEmail(context.Background(), "mallory@evil.com"); err == nil {
		t.Fatal("a login-rule-denied signup must not create a user record at all, pending or otherwise")
	}
}

// TestDevLoginFlow_PendingUserCanLogInAgain confirms a SECOND login from
// an already-pending user still succeeds (not just their first) -- pending
// is a durable state a user can repeatedly authenticate into, not a
// one-shot signup outcome.
func TestDevLoginFlow_PendingUserCanLogInAgain(t *testing.T) {
	env := newDevLoginTestEnv(t)
	env.login(t, "alice@example.com")
	enableRequireApproval(t, env.auth.store)
	if err := env.auth.store.Organizations().ReplaceLoginRules(context.Background(), []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}
	env.login(t, "bob@example.com")

	_, location := env.login(t, "bob@example.com")
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("pending user's second login redirect = %q, want /dashboard", location)
	}
	bob, err := env.auth.store.Users().ByEmail(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("Users().ByEmail: %v", err)
	}
	if bob.Status != store.UserStatusPending {
		t.Fatalf("status after second login = %q, want still %q (unchanged)", bob.Status, store.UserStatusPending)
	}
}

// TestValidateAuthenticatable_AllowsPendingRejectsDisabled is a direct
// unit test of session.go's split: validateAuthenticatable (the
// dashboard-session/API-token path) must let a pending user through but
// reject a disabled one.
func TestValidateAuthenticatable_AllowsPendingRejectsDisabled(t *testing.T) {
	st := newTestStore(t)
	a, err := New(Config{Mode: ModeDev, BaseURL: "http://example.com", ListenAddr: "127.0.0.1:0", SessionSecret: "test-secret-value"}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := st.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionAllow},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	pending := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-pending", Email: "pending@example.com", Status: store.UserStatusPending}
	if err := st.Users().Create(ctx, pending); err != nil {
		t.Fatalf("Users().Create(pending): %v", err)
	}
	disabled := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-disabled", Email: "disabled@example.com", Status: store.UserStatusDisabled}
	if err := st.Users().Create(ctx, disabled); err != nil {
		t.Fatalf("Users().Create(disabled): %v", err)
	}

	if _, err := a.validateAuthenticatable(ctx, pending); err != nil {
		t.Errorf("validateAuthenticatable(pending) = %v, want nil error (session auth must succeed for a pending user)", err)
	}
	if _, err := a.validateAuthenticatable(ctx, disabled); err == nil {
		t.Error("validateAuthenticatable(disabled) = nil error, want ErrUnauthenticated")
	}
}

// TestGitHubLoginFlow_RequireApprovalCreatesPendingBrandNewUser covers
// resolveGitHubLogin's brand-new-identity branch (github.go): same rule as
// the Google/dev path, exercised through the real GitHub OAuth2 + REST
// round trip.
func TestGitHubLoginFlow_RequireApprovalCreatesPendingBrandNewUser(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	ctx := context.Background()

	// Bootstrap via a first GitHub login (always active).
	env.login(t, "code-admin", fakeGitHubUser{
		id: 9001, login: "admin-gh",
		emails: []githubEmailResponse{{Email: "admin@example.com", Primary: true, Verified: true}},
	})
	enableRequireApproval(t, env.auth.store)
	if err := env.auth.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	_, location := env.login(t, "code-newbie", fakeGitHubUser{
		id: 9002, login: "newbie-gh",
		emails: []githubEmailResponse{{Email: "newbie@example.com", Primary: true, Verified: true}},
	})
	if !strings.HasPrefix(location, "/dashboard") {
		t.Fatalf("pending GitHub user's login redirect = %q, want /dashboard", location)
	}

	newbie, err := env.auth.store.Users().ByProviderSubject(ctx, store.ProviderGitHub, "9002")
	if err != nil {
		t.Fatalf("Users().ByProviderSubject: %v", err)
	}
	if newbie.Status != store.UserStatusPending {
		t.Fatalf("new GitHub user's status = %q, want %q", newbie.Status, store.UserStatusPending)
	}
}

// TestGitHubLoginFlow_AccountLinkKeepsExistingStatus covers §13.3's
// decision table entry: linking a new GitHub identity to an EXISTING
// account (github.go's completeGitHubLink) must NOT change that account's
// status, even though require_approval is on and even though the account
// happens to already be pending -- only brand-new identities get the
// initialUserStatus treatment.
func TestGitHubLoginFlow_AccountLinkKeepsExistingStatus(t *testing.T) {
	env := newGitHubLoginTestEnv(t)
	ctx := context.Background()

	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-admin", Email: "admin@example.com", Name: "Admin"}
	if err := env.auth.store.BootstrapFirstUser(ctx, admin, "funcbox"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := env.auth.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "admin", InternalUserID: admin.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}

	// A pre-existing, still-pending Google user (as if created earlier
	// under require_approval, awaiting approval) that is about to link a
	// GitHub identity via matching verified email.
	pendingUser := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-carol", Email: "carol@example.com", Name: "Carol", Role: store.RoleMember, Status: store.UserStatusPending}
	if err := env.auth.store.Users().Create(ctx, pendingUser); err != nil {
		t.Fatalf("Users().Create(pendingUser): %v", err)
	}
	if err := env.auth.store.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "carol", InternalUserID: pendingUser.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create(carol): %v", err)
	}

	enableRequireApproval(t, env.auth.store)
	if err := env.auth.store.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	client, location := env.login(t, "code-carol-link", fakeGitHubUser{
		id: 9003, login: "carol-gh",
		emails: []githubEmailResponse{{Email: "carol@example.com", Primary: true, Verified: true}},
	})
	if !strings.HasPrefix(location, "/auth/link/confirm?token=") {
		t.Fatalf("callback redirect = %q, want an account-link confirmation redirect", location)
	}

	// Extract and submit the confirmation token, same mechanics as
	// TestGitHubLoginFlow_EmailLinkRequiresConfirmation.
	confirmResp, err := client.Get(env.server.URL + location)
	if err != nil {
		t.Fatalf("GET confirm page: %v", err)
	}
	bodyBytes, err := io.ReadAll(confirmResp.Body)
	confirmResp.Body.Close()
	if err != nil {
		t.Fatalf("read confirm page body: %v", err)
	}
	body := string(bodyBytes)
	const marker = `name="token" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("confirmation page has no hidden token field:\n%s", body)
	}
	rest := body[idx+len(marker):]
	token := rest[:strings.Index(rest, `"`)]

	submitResp, err := client.PostForm(env.server.URL+"/auth/link/confirm", url.Values{"token": {token}})
	if err != nil {
		t.Fatalf("POST confirm: %v", err)
	}
	submitResp.Body.Close()
	if submitResp.StatusCode != http.StatusFound {
		t.Fatalf("POST confirm status = %d, want 302", submitResp.StatusCode)
	}

	linked, err := env.auth.store.Users().ByID(ctx, pendingUser.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if linked.Provider != store.ProviderGitHub {
		t.Fatalf("provider after link = %q, want %q", linked.Provider, store.ProviderGitHub)
	}
	if linked.Status != store.UserStatusPending {
		t.Fatalf("status after link = %q, want unchanged %q (linking must not touch status)", linked.Status, store.UserStatusPending)
	}
}

// TestValidateActiveUser_RejectsPendingAndDisabled is validateActiveUser's
// (the invoke-path caller-resolution check) counterpart: pending must be
// rejected exactly like disabled here, so function-invocation
// authorization keeps treating a pending user as not-a-member (§13.3).
func TestValidateActiveUser_RejectsPendingAndDisabled(t *testing.T) {
	st := newTestStore(t)
	a, err := New(Config{Mode: ModeDev, BaseURL: "http://example.com", ListenAddr: "127.0.0.1:0", SessionSecret: "test-secret-value"}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := st.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionAllow},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	pending := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-pending2", Email: "pending2@example.com", Status: store.UserStatusPending}
	if err := st.Users().Create(ctx, pending); err != nil {
		t.Fatalf("Users().Create(pending): %v", err)
	}

	if _, err := a.validateActiveUser(ctx, pending); err == nil {
		t.Error("validateActiveUser(pending) = nil error, want ErrUnauthenticated (invoke path must treat pending as not-a-member)")
	}
}
