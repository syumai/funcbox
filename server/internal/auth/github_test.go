package auth

import (
	"context"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
)

// --- provider config validation -------------------------------------------------

func TestNew_GitHubModeRequiresClientCredentials(t *testing.T) {
	st := newTestStore(t)
	_, err := New(Config{
		Mode:          ModeGitHub,
		BaseURL:       "https://funcbox.example.com",
		SessionSecret: "test-secret",
	}, st)
	if err == nil {
		t.Fatal("New in github mode without client credentials should fail")
	}
}

func TestNew_GitHubModeAcceptsCredentialsAndDefaultsEndpoints(t *testing.T) {
	st := newTestStore(t)
	a, err := New(Config{
		Mode:               ModeGitHub,
		BaseURL:            "https://funcbox.example.com",
		GitHubClientID:     "gh-id",
		GitHubClientSecret: "gh-secret",
		SessionSecret:      "test-secret",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.githubAuthorizeURL != defaultGitHubAuthorizeURL {
		t.Errorf("githubAuthorizeURL = %q, want %q", a.cfg.githubAuthorizeURL, defaultGitHubAuthorizeURL)
	}
	if a.cfg.githubTokenURL != defaultGitHubTokenURL {
		t.Errorf("githubTokenURL = %q, want %q", a.cfg.githubTokenURL, defaultGitHubTokenURL)
	}
	if a.cfg.githubAPIBaseURL != defaultGitHubAPIBaseURL {
		t.Errorf("githubAPIBaseURL = %q, want %q", a.cfg.githubAPIBaseURL, defaultGitHubAPIBaseURL)
	}
	if a.DevRoutes() != nil {
		t.Fatal("DevRoutes() should be nil outside dev mode")
	}
}

func TestNew_GitHubModeHonorsEndpointOverrides(t *testing.T) {
	st := newTestStore(t)
	a, err := New(Config{
		Mode:               ModeGitHub,
		BaseURL:            "https://funcbox.example.com",
		GitHubClientID:     "gh-id",
		GitHubClientSecret: "gh-secret",
		SessionSecret:      "test-secret",
		githubAuthorizeURL: "https://fake.test/authorize",
		githubTokenURL:     "https://fake.test/token",
		githubAPIBaseURL:   "https://fake.test/api",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.githubAuthorizeURL != "https://fake.test/authorize" {
		t.Errorf("githubAuthorizeURL = %q, want override preserved", a.cfg.githubAuthorizeURL)
	}
}

// --- GitHub email selection -------------------------------------------------

func TestSelectVerifiedPrimaryEmail(t *testing.T) {
	tests := []struct {
		name   string
		emails []githubEmailResponse
		want   string
		wantOK bool
	}{
		{
			name: "primary verified is selected",
			emails: []githubEmailResponse{
				{Email: "secondary@example.com", Primary: false, Verified: true},
				{Email: "primary@example.com", Primary: true, Verified: true},
			},
			want:   "primary@example.com",
			wantOK: true,
		},
		{
			name: "primary unverified is rejected even with a verified secondary",
			emails: []githubEmailResponse{
				{Email: "primary@example.com", Primary: true, Verified: false},
				{Email: "secondary@example.com", Primary: false, Verified: true},
			},
			want:   "",
			wantOK: false,
		},
		{
			name:   "no emails at all is rejected",
			emails: nil,
			want:   "",
			wantOK: false,
		},
		{
			name: "no email marked primary is rejected",
			emails: []githubEmailResponse{
				{Email: "a@example.com", Primary: false, Verified: true},
				{Email: "b@example.com", Primary: false, Verified: true},
			},
			want:   "",
			wantOK: false,
		},
		{
			name: "private-email account: primary still reachable via /user/emails",
			emails: []githubEmailResponse{
				{Email: "12345+octocat@users.noreply.github.com", Primary: true, Verified: true},
			},
			want:   "12345+octocat@users.noreply.github.com",
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := selectVerifiedPrimaryEmail(tt.emails)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("selectVerifiedPrimaryEmail(%+v) = (%q, %v), want (%q, %v)", tt.emails, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// --- handle lowercase/reserved validation -------------------------------------------------

func TestGitHubHandleValidation(t *testing.T) {
	// Mirrors the lowercase-then-validate step handleGitHubCallback
	// performs on the raw GitHub login before treating it as a handle.
	tests := []struct {
		login   string
		wantErr bool
	}{
		{"octocat", false},
		{"Octocat", false}, // mixed case is lowercased first
		{"OCTOCAT", false},
		{"oct-o-cat", false},
		{"api", true},       // reserved
		{"dashboard", true}, // reserved
		{"_hidden", true},   // leading underscore reserved
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.login, func(t *testing.T) {
			got := githubHandleFromLogin(tt.login)
			err := validateGitHubHandle(got)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGitHubHandle(githubHandleFromLogin(%q)=%q) error = %v, wantErr %v", tt.login, got, err, tt.wantErr)
			}
		})
	}
}

// --- link-vs-create decision table -------------------------------------------------

func newGitHubTestAuth(t *testing.T) (*Auth, store.Store) {
	t.Helper()
	st := newTestStore(t)
	a, err := New(Config{
		Mode:               ModeGitHub,
		BaseURL:            "https://funcbox.example.com",
		GitHubClientID:     "gh-id",
		GitHubClientSecret: "gh-secret",
		SessionSecret:      "test-secret",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, st
}

func TestResolveGitHubLogin_FreshSignupBootstraps(t *testing.T) {
	a, st := newGitHubTestAuth(t)
	ctx := context.Background()

	result, err := a.resolveGitHubLogin(ctx, "1001", "octocat@example.com", "octocat", "octocat")
	if err != nil {
		t.Fatalf("resolveGitHubLogin: %v", err)
	}
	if result.needsConfirmation {
		t.Fatal("fresh signup should not need confirmation")
	}
	if result.user.Role != store.RoleAdmin {
		t.Fatalf("first user's role = %q, want admin (bootstrap)", result.user.Role)
	}
	pid, err := st.PublicUserIDs().ByOwner(ctx, result.user.ID)
	if err != nil {
		t.Fatalf("PublicUserIDs().ByOwner: %v", err)
	}
	if pid.UserID != "octocat" {
		t.Fatalf("handle = %q, want %q", pid.UserID, "octocat")
	}
}

func TestResolveGitHubLogin_SecondLoginSameSubjectReturnsSameUser(t *testing.T) {
	a, _ := newGitHubTestAuth(t)
	ctx := context.Background()

	first, err := a.resolveGitHubLogin(ctx, "1001", "octocat@example.com", "octocat", "octocat")
	if err != nil {
		t.Fatalf("first resolveGitHubLogin: %v", err)
	}

	second, err := a.resolveGitHubLogin(ctx, "1001", "octocat@example.com", "octocat", "octocat")
	if err != nil {
		t.Fatalf("second resolveGitHubLogin: %v", err)
	}
	if second.needsConfirmation {
		t.Fatal("a repeat login by the same subject should never need confirmation")
	}
	if second.user.ID != first.user.ID {
		t.Fatalf("second login user ID = %q, want %q (same user)", second.user.ID, first.user.ID)
	}
}

func TestResolveGitHubLogin_EmailMatchDifferentProviderNeedsConfirmation(t *testing.T) {
	a, st := newGitHubTestAuth(t)
	ctx := context.Background()

	// Bootstrap a Google user first (the org's existing admin).
	googleUser := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-1", Email: "alice@example.com", Name: "Alice"}
	if err := st.BootstrapFirstUser(ctx, googleUser, "funcbox"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := st.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "alice", InternalUserID: googleUser.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	if err := st.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: "alice@example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	// A later GitHub login with the SAME verified email, but a github
	// username that differs from the current handle, must be offered as
	// a link -- not silently applied.
	result, err := a.resolveGitHubLogin(ctx, "gh-sub-1", "alice@example.com", "alice-gh", "alice-gh")
	if err != nil {
		t.Fatalf("resolveGitHubLogin: %v", err)
	}
	if !result.needsConfirmation {
		t.Fatal("an email match under a different provider should need confirmation before linking")
	}
	if result.existingUserID != googleUser.ID {
		t.Fatalf("existingUserID = %q, want %q", result.existingUserID, googleUser.ID)
	}

	// The link must NOT have been applied yet: the google user's provider
	// and handle are still untouched.
	reloaded, err := st.Users().ByID(ctx, googleUser.ID)
	if err != nil {
		t.Fatalf("Users().ByID: %v", err)
	}
	if reloaded.Provider != store.ProviderGoogle {
		t.Fatalf("provider = %q, want unchanged %q (link not yet confirmed)", reloaded.Provider, store.ProviderGoogle)
	}
}

func TestResolveGitHubLogin_HandleTakenByAnotherUserIsRejected(t *testing.T) {
	a, st := newGitHubTestAuth(t)
	ctx := context.Background()

	// A pre-existing user (e.g. a Google user who manually chose this
	// handle) already owns "octocat".
	other := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-2", Email: "someone@example.com", Name: "Someone"}
	if err := st.BootstrapFirstUser(ctx, other, "funcbox"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := st.PublicUserIDs().Create(ctx, &store.PublicUserID{UserID: "octocat", InternalUserID: other.ID}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}

	// A brand new GitHub identity (different email) whose username also
	// happens to be "octocat" cannot register: the handle is fixed and
	// there is no fallback suffixing.
	_, err := a.resolveGitHubLogin(ctx, "gh-sub-3", "newperson@example.com", "octocat", "octocat")
	if err == nil {
		t.Fatal("resolveGitHubLogin should reject a handle already claimed by a different account")
	}
	if got := err; got != ErrGitHubHandleTaken {
		t.Fatalf("error = %v, want %v", got, ErrGitHubHandleTaken)
	}
}

func TestResolveGitHubLogin_LoginRuleDenialBlocksNewUser(t *testing.T) {
	a, st := newGitHubTestAuth(t)
	ctx := context.Background()

	// Bootstrap an existing (unrelated) org so login rules apply (empty
	// rule set denies everyone).
	admin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "g-sub-1", Email: "admin@example.com", Name: "Admin"}
	if err := st.BootstrapFirstUser(ctx, admin, "funcbox"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	if err := st.Organizations().ReplaceLoginRules(ctx, []*store.LoginRule{
		{Ord: 0, RuleType: store.LoginRuleTypeEmailExact, Value: "admin@example.com", Action: store.LoginRuleActionAllow},
		{Ord: 1, RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}); err != nil {
		t.Fatalf("ReplaceLoginRules: %v", err)
	}

	_, err := a.resolveGitHubLogin(ctx, "gh-sub-4", "outsider@example.com", "outsider", "outsider")
	if err != ErrLoginDenied {
		t.Fatalf("error = %v, want %v", err, ErrLoginDenied)
	}
}
