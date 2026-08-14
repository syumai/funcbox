package service_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/syumai/funcbox/bundle"
	blobfs "github.com/syumai/funcbox/server/internal/blob/fs"
	"github.com/syumai/funcbox/server/internal/service"
	"github.com/syumai/funcbox/server/internal/settings"
	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

func newTestDeployer(t *testing.T) *service.Deployer {
	t.Helper()
	st, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	blobStore, err := blobfs.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobfs.New: %v", err)
	}
	return &service.Deployer{Store: st, Blob: blobStore}
}

func pack(t *testing.T, files map[string][]byte) io.Reader {
	t.Helper()
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	return bytes.NewReader(packed)
}

// newOwnerActor creates a user and claims a public User ID for them.
// Deploy-time auto-provisioning is not supported: User IDs must already exist
// before a deploy can target them.
func newOwnerActor(t *testing.T, st store.Store, userID string) *store.User {
	t.Helper()
	u := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-" + userID, Email: userID + "@example.com", Name: userID, Role: store.RoleMember, Status: store.UserStatusActive}
	if err := st.Users().Create(context.Background(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.PublicUserIDs().Create(context.Background(), &store.PublicUserID{
		UserID: userID, InternalUserID: u.ID,
	}); err != nil {
		t.Fatalf("PublicUserIDs().Create: %v", err)
	}
	return u
}

func TestDeploy_DryRunWritesNothing(t *testing.T) {
	d := newTestDeployer(t)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: dryapp\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if !result.DryRun {
		t.Error("result.DryRun = false, want true")
	}
	if result.Function != nil || result.Version != nil {
		t.Errorf("dry run wrote Function=%v Version=%v, want both nil", result.Function, result.Version)
	}
	if result.Manifest == nil || result.Manifest.Name != "dryapp" {
		t.Errorf("Manifest = %+v, want Name \"dryapp\"", result.Manifest)
	}

	// Confirm nothing was actually persisted: the owner User ID must not
	// have been auto-provisioned.
	if _, err := d.Store.PublicUserIDs().ByUserID(context.Background(), "alice"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("PublicUserIDs().ByUserID(\"alice\") after dry run: err = %v, want store.ErrNotFound", err)
	}
}

func TestDeploy_RejectsNodeCoreImportWhenNodejsCompatEnabled(t *testing.T) {
	d := newTestDeployer(t)
	actor := newOwnerActor(t, d.Store, "alice")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: nodeapp\ncompat:\n  nodejs: true\n"),
		"index.js":     []byte(`import fs from "node:fs"; export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		Actor:  actor,
	})
	if err == nil {
		t.Fatal("Deploy succeeded, want an error rejecting the node:fs import")
	}
	svcErr, ok := service.AsError(err)
	if !ok {
		t.Fatalf("error is not a *service.Error: %v", err)
	}
	if svcErr.Status != 400 || svcErr.Code != "node_core_import" {
		t.Errorf("error = {status:%d code:%q}, want {400, \"node_core_import\"}", svcErr.Status, svcErr.Code)
	}
}

func TestDeploy_NodeCoreImportAllowedWithoutNodejsCompat(t *testing.T) {
	d := newTestDeployer(t)
	// The literal string "node:fs" appears in a file, but compat.nodejs is
	// off, so runtime.DetectNodeCoreImports's deploy-time scan doesn't run
	// 3.5) — the normal (non-Node) loader already rejects bare specifiers
	// (including "node:*" ones) on its own at invoke time.
	actor := newOwnerActor(t, d.Store, "alice")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: normalapp\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("node:fs mentioned but not imported"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Version == nil {
		t.Fatal("Deploy did not create a version")
	}
}

func TestDeploy_UnknownOwnerIs404(t *testing.T) {
	// from the auth flow's first-login derivation or from workspace
	// creation -- before anything can be deployed under it.
	d := newTestDeployer(t)
	actor := newOwnerActor(t, d.Store, "someone")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "brandnew",
		Actor:  actor,
	})
	svcErr, ok := service.AsError(err)
	if !ok || svcErr.Status != 404 {
		t.Fatalf("error = %v, want a 404 *service.Error", err)
	}
}

func TestDeploy_RequiresActor(t *testing.T) {
	d := newTestDeployer(t)
	newOwnerActor(t, d.Store, "alice")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		// Actor deliberately omitted.
	})
	svcErr, ok := service.AsError(err)
	if !ok || svcErr.Status != 401 {
		t.Fatalf("error = %v, want a 401 *service.Error", err)
	}
}

func TestDeploy_CannotDeployUnderSomeoneElsesUserID(t *testing.T) {
	d := newTestDeployer(t)
	newOwnerActor(t, d.Store, "alice")
	bob := newOwnerActor(t, d.Store, "bob")

	files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice", // bob is not alice
		Actor:  bob,
	})
	svcErr, ok := service.AsError(err)
	if !ok || svcErr.Status != 403 {
		t.Fatalf("error = %v, want a 403 *service.Error (bob deploying under alice's User ID)", err)
	}
}

func TestDeploy_OrgAdminCanDeployUnderAnyPersonalUserID(t *testing.T) {
	d := newTestDeployer(t)
	newOwnerActor(t, d.Store, "alice")
	admin := newOwnerActor(t, d.Store, "the-admin")
	admin.Role = store.RoleAdmin
	if err := d.Store.Users().Update(context.Background(), admin); err != nil {
		t.Fatalf("Users().Update: %v", err)
	}

	files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		Actor:  admin,
	})
	if err != nil {
		t.Fatalf("Deploy (org admin deploying under alice's User ID): %v", err)
	}
	if result.Version.CreatedBy != admin.ID {
		t.Errorf("Version.CreatedBy = %q, want the admin's id %q", result.Version.CreatedBy, admin.ID)
	}
}

func TestDeploy_ReservedOwnerRejected(t *testing.T) {
	d := newTestDeployer(t)
	actor := newOwnerActor(t, d.Store, "someone")
	files := map[string][]byte{
		"index.js": []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "api",
		Name:   "whatever",
		Actor:  actor,
	})
	svcErr, ok := service.AsError(err)
	if !ok || svcErr.Status != 400 {
		t.Fatalf("error = %v, want a 400 *service.Error", err)
	}
}

// TestDeploy_NodejsCompatWarningWhenOrgDisallows covers
// level) → deploy warning": the deploy still succeeds (compat.nodejs is a
// runtime-time disable, not a deploy-time rejection -- see
// internal/invoke/pool.go's orgAllowsNodejsCompat), but the response
// carries a warning telling the deployer their manifest's compat.nodejs
// won't actually take effect.
func TestDeploy_NodejsCompatWarningWhenOrgDisallows(t *testing.T) {
	d := newTestDeployer(t)

	orgAdmin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-org-admin", Email: "org-admin@example.com", Name: "Org Admin"}
	if err := d.Store.BootstrapFirstUser(context.Background(), orgAdmin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	actor := newOwnerActor(t, d.Store, "alice")

	org, err := d.Store.Organizations().Get(context.Background())
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	orgSet := settings.DefaultOrg()
	orgSet.AllowNodejsCompat = false
	org.Settings = orgSet.JSON()
	if err := d.Store.Organizations().Update(context.Background(), org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}

	files := map[string][]byte{
		"funcbox.yaml": []byte("name: nodeapp2\ncompat:\n  nodejs: true\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "allow_nodejs_compat") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one mentioning allow_nodejs_compat", result.Warnings)
	}
}

// TestDeploy_NameReconciliation covers tmp/04-manifest.md's footnote to the
// name field: name comes from the manifest or the deploy parameter; when
// both are present they must agree, and a disagreement is a name_mismatch
// error rather than the manifest silently overriding the request (or vice
// versa). Each case runs both as a real deploy and as a dry run, since the
// footnote's check must apply identically to both.
func TestDeploy_NameReconciliation(t *testing.T) {
	cases := []struct {
		name         string
		manifestName string
		paramName    string
		wantName     string // resolved name on success; ignored if wantErrCode != ""
		wantErrCode  string // "" means Deploy should succeed
	}{
		{name: "manifest only", manifestName: "from-manifest", paramName: "", wantName: "from-manifest"},
		{name: "param only", manifestName: "", paramName: "from-param", wantName: "from-param"},
		{name: "equal", manifestName: "same-name", paramName: "same-name", wantName: "same-name"},
		{name: "differ", manifestName: "from-manifest", paramName: "from-param", wantErrCode: "name_mismatch"},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/deploy", func(t *testing.T) {
			d := newTestDeployer(t)
			actor := newOwnerActor(t, d.Store, "alice")
			files := map[string][]byte{
				"index.js": []byte(`export default { fetch() { return new Response("ok"); } };`),
			}
			if tc.manifestName != "" {
				files["funcbox.yaml"] = []byte("name: " + tc.manifestName + "\n")
			}
			result, err := d.Deploy(context.Background(), service.DeployParams{
				Bundle: pack(t, files),
				Owner:  "alice",
				Name:   tc.paramName,
				Actor:  actor,
			})
			if tc.wantErrCode != "" {
				svcErr, ok := service.AsError(err)
				if !ok || svcErr.Status != 400 || svcErr.Code != tc.wantErrCode {
					t.Fatalf("error = %v, want a 400 *service.Error with code %q", err, tc.wantErrCode)
				}
				if !strings.Contains(svcErr.Message, tc.manifestName) || !strings.Contains(svcErr.Message, tc.paramName) {
					t.Errorf("error message %q does not mention both names %q and %q", svcErr.Message, tc.manifestName, tc.paramName)
				}
				return
			}
			if err != nil {
				t.Fatalf("Deploy: %v", err)
			}
			if result.Function.Name != tc.wantName {
				t.Errorf("Function.Name = %q, want %q", result.Function.Name, tc.wantName)
			}
		})

		t.Run(tc.name+"/dry_run", func(t *testing.T) {
			d := newTestDeployer(t)
			files := map[string][]byte{
				"index.js": []byte(`export default { fetch() { return new Response("ok"); } };`),
			}
			if tc.manifestName != "" {
				files["funcbox.yaml"] = []byte("name: " + tc.manifestName + "\n")
			}
			result, err := d.Deploy(context.Background(), service.DeployParams{
				Bundle: pack(t, files),
				Owner:  "alice",
				Name:   tc.paramName,
				DryRun: true,
			})
			if tc.wantErrCode != "" {
				svcErr, ok := service.AsError(err)
				if !ok || svcErr.Status != 400 || svcErr.Code != tc.wantErrCode {
					t.Fatalf("error = %v, want a 400 *service.Error with code %q", err, tc.wantErrCode)
				}
				return
			}
			if err != nil {
				t.Fatalf("Deploy (dry run): %v", err)
			}
			if result.Manifest.Name != tc.wantName {
				t.Errorf("Manifest.Name = %q, want %q", result.Manifest.Name, tc.wantName)
			}
		})
	}
}

// newTestDeployerWithOrgSettings is newTestDeployer plus a bootstrapped
// organization row carrying orgSet, via a throwaway bootstrap admin user.
// It must be called BEFORE any newOwnerActor call in the same test:
// store.Store.BootstrapFirstUser (which this uses to create the
// organization row at all -- OrganizationRepo.Update requires the row to
// already exist) requires an empty users table.
func newTestDeployerWithOrgSettings(t *testing.T, orgSet settings.Org) *service.Deployer {
	t.Helper()
	d := newTestDeployer(t)
	ctx := context.Background()
	bootstrapAdmin := &store.User{Provider: store.ProviderGoogle, ProviderSubject: "sub-org-settings-bootstrap", Email: "org-settings-bootstrap@example.com", Name: "Bootstrap"}
	if err := d.Store.BootstrapFirstUser(ctx, bootstrapAdmin, "Test Org"); err != nil {
		t.Fatalf("BootstrapFirstUser: %v", err)
	}
	org, err := d.Store.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := d.Store.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}
	return d
}

// updateOrgSettings updates an ALREADY-bootstrapped organization's
// settings (see newTestDeployerWithOrgSettings) -- for tests that need to
// change the limit again partway through, after functions already exist.
func updateOrgSettings(t *testing.T, st store.Store, orgSet settings.Org) {
	t.Helper()
	ctx := context.Background()
	org, err := st.Organizations().Get(ctx)
	if err != nil {
		t.Fatalf("Organizations().Get: %v", err)
	}
	org.Settings = orgSet.JSON()
	org.SettingsGen++
	if err := st.Organizations().Update(ctx, org); err != nil {
		t.Fatalf("Organizations().Update: %v", err)
	}
}

// deployNamed is a small helper for the function-limit table tests below:
// deploys a fresh, uniquely-named function under owner as actor, ignoring
// the result -- only whether it succeeded or which *service.Error it
// failed with matters to those tests.
func deployNamed(t *testing.T, d *service.Deployer, owner, name string, actor *store.User) error {
	t.Helper()
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: " + name + "\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files), Owner: owner, Actor: actor,
	})
	return err
}

// TestDeploy_MaxFunctionsPerUser is a table test covering
// tmp/13-public-mode.md §13.4's org-level max_functions_per_user limit:
// at/below the limit succeeds, above it 403s with function_limit_exceeded,
// 0/unset is unlimited, and a limit lowered below an owner's EXISTING
// count still lets them keep those functions (only new creation is
// blocked).
func TestDeploy_MaxFunctionsPerUser(t *testing.T) {
	t.Run("unlimited by default", func(t *testing.T) {
		d := newTestDeployer(t)
		actor := newOwnerActor(t, d.Store, "alice")
		for i := 0; i < 3; i++ {
			if err := deployNamed(t, d, "alice", fmt.Sprintf("app-%d", i), actor); err != nil {
				t.Fatalf("deploy %d: %v", i, err)
			}
		}
	})

	t.Run("at and above the limit", func(t *testing.T) {
		orgSet := settings.DefaultOrg()
		orgSet.MaxFunctionsPerUser = 2
		d := newTestDeployerWithOrgSettings(t, orgSet)
		actor := newOwnerActor(t, d.Store, "alice")

		if err := deployNamed(t, d, "alice", "app-0", actor); err != nil {
			t.Fatalf("deploy 0 (1st, under limit): %v", err)
		}
		if err := deployNamed(t, d, "alice", "app-1", actor); err != nil {
			t.Fatalf("deploy 1 (2nd, AT limit -- must still succeed): %v", err)
		}
		err := deployNamed(t, d, "alice", "app-2", actor)
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Status != 403 || svcErr.Code != "function_limit_exceeded" {
			t.Fatalf("deploy 2 (3rd, OVER limit) error = %v, want 403 function_limit_exceeded", err)
		}
		if !strings.Contains(svcErr.Message, "2") {
			t.Errorf("error message = %q, want it to mention the current/limit counts", svcErr.Message)
		}
	})

	t.Run("updating an existing function is never limited", func(t *testing.T) {
		orgSet := settings.DefaultOrg()
		orgSet.MaxFunctionsPerUser = 1
		d := newTestDeployerWithOrgSettings(t, orgSet)
		actor := newOwnerActor(t, d.Store, "alice")

		if err := deployNamed(t, d, "alice", "app-0", actor); err != nil {
			t.Fatalf("first deploy: %v", err)
		}
		// Redeploying the SAME function name is an update, not a new
		// function -- must never be blocked by the limit even though the
		// owner is already AT it.
		if err := deployNamed(t, d, "alice", "app-0", actor); err != nil {
			t.Fatalf("redeploy of the same function (update, not new): %v", err)
		}
	})

	t.Run("lowering the limit tolerates an already-over-limit owner", func(t *testing.T) {
		d := newTestDeployerWithOrgSettings(t, settings.DefaultOrg()) // unlimited to start
		actor := newOwnerActor(t, d.Store, "alice")
		// Deploy 2 functions while unlimited...
		for i := 0; i < 2; i++ {
			if err := deployNamed(t, d, "alice", fmt.Sprintf("app-%d", i), actor); err != nil {
				t.Fatalf("deploy %d: %v", i, err)
			}
		}
		// ...then lower the limit below that existing count.
		orgSet := settings.DefaultOrg()
		orgSet.MaxFunctionsPerUser = 1
		updateOrgSettings(t, d.Store, orgSet)

		// The existing 2 functions must still be there and usable (Deploy
		// doesn't delete anything); confirmed indirectly by CountByOwner.
		n, err := d.Store.Functions().CountByOwner(context.Background(), store.OwnerTypeUser, actor.ID)
		if err != nil || n != 2 {
			t.Fatalf("CountByOwner after lowering the limit = %d, %v; want 2 (untouched)", n, err)
		}
		// A NEW function is now blocked.
		err = deployNamed(t, d, "alice", "app-new", actor)
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Code != "function_limit_exceeded" {
			t.Fatalf("deploy of a new function after lowering the limit = %v, want function_limit_exceeded", err)
		}
	})

	t.Run("admins are not exempt", func(t *testing.T) {
		orgSet := settings.DefaultOrg()
		orgSet.MaxFunctionsPerUser = 1
		d := newTestDeployerWithOrgSettings(t, orgSet)
		newOwnerActor(t, d.Store, "alice")
		admin := newOwnerActor(t, d.Store, "the-admin")
		admin.Role = store.RoleAdmin
		if err := d.Store.Users().Update(context.Background(), admin); err != nil {
			t.Fatalf("Users().Update: %v", err)
		}

		// Admin deploying under ALICE's owner ID (permitted per
		// CanDeployPersonal) is still subject to alice's OWN quota, since
		// the limit is per-owner, not per-actor -- this deploy is alice's
		// first, so it must succeed.
		if err := deployNamed(t, d, "alice", "app-0", admin); err != nil {
			t.Fatalf("admin's first deploy under alice: %v", err)
		}
		// Admin's OWN personal owner is separately subject to the same
		// limit, and admin gets no exemption from it.
		if err := deployNamed(t, d, "the-admin", "admin-app-0", admin); err != nil {
			t.Fatalf("admin's first deploy under themselves: %v", err)
		}
		err := deployNamed(t, d, "the-admin", "admin-app-1", admin)
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Code != "function_limit_exceeded" {
			t.Fatalf("admin's second deploy under themselves (over limit) = %v, want function_limit_exceeded (admins are NOT exempt)", err)
		}
	})
}

// TestDeploy_MaxFunctionsPerMember is TestDeploy_MaxFunctionsPerUser's
// workspace-scope counterpart: max_functions_per_member counts by
// CREATOR within the workspace, not by ownership (the workspace owns
// every function regardless of who made it).
func TestDeploy_MaxFunctionsPerMember(t *testing.T) {
	newWorkspace := func(t *testing.T, d *service.Deployer, adminUserID string) *store.Workspace {
		t.Helper()
		ws := &store.Workspace{Name: "Acme", Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
		if err := d.Store.CreateWorkspace(context.Background(), ws, adminUserID); err != nil {
			t.Fatalf("CreateWorkspace: %v", err)
		}
		return ws
	}
	setWorkspaceLimit := func(t *testing.T, d *service.Deployer, ws *store.Workspace, limit int) {
		t.Helper()
		wsSet := settings.DefaultWorkspace()
		wsSet.MaxFunctionsPerMember = limit
		ws.Settings = wsSet.JSON()
		ws.SettingsGen++
		if err := d.Store.Workspaces().Update(context.Background(), ws); err != nil {
			t.Fatalf("Workspaces().Update: %v", err)
		}
	}

	t.Run("at and above the per-member limit", func(t *testing.T) {
		d := newTestDeployer(t)
		alice := newOwnerActor(t, d.Store, "alice")
		bob := newOwnerActor(t, d.Store, "bob")
		ws := newWorkspace(t, d, alice.ID)
		if err := d.Store.Workspaces().AddMember(context.Background(), &store.WorkspaceMember{WorkspaceID: ws.ID, UserID: bob.ID, Role: store.RoleMember}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		setWorkspaceLimit(t, d, ws, 1)

		if err := deployNamed(t, d, ws.ID, "alice-app", alice); err != nil {
			t.Fatalf("alice's first deploy (workspace admin, at limit): %v", err)
		}
		// bob's own quota is independent of alice's -- bob is still at 0,
		// so his first deploy must succeed even though the workspace's
		// TOTAL function count is already at what would be alice's limit.
		if err := deployNamed(t, d, ws.ID, "bob-app", bob); err != nil {
			t.Fatalf("bob's first deploy (separate per-member quota): %v", err)
		}
		// alice's SECOND deploy is over HER limit.
		err := deployNamed(t, d, ws.ID, "alice-app-2", alice)
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Status != 403 || svcErr.Code != "function_limit_exceeded" {
			t.Fatalf("alice's second deploy (over her per-member limit) = %v, want 403 function_limit_exceeded", err)
		}
	})

	t.Run("CountByOwner on the workspace itself is unaffected by the per-member limit", func(t *testing.T) {
		d := newTestDeployer(t)
		alice := newOwnerActor(t, d.Store, "alice")
		ws := newWorkspace(t, d, alice.ID)
		setWorkspaceLimit(t, d, ws, 0) // unlimited
		if err := deployNamed(t, d, ws.ID, "app-0", alice); err != nil {
			t.Fatalf("deploy: %v", err)
		}
		n, err := d.Store.Functions().CountByWorkspaceAndCreator(context.Background(), ws.ID, alice.ID)
		if err != nil || n != 1 {
			t.Fatalf("CountByWorkspaceAndCreator = %d, %v; want 1", n, err)
		}
	})

	t.Run("org-level max_functions_per_user does not apply to a workspace owner", func(t *testing.T) {
		// No org-settings bootstrap needed here: loadOrgSettings already
		// falls back to settings.DefaultOrg() (MaxFunctionsPerUser
		// unlimited) when there's no organization row at all, which is
		// exactly the "irrelevant/unlimited" org-level state this subtest
		// wants.
		d := newTestDeployer(t)
		alice := newOwnerActor(t, d.Store, "alice")
		ws := newWorkspace(t, d, alice.ID)
		setWorkspaceLimit(t, d, ws, 1)

		if err := deployNamed(t, d, ws.ID, "app-0", alice); err != nil {
			t.Fatalf("deploy under workspace limit: %v", err)
		}
		err := deployNamed(t, d, ws.ID, "app-1", alice)
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Code != "function_limit_exceeded" {
			t.Fatalf("deploy over the WORKSPACE limit = %v, want function_limit_exceeded", err)
		}
	})
}

// TestDeploy_OpenModeRejectsWorkspaceVisibility covers
// tmp/13-public-mode.md §13.1 item 3: while the organization has open
// mode enabled, visibility: workspace is a deploy-time error -- whether
// declared explicitly in the manifest or inherited via the organization's
// own default_visibility -- for both a real deploy and a dry run (the
// dry-run path must reject, not just warn, since this is a hard
// validation error rather than a soft quota check).
func TestDeploy_OpenModeRejectsWorkspaceVisibility(t *testing.T) {
	orgSet := settings.DefaultOrg()
	orgSet.OpenMode = true

	t.Run("explicit visibility: workspace in the manifest", func(t *testing.T) {
		d := newTestDeployerWithOrgSettings(t, orgSet)
		alice := newOwnerActor(t, d.Store, "alice")
		files := map[string][]byte{
			"funcbox.yaml": []byte("name: wsapp\nvisibility: workspace\n"),
			"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
		}
		_, err := d.Deploy(context.Background(), service.DeployParams{
			Bundle: pack(t, files), Owner: "alice", Actor: alice,
		})
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Status != 400 || svcErr.Code != "workspace_visibility_disabled" {
			t.Fatalf("deploy with visibility: workspace under open mode = %v, want 400 workspace_visibility_disabled", err)
		}
	})

	t.Run("dry run rejects the same way, not just a warning", func(t *testing.T) {
		d := newTestDeployerWithOrgSettings(t, orgSet)
		files := map[string][]byte{
			"funcbox.yaml": []byte("name: wsapp\nvisibility: workspace\n"),
			"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
		}
		_, err := d.Deploy(context.Background(), service.DeployParams{
			Bundle: pack(t, files), Owner: "alice", DryRun: true,
		})
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Code != "workspace_visibility_disabled" {
			t.Fatalf("dry run with visibility: workspace under open mode = %v, want workspace_visibility_disabled error (not a warning)", err)
		}
	})

	t.Run("inherited via org default_visibility", func(t *testing.T) {
		inheritedOrgSet := settings.DefaultOrg()
		inheritedOrgSet.OpenMode = true
		inheritedOrgSet.DefaultVisibility = "workspace"
		d := newTestDeployerWithOrgSettings(t, inheritedOrgSet)
		alice := newOwnerActor(t, d.Store, "alice")
		files := map[string][]byte{
			"funcbox.yaml": []byte("name: wsapp\n"), // no explicit visibility
			"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
		}
		_, err := d.Deploy(context.Background(), service.DeployParams{
			Bundle: pack(t, files), Owner: "alice", Actor: alice,
		})
		svcErr, ok := service.AsError(err)
		if !ok || svcErr.Code != "workspace_visibility_disabled" {
			t.Fatalf("deploy inheriting default_visibility: workspace under open mode = %v, want workspace_visibility_disabled", err)
		}
	})

	t.Run("public and org visibility remain allowed", func(t *testing.T) {
		d := newTestDeployerWithOrgSettings(t, orgSet)
		alice := newOwnerActor(t, d.Store, "alice")
		for _, vis := range []string{"public", "org"} {
			files := map[string][]byte{
				"funcbox.yaml": []byte("name: ok-" + vis + "\nvisibility: " + vis + "\n"),
				"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
			}
			if _, err := d.Deploy(context.Background(), service.DeployParams{
				Bundle: pack(t, files), Owner: "alice", Actor: alice,
			}); err != nil {
				t.Errorf("deploy with visibility: %s under open mode: %v, want success", vis, err)
			}
		}
	})
}

// TestDeploy_OpenModeRejectsWorkspaceOwner covers tmp/13-public-mode.md
// §13.1 item 3's "workspace-scoped owner deploys rejected": defense in
// depth in Deploy itself, alongside the API-level toggle guard
// (PATCH /api/v1/org refuses to enable open_mode while any workspace
// exists) and routeWorkspaces's 404 (which together should make a
// workspace owner unreachable here in practice).
func TestDeploy_OpenModeRejectsWorkspaceOwner(t *testing.T) {
	orgSet := settings.DefaultOrg()
	orgSet.OpenMode = true
	d := newTestDeployerWithOrgSettings(t, orgSet)
	alice := newOwnerActor(t, d.Store, "alice")

	ws := &store.Workspace{Name: "Team", Settings: settings.DefaultWorkspace().JSON(), SettingsGen: 1}
	if err := d.Store.CreateWorkspace(context.Background(), ws, alice.ID); err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}

	files := map[string][]byte{
		"funcbox.yaml": []byte("name: teamapp\nvisibility: org\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files), Owner: ws.ID, Actor: alice,
	})
	svcErr, ok := service.AsError(err)
	if !ok || svcErr.Status != 400 || svcErr.Code != "workspace_owner_disabled" {
		t.Fatalf("deploy to a workspace owner under open mode = %v, want 400 workspace_owner_disabled", err)
	}
}

// TestDeploy_DryRunReportsFunctionLimitAsWarning covers §13.4's "dry-run
// でも同じ判定を行い警告として返す": a dry run at/over the limit must
// still succeed (it never writes anything), but its Warnings must mention
// the limit; under the limit, no such warning appears.
func TestDeploy_DryRunReportsFunctionLimitAsWarning(t *testing.T) {
	orgSet := settings.DefaultOrg()
	orgSet.MaxFunctionsPerUser = 1
	d := newTestDeployerWithOrgSettings(t, orgSet)
	actor := newOwnerActor(t, d.Store, "alice")

	if err := deployNamed(t, d, "alice", "app-0", actor); err != nil {
		t.Fatalf("real deploy to reach the limit: %v", err)
	}

	files := map[string][]byte{
		"funcbox.yaml": []byte("name: app-1\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files), Owner: "alice", Actor: actor, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run over the limit must still succeed: %v", err)
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "1") {
			found = true
		}
	}
	if !found {
		t.Errorf("dry-run warnings = %v, want one mentioning the function limit", result.Warnings)
	}

	// A dry run for a NAME ALREADY OWNED by this same owner (an update, not
	// a new function) must not warn, even over the limit.
	updateFiles := map[string][]byte{
		"funcbox.yaml": []byte("name: app-0\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	updateResult, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, updateFiles), Owner: "alice", Actor: actor, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry run (update): %v", err)
	}
	for _, w := range updateResult.Warnings {
		if strings.Contains(w, "function limit") {
			t.Errorf("dry-run update warnings = %v, want no function-limit warning (this is an update, not a new function)", updateResult.Warnings)
		}
	}
}

func TestDeploy_GlobalFunctionNameFirstClaimWins(t *testing.T) {
	d := newTestDeployer(t)
	alice := newOwnerActor(t, d.Store, "alice")
	bob := newOwnerActor(t, d.Store, "bob")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: shared-name\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	if _, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files), Owner: "alice", Actor: alice,
	}); err != nil {
		t.Fatalf("first Deploy: %v", err)
	}

	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files), Owner: "bob", Actor: bob,
	})
	svcErr, ok := service.AsError(err)
	if !ok || svcErr.Status != 409 || svcErr.Code != "function_name_taken" {
		t.Fatalf("second Deploy error = %v, want 409 function_name_taken", err)
	}

	claimed, err := d.Store.Functions().ByName(context.Background(), "shared-name")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	if claimed.OwnerID != alice.ID {
		t.Fatalf("claimed.OwnerID = %q, want first claimant %q", claimed.OwnerID, alice.ID)
	}
}
