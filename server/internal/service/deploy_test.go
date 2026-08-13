package service_test

import (
	"bytes"
	"context"
	"errors"
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

// newOwnerActor creates a user and claims handle for them, returning the
// Deploy-time auto-provisioning: handles must already exist (created by
// the auth flow or workspace creation) before a deploy can target them.
func newOwnerActor(t *testing.T, st store.Store, handle string) *store.User {
	t.Helper()
	u := &store.User{GoogleSub: "sub-" + handle, Email: handle + "@example.com", Name: handle, Role: store.RoleMember}
	if err := st.Users().Create(context.Background(), u); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	if err := st.Handles().Create(context.Background(), &store.Handle{
		Handle: handle, OwnerType: store.OwnerTypeUser, OwnerID: u.ID,
	}); err != nil {
		t.Fatalf("Handles().Create: %v", err)
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

	// Confirm nothing was actually persisted: the owner handle must not
	// have been auto-provisioned.
	if _, err := d.Store.Handles().ByHandle(context.Background(), "alice"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Handles().ByHandle(\"alice\") after dry run: err = %v, want store.ErrNotFound", err)
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

func TestDeploy_CannotDeployUnderSomeoneElsesHandle(t *testing.T) {
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
		t.Fatalf("error = %v, want a 403 *service.Error (bob deploying under alice's handle)", err)
	}
}

func TestDeploy_OrgAdminCanDeployUnderAnyPersonalHandle(t *testing.T) {
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
		t.Fatalf("Deploy (org admin deploying under alice's handle): %v", err)
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

	orgAdmin := &store.User{GoogleSub: "sub-org-admin", Email: "org-admin@example.com", Name: "Org Admin"}
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

func TestDeploy_ManifestNameWinsOverParam(t *testing.T) {
	d := newTestDeployer(t)
	actor := newOwnerActor(t, d.Store, "alice")
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: from-manifest\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		Name:   "from-param",
		Actor:  actor,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Function.Name != "from-manifest" {
		t.Errorf("Function.Name = %q, want %q (manifest name should win)", result.Function.Name, "from-manifest")
	}
}
