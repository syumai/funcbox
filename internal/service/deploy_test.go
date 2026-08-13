package service_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	blobfs "github.com/syumai/funcbox/internal/blob/fs"
	"github.com/syumai/funcbox/internal/bundle"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/internal/store/sqlite"
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
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: nodeapp\ncompat:\n  nodejs: true\n"),
		"index.js":     []byte(`import fs from "node:fs"; export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
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
	// at all (it's specific to compat.nodejs deploys, tmp/03-runtime.md
	// 3.5) — the normal (non-Node) loader already rejects bare specifiers
	// (including "node:*" ones) on its own at invoke time.
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: normalapp\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("node:fs mentioned but not imported"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Version == nil {
		t.Fatal("Deploy did not create a version")
	}
}

func TestDeploy_AutoProvisionsUnknownOwner(t *testing.T) {
	d := newTestDeployer(t)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "brandnew",
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	h, err := d.Store.Handles().ByHandle(context.Background(), "brandnew")
	if err != nil {
		t.Fatalf("Handles().ByHandle after deploy: %v", err)
	}
	if h.OwnerType != store.OwnerTypeUser {
		t.Errorf("auto-provisioned handle OwnerType = %q, want %q", h.OwnerType, store.OwnerTypeUser)
	}
	if result.Function.OwnerID != h.OwnerID {
		t.Errorf("Function.OwnerID = %q, want %q", result.Function.OwnerID, h.OwnerID)
	}
}

func TestDeploy_ReservedOwnerRejected(t *testing.T) {
	d := newTestDeployer(t)
	files := map[string][]byte{
		"index.js": []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	_, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "api",
		Name:   "whatever",
	})
	svcErr, ok := service.AsError(err)
	if !ok || svcErr.Status != 400 {
		t.Fatalf("error = %v, want a 400 *service.Error", err)
	}
}

func TestDeploy_ManifestNameWinsOverParam(t *testing.T) {
	d := newTestDeployer(t)
	files := map[string][]byte{
		"funcbox.yaml": []byte("name: from-manifest\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("ok"); } };`),
	}
	result, err := d.Deploy(context.Background(), service.DeployParams{
		Bundle: pack(t, files),
		Owner:  "alice",
		Name:   "from-param",
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if result.Function.Name != "from-manifest" {
		t.Errorf("Function.Name = %q, want %q (manifest name should win)", result.Function.Name, "from-manifest")
	}
}
