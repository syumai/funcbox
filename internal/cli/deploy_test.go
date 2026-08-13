package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/syumai/funcbox/bundle"
)

// newDeployTestProject creates a minimal deployable project (manifest +
// entry point + a lib file, matching the shape of testdata/hello) in a
// fresh temp directory and returns its path.
func newDeployTestProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"funcbox.yaml": "name: hello\nowner: acme\n",
		"index.js":     "import { greeting } from \"./lib/x.js\";\nexport default { async fetch() { return new Response(greeting()); } };\n",
		"lib/x.js":     "export function greeting() { return \"hi\"; }\n",
	})
	return dir
}

// TestClientDeployMultipartRequest starts an httptest.Server that mimics
// POST /api/v1/functions closely enough to verify the CLI's request shape:
// it records the multipart request, decodes the "bundle" part as a
// canonical tar.gz via bundle.Unpack, and asserts on the form fields and
// the dry_run query parameter.
func TestClientDeployMultipartRequest(t *testing.T) {
	var (
		gotAuth       string
		gotOwner      string
		gotName       string
		gotDryRunQS   string
		gotUnpacked   map[string][]byte
		handlerCalled bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		gotAuth = r.Header.Get("Authorization")
		gotDryRunQS = r.URL.Query().Get("dry_run")

		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("server: ParseMultipartForm: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gotOwner = r.FormValue("owner")
		gotName = r.FormValue("name")

		file, _, err := r.FormFile("bundle")
		if err != nil {
			t.Errorf("server: FormFile(bundle): %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()

		unpacked, err := bundle.Unpack(file)
		if err != nil {
			t.Errorf("server: bundle.Unpack: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gotUnpacked = unpacked

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dry_run":  true,
			"manifest": map[string]any{"name": gotName},
			"warnings": []string{},
		})
	}))
	defer srv.Close()

	client := NewClient(Config{Server: srv.URL, Token: "fbx_test123"})

	files := map[string][]byte{
		"index.js": []byte("export default { async fetch() { return new Response('hi'); } };"),
		"lib/x.js": []byte("export const x = 1;"),
	}
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}

	resp, err := client.Deploy(t.Context(), DeployRequest{
		Bundle: packed,
		Owner:  "acme",
		Name:   "hello",
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if !handlerCalled {
		t.Fatal("server handler was never called")
	}
	if !resp.DryRun {
		t.Error("response DryRun should be true")
	}

	if gotAuth != "Bearer fbx_test123" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer fbx_test123")
	}
	if gotDryRunQS != "true" {
		t.Errorf("dry_run query param = %q, want \"true\"", gotDryRunQS)
	}
	if gotOwner != "acme" || gotName != "hello" {
		t.Errorf("owner/name form fields = %q/%q, want acme/hello", gotOwner, gotName)
	}
	if len(gotUnpacked) != len(files) {
		t.Fatalf("unpacked %d files, want %d", len(gotUnpacked), len(files))
	}
	for name, data := range files {
		got, ok := gotUnpacked[name]
		if !ok {
			t.Errorf("unpacked bundle missing %q", name)
			continue
		}
		if !bytes.Equal(got, data) {
			t.Errorf("unpacked %q = %q, want %q", name, got, data)
		}
	}
}

// TestRunDeployDryRun exercises the full `funcbox deploy --dry-run` path
// end to end: file collection from a real directory, owner resolution from
// the manifest, packing, and the HTTP round trip, against a fake server.
func TestRunDeployDryRun(t *testing.T) {
	var gotDryRunQS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDryRunQS = r.URL.Query().Get("dry_run")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dry_run":  true,
			"manifest": map[string]any{"name": "hello"},
			"warnings": []string{"example warning"},
		})
	}))
	defer srv.Close()

	dir := newDeployTestProject(t)
	t.Setenv("FUNCBOX_SERVER", srv.URL)
	t.Setenv("FUNCBOX_API_TOKEN", "fbx_test")
	withXDGConfigHome(t)

	var stdout, stderr bytes.Buffer
	err := RunDeploy([]string{"--dry-run", dir}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("RunDeploy: %v (stderr=%s)", err, stderr.String())
	}
	if gotDryRunQS != "true" {
		t.Errorf("dry_run query param = %q, want \"true\"", gotDryRunQS)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("dry run OK")) {
		t.Errorf("stdout = %q, want it to mention the dry run succeeded", stdout.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("example warning")) {
		t.Errorf("stderr = %q, want it to print the warning", stderr.String())
	}
}

// TestRunDeployFlagsAfterPositionalArgument is the regression test for the
// CLI's flag-parsing limitation: `funcbox deploy dir --owner X` used to
// silently drop --owner because the stdlib flag package stops consuming
// flags at the first positional argument. RunDeploy now parses flags and
// positionals in any order via parseFlagsInterspersed, so a --owner flag
// placed AFTER the directory argument must still override the manifest's
// own "owner" field.
func TestRunDeployFlagsAfterPositionalArgument(t *testing.T) {
	var gotOwner string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gotOwner = r.FormValue("owner")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dry_run":  true,
			"manifest": map[string]any{"name": "hello"},
			"warnings": []string{},
		})
	}))
	defer srv.Close()

	// The manifest itself declares a DIFFERENT owner ("acme"), so a passing
	// test here can only mean the --owner flag (placed after the
	// directory) actually reached ResolveOwner, not that it was silently
	// ignored and the manifest's own owner happened to match.
	dir := newDeployTestProject(t)
	t.Setenv("FUNCBOX_SERVER", srv.URL)
	t.Setenv("FUNCBOX_API_TOKEN", "fbx_test")
	withXDGConfigHome(t)

	var stdout, stderr bytes.Buffer
	err := RunDeploy([]string{dir, "--owner", "flag-owner", "--dry-run"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("RunDeploy: %v (stderr=%s)", err, stderr.String())
	}
	if gotOwner != "flag-owner" {
		t.Errorf("server received owner = %q, want %q (a --owner flag after the directory argument must not be dropped)", gotOwner, "flag-owner")
	}
}

// TestRunDeployFallsBackToMeHandle is the end-to-end test for the
// documented-but-missing owner fallback (tmp/07-http-api.md §7.5's owner
// precedence, final step): when neither --owner nor the manifest's own
// "owner" field are set, RunDeploy must fall back to the caller's own
// handle via GET /api/v1/me instead of erroring out.
func TestRunDeployFallsBackToMeHandle(t *testing.T) {
	var gotOwner string
	var meCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/me":
			meCalled = true
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"handle": "me-handle"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/functions":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			gotOwner = r.FormValue("owner")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"dry_run":  true,
				"manifest": map[string]any{"name": "hello"},
				"warnings": []string{},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		// No "owner" key: RunDeploy must fall back to GET /api/v1/me.
		"funcbox.yaml": "name: hello\n",
		"index.js":     "export default { async fetch() { return new Response('hi'); } };\n",
	})
	t.Setenv("FUNCBOX_SERVER", srv.URL)
	t.Setenv("FUNCBOX_API_TOKEN", "fbx_test")
	withXDGConfigHome(t)

	var stdout, stderr bytes.Buffer
	err := RunDeploy([]string{"--dry-run", dir}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("RunDeploy: %v (stderr=%s)", err, stderr.String())
	}
	if !meCalled {
		t.Error("GET /api/v1/me was never called")
	}
	if gotOwner != "me-handle" {
		t.Errorf("server received owner = %q, want %q (the /me fallback handle)", gotOwner, "me-handle")
	}
}

// TestRunDeployMeFallbackErrorSurfaced checks that a failure resolving the
// caller's own handle (e.g. an expired token, a server error) produces an
// actionable error rather than a confusing one, when neither --owner nor
// the manifest set an owner.
func TestRunDeployMeFallbackErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "unauthorized", "message": "bad token"}})
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"funcbox.yaml": "name: hello\n",
		"index.js":     "export default { async fetch() { return new Response('hi'); } };\n",
	})
	t.Setenv("FUNCBOX_SERVER", srv.URL)
	t.Setenv("FUNCBOX_API_TOKEN", "fbx_test")
	withXDGConfigHome(t)

	var stdout, stderr bytes.Buffer
	err := RunDeploy([]string{dir}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected an error when the /me fallback fails")
	}
}

// TestRunDeploySizeLimit ensures a project exceeding the 5MiB unpacked
// limit is rejected client-side, before any HTTP request is made.
func TestRunDeploySizeLimit(t *testing.T) {
	requestMade := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestMade = true
	}))
	defer srv.Close()

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"funcbox.yaml": "name: big\nowner: acme\n",
	})
	if err := os.WriteFile(filepath.Join(dir, "index.js"), make([]byte, bundle.MaxUnpackedBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FUNCBOX_SERVER", srv.URL)
	t.Setenv("FUNCBOX_API_TOKEN", "fbx_test")
	withXDGConfigHome(t)

	var stdout, stderr bytes.Buffer
	err := RunDeploy([]string{dir}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected an error for an oversized bundle")
	}
	if requestMade {
		t.Error("no HTTP request should be made when the client-side size check fails")
	}
}
