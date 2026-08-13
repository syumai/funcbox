// Package funcbox_test exercises the Phase 1 end-to-end path: deploy a
// function through the management API, then invoke it over HTTP, wiring
// together every package this task integrates (internal/service,
// internal/api, internal/invoke, internal/server) against real sqlite and
// filesystem-blob backends (in-memory / a temp dir, so no external state is
// needed to run it).
package funcbox_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syumai/funcbox/internal/api"
	blobfs "github.com/syumai/funcbox/internal/blob/fs"
	"github.com/syumai/funcbox/internal/bundle"
	"github.com/syumai/funcbox/internal/invoke"
	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/server"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store/sqlite"
)

// testEnv is one fully-wired funcbox-server instance (real sqlite +
// filesystem blob + runtime.Manager), listening on an httptest.Server, torn
// down automatically at the end of the test.
type testEnv struct {
	baseURL string
}

func newTestEnv(t *testing.T) *testEnv {
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

	manager := runtime.NewManager()
	t.Cleanup(func() { manager.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	functions := &service.Functions{Store: st, Runtime: manager}
	apiHandler := api.New(deployer, functions, logger)

	invoker := &invoke.Invoker{
		Store:   st,
		Blob:    blobStore,
		Manager: manager,
		Logger:  logger,
		Timeout: 10 * time.Second,
	}

	handler := server.New(server.Deps{Logger: logger, API: apiHandler, Invoker: invoker})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &testEnv{baseURL: srv.URL}
}

// readDirFiles loads every file under dir into the map[string][]byte shape
// bundle.Pack expects, keyed by slash-separated path relative to dir.
func readDirFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return files
}

// deployOpts is the multipart form fields for POST /api/v1/functions.
type deployOpts struct {
	owner  string
	name   string
	note   string
	dryRun bool
}

// deploy packs files into a canonical bundle (reusing bundle.Pack, per this
// task's suggestion) and POSTs it to /api/v1/functions, returning the
// response and its decoded JSON body.
func deploy(t *testing.T, baseURL string, files map[string][]byte, opts deployOpts) (*http.Response, map[string]any) {
	t.Helper()
	packed, err := bundle.Pack(files)
	if err != nil {
		t.Fatalf("bundle.Pack: %v", err)
	}
	return deployRaw(t, baseURL, packed, opts)
}

// deployRaw is like deploy but takes the raw (possibly non-canonical, or
// deliberately oversized) bundle bytes directly, for the validation-failure
// tests.
func deployRaw(t *testing.T, baseURL string, bundleBytes []byte, opts deployOpts) (*http.Response, map[string]any) {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="bundle"; filename="bundle.tar.gz"`)
	h.Set("Content-Type", "application/gzip")
	pw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := pw.Write(bundleBytes); err != nil {
		t.Fatalf("write bundle part: %v", err)
	}

	if opts.owner != "" {
		_ = mw.WriteField("owner", opts.owner)
	}
	if opts.name != "" {
		_ = mw.WriteField("name", opts.name)
	}
	if opts.note != "" {
		_ = mw.WriteField("note", opts.note)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	url := baseURL + "/api/v1/functions"
	if opts.dryRun {
		url += "?dry_run=true"
	}

	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/functions: %v", err)
	}
	defer resp.Body.Close()

	var body map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode deploy response: %v (body: %q)", err, raw)
		}
	}
	return resp, body
}

func mustGetString(t *testing.T, body map[string]any, path ...string) string {
	t.Helper()
	var cur any = body
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("path %v: %v is not an object (body: %v)", path, key, body)
		}
		cur, ok = m[key]
		if !ok {
			t.Fatalf("path %v: missing key %q (body: %v)", path, key, body)
		}
	}
	s, ok := cur.(string)
	if !ok {
		t.Fatalf("path %v: value is not a string: %v", path, cur)
	}
	return s
}

// TestE2E_DeployAndInvoke covers the core Phase 1 path: deploy testdata/hello
// (a multi-file ESM function: index.js imports ./lib/x.js) via a multipart
// POST, then GET it over HTTP and check the response body and headers.
func TestE2E_DeployAndInvoke(t *testing.T) {
	env := newTestEnv(t)
	files := readDirFiles(t, filepath.Join("testdata", "hello"))

	resp, body := deploy(t, env.baseURL, files, deployOpts{owner: "alice"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}
	if warnings, ok := body["warnings"].([]any); !ok || len(warnings) != 0 {
		t.Errorf("warnings = %v, want empty (manifest is present and fully specified)", body["warnings"])
	}

	invokeResp, err := http.Get(env.baseURL + "/alice/hello/some/path")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer invokeResp.Body.Close()
	got, _ := io.ReadAll(invokeResp.Body)

	if invokeResp.StatusCode != http.StatusOK {
		t.Fatalf("invoke status = %d, body = %q", invokeResp.StatusCode, got)
	}
	if h := invokeResp.Header.Get("X-Funcbox-Test"); h != "hello" {
		t.Errorf("X-Funcbox-Test header = %q, want %q", h, "hello")
	}
	want := "hello from funcbox path=/alice/hello/some/path"
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// fetchTestSource returns a worker that fetches ?target= and reports
// success/failure in the response body, mirroring
// internal/runtime/hooks_test.go's pattern so a policy denial is asserted
// as a guest-visible error, not a hang or a Go-level failure.
func fetchTestSource() []byte {
	return []byte(`
		export default {
			async fetch(req) {
				const target = new URL(req.url).searchParams.get("target");
				try {
					const r = await fetch(target);
					return new Response("ok:" + (await r.text()));
				} catch (e) {
					return new Response("fail:" + String((e && e.message) || e), { status: 502 });
				}
			},
		};
	`)
}

// TestE2E_FetchPolicy deploys one function whose manifest allowlists only
// one of two httptest targets (by literal IP:port), then checks that
// fetching the allowlisted target succeeds while fetching the other one
// fails with a guest-visible error (not a hang, not a 5xx from funcbox
// itself misbehaving).
func TestE2E_FetchPolicy(t *testing.T) {
	env := newTestEnv(t)

	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "allowed-upstream")
	}))
	t.Cleanup(allowed.Close)
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "blocked-upstream")
	}))
	t.Cleanup(blocked.Close)

	allowedHostPort := strings.TrimPrefix(allowed.URL, "http://")
	manifestYAML := fmt.Sprintf(`
name: fetchtest
permissions:
  fetch:
    mode: allowlist
    allow:
      - %q
`, allowedHostPort)

	files := map[string][]byte{
		"funcbox.yaml": []byte(manifestYAML),
		"index.js":     fetchTestSource(),
	}

	resp, body := deploy(t, env.baseURL, files, deployOpts{owner: "bob"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("deploy status = %d, body = %v", resp.StatusCode, body)
	}

	t.Run("allowlisted host succeeds", func(t *testing.T) {
		u := env.baseURL + "/bob/fetchtest?target=" + allowed.URL
		r, err := http.Get(u)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		got, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %q", r.StatusCode, got)
		}
		if string(got) != "ok:allowed-upstream" {
			t.Errorf("body = %q, want %q", got, "ok:allowed-upstream")
		}
	})

	t.Run("non-allowlisted host fails visibly to the guest", func(t *testing.T) {
		u := env.baseURL + "/bob/fetchtest?target=" + blocked.URL
		r, err := http.Get(u)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		got, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, body = %q, want 502 (guest-caught fetch failure)", r.StatusCode, got)
		}
		if !strings.HasPrefix(string(got), "fail:") {
			t.Errorf("body = %q, want a \"fail:\" prefix (guest-visible error)", got)
		}
	})
}

// TestE2E_Rollback deploys two versions of the same function, checks the
// response changes between them, then activates the first version again
// (rollback) and checks the response reverts.
func TestE2E_Rollback(t *testing.T) {
	env := newTestEnv(t)

	v1Files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("v1"); } };`),
	}
	v2Files := map[string][]byte{
		"funcbox.yaml": []byte("name: app\n"),
		"index.js":     []byte(`export default { fetch() { return new Response("v2"); } };`),
	}

	resp1, body1 := deploy(t, env.baseURL, v1Files, deployOpts{owner: "carol"})
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("deploy v1 status = %d, body = %v", resp1.StatusCode, body1)
	}
	v1ID := mustGetString(t, body1, "version", "id")

	get := func() string {
		t.Helper()
		r, err := http.Get(env.baseURL + "/carol/app")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %q", r.StatusCode, b)
		}
		return string(b)
	}

	if got := get(); got != "v1" {
		t.Fatalf("after deploy v1: body = %q, want %q", got, "v1")
	}

	resp2, body2 := deploy(t, env.baseURL, v2Files, deployOpts{owner: "carol"})
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("deploy v2 status = %d, body = %v", resp2.StatusCode, body2)
	}

	if got := get(); got != "v2" {
		t.Fatalf("after deploy v2: body = %q, want %q", got, "v2")
	}

	activateURL := fmt.Sprintf("%s/api/v1/functions/carol/app/versions/%s/activate", env.baseURL, v1ID)
	actResp, err := http.Post(activateURL, "application/json", nil)
	if err != nil {
		t.Fatalf("activate POST: %v", err)
	}
	actBody, _ := io.ReadAll(actResp.Body)
	actResp.Body.Close()
	if actResp.StatusCode != http.StatusOK {
		t.Fatalf("activate status = %d, body = %q", actResp.StatusCode, actBody)
	}

	if got := get(); got != "v1" {
		t.Fatalf("after rollback to v1: body = %q, want %q", got, "v1")
	}
}

// TestE2E_DeployValidationFailures covers the deploy request's 4xx paths:
// an oversized bundle (413), a malformed manifest (400), and a reserved
// owner handle (400).
func TestE2E_DeployValidationFailures(t *testing.T) {
	env := newTestEnv(t)

	t.Run("oversize bundle is 413", func(t *testing.T) {
		// A single, highly compressible 6 MiB file: small enough on the
		// wire to sail through the 5 MiB *compressed* MaxBytesReader cap,
		// but its decompressed size exceeds bundle.MaxUnpackedBytes (5
		// MiB) — exactly the "gzip bomb" shape internal/bundle's guarded
		// unpack is meant to catch by counting decompressed bytes as they
		// stream, not by trusting the compressed size.
		big := map[string][]byte{
			"index.js": bytes.Repeat([]byte("x"), 6<<20),
		}
		packed, err := bundle.Pack(big)
		if err != nil {
			t.Fatalf("bundle.Pack: %v", err)
		}
		if len(packed) >= service.MaxCompressedBundleBytes {
			t.Fatalf("test bundle's compressed size (%d) isn't actually small; adjust the fixture", len(packed))
		}

		resp, body := deployRaw(t, env.baseURL, packed, deployOpts{owner: "dave", name: "toobig"})
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, body = %v, want 413", resp.StatusCode, body)
		}
	})

	t.Run("malformed manifest is 400", func(t *testing.T) {
		files := map[string][]byte{
			"funcbox.yaml": []byte("name: [this is not valid: yaml: syntax\n"),
			"index.js":     []byte(`export default { fetch() { return new Response("x"); } };`),
		}
		resp, body := deploy(t, env.baseURL, files, deployOpts{owner: "dave", name: "badmanifest"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %v, want 400", resp.StatusCode, body)
		}
	})

	t.Run("reserved owner is 400", func(t *testing.T) {
		files := map[string][]byte{
			"index.js": []byte(`export default { fetch() { return new Response("x"); } };`),
		}
		resp, body := deploy(t, env.baseURL, files, deployOpts{owner: "api", name: "whatever"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %v, want 400", resp.StatusCode, body)
		}
	})
}
