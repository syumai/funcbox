package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// copyDir recursively copies src into dst (both existing directories),
// used to give each dev test its own mutable copy of testdata/hello.
func copyDir(t *testing.T, dst, src string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			copyDir(t, d, s)
			continue
		}
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(d, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestDevServerServesAndHotReloads is the end-to-end test called for by
// testdata/hello (index.js importing lib/x.js), assert the HTTP response,
// then modify a file and assert the response changes after reload.
func TestDevServerServesAndHotReloads(t *testing.T) {
	dir := t.TempDir()
	copyDir(t, dir, filepath.Join("..", "..", "testdata", "hello"))

	var stdout, stderr bytes.Buffer
	ds, err := newDevServer(dir, "127.0.0.1:0", nil, false, &stdout, &stderr)
	if err != nil {
		t.Fatalf("newDevServer: %v", err)
	}
	defer ds.Close()

	if ds.owner != "dev" {
		t.Errorf("owner = %q, want \"dev\" (testdata/hello's manifest declares no owner)", ds.owner)
	}
	if ds.name != "hello" {
		t.Errorf("name = %q, want \"hello\"", ds.name)
	}

	go ds.Serve()

	url := "http://" + ds.Addr() + "/" + ds.owner + "/" + ds.name + "/some/path"
	body := getBodyWithRetry(t, url)
	if !bytes.Contains(body, []byte("hello from funcbox")) {
		t.Fatalf("initial response = %q, want it to contain the lib greeting", body)
	}
	if !bytes.Contains(body, []byte("path=/dev/hello/some/path")) {
		t.Fatalf("initial response = %q, want the full unstripped request path", body)
	}

	// Modify the lib file the handler imports, and confirm the running
	// server picks up the change (fsnotify -> debounce -> rebuild ->
	// Manager.Invalidate) without restarting the process.
	libPath := filepath.Join(dir, "lib", "x.js")
	newSrc := `export function greeting() { return "hello v2"; }` + "\n"
	if err := os.WriteFile(libPath, []byte(newSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(10 * time.Second)
	var last []byte
	for time.Now().Before(deadline) {
		last = getBodyWithRetry(t, url)
		if bytes.Contains(last, []byte("hello v2")) {
			return // success
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("response never reflected the reloaded file within the timeout; last body = %q; stderr = %s", last, stderr.String())
}

func getBodyWithRetry(t *testing.T, url string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDevServerRedirectsRootToFunction(t *testing.T) {
	dir := t.TempDir()
	copyDir(t, dir, filepath.Join("..", "..", "testdata", "hello"))

	var stdout, stderr bytes.Buffer
	ds, err := newDevServer(dir, "127.0.0.1:0", nil, false, &stdout, &stderr)
	if err != nil {
		t.Fatalf("newDevServer: %v", err)
	}
	defer ds.Close()
	go ds.Serve()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ds.Addr()+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if loc := resp.Header.Get("Location"); loc != "/dev/hello" {
		t.Errorf("Location = %q, want /dev/hello", loc)
	}

	// The convenience redirect must carry the query string along, so
	// "GET /?text=abc" reaches the guest as "/dev/hello?text=abc".
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ds.Addr()+"/?text=abc", nil)
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /?text=abc: %v", err)
	}
	defer resp2.Body.Close()
	if loc := resp2.Header.Get("Location"); loc != "/dev/hello?text=abc" {
		t.Errorf("Location = %q, want /dev/hello?text=abc", loc)
	}
}

// fetchProbeSource is a minimal handler for exercising the fetch policy a
// devServer applies: it fetches the "target" query param and reports
// success/failure the same way runtime/hooks_test.go's fixture
// does, so a permission-denied fetch is guest-visible (a 502 with a
// "fail:" body) rather than an uncaught exception.
func fetchProbeSource() string {
	return `
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
	`
}

// TestDevServerAllowAllFetchFlag is the end-to-end test for `funcbox dev
// permissions.fetch block defaults to deny (manifest.Permissions'
// own doc comment), so a fetch to a non-allowlisted target must fail
// without the flag and succeed once --allow-all-fetch is set — proving the
// flag actually bypasses the manifest's fetch policy rather than the
// devServer having been permissive all along.
func TestDevServerAllowAllFetchFlag(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "upstream data")
	}))
	defer upstream.Close()

	newProject := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{
			"funcbox.yaml": "name: fetchprobe\n",
			"index.js":     fetchProbeSource(),
		})
		return dir
	}

	t.Run("denied without the flag", func(t *testing.T) {
		dir := newProject(t)
		ds, err := newDevServer(dir, "127.0.0.1:0", nil, false, io.Discard, io.Discard)
		if err != nil {
			t.Fatalf("newDevServer: %v", err)
		}
		defer ds.Close()
		go ds.Serve()

		url := "http://" + ds.Addr() + "/" + ds.owner + "/" + ds.name + "?target=" + upstream.URL
		resp := getResponseWithRetry(t, url)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d body=%q, want 502 (default fetch policy is deny)", resp.StatusCode, body)
		}
	})

	t.Run("allowed with the flag", func(t *testing.T) {
		dir := newProject(t)
		ds, err := newDevServer(dir, "127.0.0.1:0", nil, true, io.Discard, io.Discard)
		if err != nil {
			t.Fatalf("newDevServer: %v", err)
		}
		defer ds.Close()
		go ds.Serve()

		url := "http://" + ds.Addr() + "/" + ds.owner + "/" + ds.name + "?target=" + upstream.URL
		resp := getResponseWithRetry(t, url)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d body=%q, want 200 (--allow-all-fetch should bypass the manifest's fetch policy)", resp.StatusCode, body)
		}
		if string(body) != "ok:upstream data" {
			t.Errorf("body = %q, want %q", body, "ok:upstream data")
		}
	})
}

// getResponseWithRetry is getBodyWithRetry's cousin for callers that need
// the full *http.Response (e.g. to check the status code), not just the
// body.
func getResponseWithRetry(t *testing.T, url string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func TestDevServerMissingManifestName(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"funcbox.yaml": "description: no name here\n",
		"index.js":     "export default { async fetch() { return new Response('hi'); } };\n",
	})
	_, err := newDevServer(dir, "127.0.0.1:0", nil, false, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected an error for a manifest with no name")
	}
}
