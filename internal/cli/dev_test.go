package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
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
// the phase 5 spec: start `funcbox dev` on a random port against a copy of
// testdata/hello (index.js importing lib/x.js), assert the HTTP response,
// then modify a file and assert the response changes after reload.
func TestDevServerServesAndHotReloads(t *testing.T) {
	dir := t.TempDir()
	copyDir(t, dir, filepath.Join("..", "..", "testdata", "hello"))

	var stdout, stderr bytes.Buffer
	ds, err := newDevServer(dir, "127.0.0.1:0", nil, &stdout, &stderr)
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
	ds, err := newDevServer(dir, "127.0.0.1:0", nil, &stdout, &stderr)
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
}

func TestDevServerMissingManifestName(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"funcbox.yaml": "description: no name here\n",
		"index.js":     "export default { async fetch() { return new Response('hi'); } };\n",
	})
	_, err := newDevServer(dir, "127.0.0.1:0", nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected an error for a manifest with no name")
	}
}
