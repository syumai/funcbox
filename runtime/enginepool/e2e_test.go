package enginepool

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// singleFileLoader is minimal test scaffolding: a spidermonkey.ModuleLoader
// that resolves exactly one specifier to one source string, for tests that
// don't need a real bundle.
func singleFileLoader(files map[string]string) spidermonkey.ModuleLoader {
	return func(_ spidermonkey.Config, specifier, referrer string) (string, error) {
		if src, ok := files[specifier]; ok {
			return src, nil
		}
		return "", &moduleNotFoundError{specifier}
	}
}

type moduleNotFoundError struct{ specifier string }

func (e *moduleNotFoundError) Error() string { return "module not found: " + e.specifier }

// TestMinimalE2EMultiFileESM is checklist item 1 ported to enginepool: a
// multi-file ESM project (index.js importing ./lib/greet.js) with
// `export default { fetch }`, served behind httptest.
func TestMinimalE2EMultiFileESM(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			import { greet } from "./lib/greet.js";
			export default {
				async fetch(request) {
					const u = new URL(request.url);
					return new Response(greet("world") + " path=" + u.pathname, {
						status: 200,
						headers: { "X-From": "index.js" },
					});
				},
			};
		`,
		"lib/greet.js": `
			export function greet(name) {
				return "hello, " + name;
			}
		`,
	})

	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/some/path")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-From"); got != "index.js" {
		t.Errorf("X-From = %q, want %q", got, "index.js")
	}
	want := "hello, world path=/some/path"
	if string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

// TestFetchOnlyRejectsMissingFetch is requirement 4: a module whose default
// export has no fetch is a boot error.
func TestFetchOnlyRejectsMissingFetch(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `export default { scheduled() {} };`,
	})
	_, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err == nil {
		t.Fatal("NewPool succeeded with no fetch handler, want an error")
	}
	if !strings.Contains(err.Error(), "fetch") {
		t.Errorf("error = %q, want it to mention the missing fetch handler", err)
	}
}

// TestFetchOnlyRejectsNonObjectDefaultExport covers a default export that
// isn't an object at all (e.g. a bare function or a class).
func TestFetchOnlyRejectsNonObjectDefaultExport(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `export default function fetch(req) { return new Response("nope"); };`,
	})
	_, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err == nil {
		t.Fatal("NewPool succeeded with a non-object default export, want an error")
	}
}

// TestFetchOnlyWarnsOnExtraKeysButBoots is requirement 4's other half: a
// scheduled/queue key alongside fetch is a warning, not a boot error.
func TestFetchOnlyWarnsOnExtraKeysButBoots(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(request) { return new Response("ok"); },
				scheduled() {},
				queue() {},
			};
		`,
	})
	var warned []string
	pool, err := NewPool(Config{
		Size: 1, Entry: "index.js", Loader: loader,
		Warn: func(key string) { warned = append(warned, key) },
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	if len(warned) != 2 {
		t.Fatalf("warned = %v, want 2 entries (scheduled, queue)", warned)
	}
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("status=%d body=%q, want 200 ok", resp.StatusCode, body)
	}
}

// TestFetchSignatureHasNoEnvOrCtxArguments is requirement per the spec's
// breaking change: fetch(request) only — a second argument, if the function
// reads it, must be undefined (no env/ctx object is ever passed).
func TestFetchSignatureHasNoEnvOrCtxArguments(t *testing.T) {
	loader := singleFileLoader(map[string]string{
		"index.js": `
			export default {
				async fetch(request, second, third) {
					return new Response(JSON.stringify({ argCount: arguments.length, second, third }));
				},
			};
		`,
	})
	pool, err := NewPool(Config{Size: 1, Entry: "index.js", Loader: loader})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	srv := httptest.NewServer(pool)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := `{"argCount":1}`; string(body) != want {
		t.Fatalf("body = %q, want %q (fetch must be called with exactly one argument)", body, want)
	}
}
