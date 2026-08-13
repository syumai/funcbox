package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// TestMinimalE2EMultiFileESM is checklist item 1: a multi-file ESM project
// (index.js importing ./lib/greet.js) with `export default { fetch }`,
// served through cfworkers.NewPool with our Loader, behind httptest. Checks
// status, headers, body, and request.url shape.
func TestMinimalE2EMultiFileESM(t *testing.T) {
	bundle := Bundle{
		"index.js": []byte(`
			import { greet } from "./lib/greet.js";
			export default {
				async fetch(request, env, ctx) {
					const u = new URL(request.url);
					return new Response(greet("world") + " path=" + u.pathname, {
						status: 200,
						headers: { "X-From": "index.js" },
					});
				},
			};
		`),
		"lib/greet.js": []byte(`
			export function greet(name) {
				return "hello, " + name;
			}
		`),
	}

	pool, err := cfworkers.NewPool(cfworkers.PoolConfig{
		Size:   1,
		Source: `import handler from "./index.js"; export default handler;`,
		Loader: NewLoader(bundle),
	})
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

	var body strings.Builder
	buf := make([]byte, 256)
	for {
		n, rerr := resp.Body.Read(buf)
		body.Write(buf[:n])
		if rerr != nil {
			break
		}
	}

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-From"); got != "index.js" {
		t.Errorf("X-From = %q, want %q", got, "index.js")
	}
	want := "hello, world path=/some/path"
	if body.String() != want {
		t.Errorf("body = %q, want %q", body.String(), want)
	}
}

// TestLoaderRejectsBareSpecifier verifies the default (non-Node-compat)
// loader rejects a bare import with a message pointing at compat.nodejs.
func TestLoaderRejectsBareSpecifier(t *testing.T) {
	bundle := Bundle{"index.js": []byte(`import "left-pad";`)}
	js, err := spidermonkey.New(spidermonkey.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer js.Close()
	js.SetModuleLoader(NewLoader(bundle))

	r, err := js.EvalModule(context.Background(), "index.js", string(bundle["index.js"]))
	if err != nil {
		t.Fatalf("EvalModule: %v", err)
	}
	if r.Error == nil {
		t.Fatal("bare specifier import succeeded, want an error")
	}
	if !strings.Contains(r.Error.Error(), "compat.nodejs") && !strings.Contains(r.Error.Error(), "bare module specifier") {
		t.Errorf("error = %q, want mention of bare specifiers / compat.nodejs", r.Error)
	}
}

// TestLoaderRequiresExplicitExtension verifies an extension-less relative
// import is rejected (3.5: "拡張子は明示必須").
func TestLoaderRequiresExplicitExtension(t *testing.T) {
	bundle := Bundle{
		"index.js":     []byte(`import "./lib/greet";`),
		"lib/greet.js": []byte(`export const x = 1;`),
	}
	js, err := spidermonkey.New(spidermonkey.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer js.Close()
	js.SetModuleLoader(NewLoader(bundle))

	r, err := js.EvalModule(context.Background(), "index.js", string(bundle["index.js"]))
	if err != nil {
		t.Fatalf("EvalModule: %v", err)
	}
	if r.Error == nil {
		t.Fatal("extension-less import succeeded, want an error")
	}
	if !strings.Contains(r.Error.Error(), "extension") {
		t.Errorf("error = %q, want mention of a missing extension", r.Error)
	}
}

// TestLoaderEscapeAboveRootIsClampedByEngine documents an empirical finding
// (see the NewLoader doc comment): the engine itself resolves "../" walks
// against the referrer's directory and clamps at the bundle root BEFORE
// calling our loader, so "../../etc/passwd.js" from the root module never
// reaches this package as an escaping path — it arrives as "etc/passwd.js"
// (a harmless miss: nothing at that bundle path, so it just 404s as "not
// found", never as a filesystem read since the bundle is a pure in-memory
// map with no real filesystem behind it either way).
func TestLoaderEscapeAboveRootIsClampedByEngine(t *testing.T) {
	bundle := Bundle{"index.js": []byte(`import "../../etc/passwd.js";`)}
	js, err := spidermonkey.New(spidermonkey.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer js.Close()
	js.SetModuleLoader(NewLoader(bundle))

	r, err := js.EvalModule(context.Background(), "index.js", string(bundle["index.js"]))
	if err != nil {
		t.Fatalf("EvalModule: %v", err)
	}
	if r.Error == nil {
		t.Fatal("escaping import succeeded, want an error (there is nothing at the clamped path)")
	}
	if !strings.Contains(r.Error.Error(), "not found") {
		t.Errorf("error = %q, want a plain \"not found\" (the engine already clamped the escape)", r.Error)
	}
}

// TestLoaderDefenseInDepthAgainstEscape exercises NewLoader's own
// belt-and-suspenders escape check directly (bypassing the engine, which
// per TestLoaderEscapeAboveRootIsClampedByEngine never actually hands this
// package an escaping specifier) so the check itself is proven correct even
// if that upstream clamping behavior ever changes.
func TestLoaderDefenseInDepthAgainstEscape(t *testing.T) {
	loader := NewLoader(Bundle{})
	_, err := loader(spidermonkey.Config{}, "../../etc/passwd.js", "index.js")
	if err == nil {
		t.Fatal("escaping specifier accepted, want an error")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Errorf("error = %q, want mention of escaping the bundle root", err)
	}
}
