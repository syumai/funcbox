package runtime

import (
	"context"
	"strings"
	"testing"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

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
