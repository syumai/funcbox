// Package runtime is the Phase 0 spike implementation of funcbox's JS
// execution layer: it wires go-spidermonkey's compat/cfworkers pool to an
// in-memory function bundle, a local fetch-permission interface, and a
// lazy per-version Pool manager. See tmp/03-runtime.md for the design and
// tmp/phase0-findings.md for what this spike verified.
package runtime

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
	"testing/fstest"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// Bundle is an in-memory ESM source tree for one function version, keyed by
// virtual root-relative path ("index.js", "lib/greet.js", ...). Paths use
// "/" separators and never start with "/" or contain "..". In production
// this is populated by internal/bundle's guarded tar.gz extractor (out of
// scope here); this package only consumes already-extracted bytes.
type Bundle map[string][]byte

// NewLoader returns a spidermonkey.ModuleLoader that resolves module
// specifiers against bundle, matching 03-runtime.md 3.5's "normal mode":
// ESM only, explicit extensions required, no escaping above the bundle
// root, bare specifiers rejected with a message pointing at compat.nodejs.
//
// IMPORTANT, confirmed empirically (see loader_test.go's shape-diagnostic
// coverage — module.go's own doc comment only states this for the FS-backed
// defaultModuleLoader, but it holds for a custom loader too): the engine
// resolves a "./" or "../" specifier against its referrer's directory,
// strips the leading dot-segment, and clamps any attempt to walk above the
// bundle root — ALL BEFORE calling this loader. A bare specifier (no
// leading "./" or "../") arrives completely unchanged, un-joined against
// the referrer's directory. So by the time this function is called,
// specifier is already either the final bundle-relative path (for what was
// written as a relative import) or a verbatim bare specifier — there is no
// "./" left for this function to test, and no path.Join/path.Dir left for
// it to do. Consequently:
//
//   - A genuinely relative import and a bare specifier that happens to look
//     like a bundle path (e.g. `import "lib/greet.js"` without "./") are
//     indistinguishable once they reach here — both arrive as
//     "lib/greet.js". Since real relative imports MUST use "./"/"../" per
//     the ECMAScript host-resolution algorithm, this is spec-compliant
//     ambiguity at the loader boundary, not a bug: a spec-legal bare import
//     that happens to collide with a real bundle path would (incorrectly
//     but harmlessly) load that file. This is a known, accepted limitation
//     of the Phase 0 loader — see tmp/phase0-findings.md.
//   - A missing file extension is still a reliable signal: genuine relative
//     imports in normal mode are required to carry one, so an extension-less
//     specifier is rejected outright (this also catches the overwhelmingly
//     common case of a real bare npm specifier, e.g. "left-pad").
func NewLoader(bundle Bundle) spidermonkey.ModuleLoader {
	return func(_ spidermonkey.Config, specifier, referrer string) (string, error) {
		if path.Ext(specifier) == "" {
			return "", fmt.Errorf(
				"module specifier %q has no file extension: relative imports need an explicit extension "+
					"(e.g. \"./lib/greet.js\"), and bare specifiers (npm-style package names) are not "+
					"supported here; enable compat.nodejs for node_modules resolution", specifier)
		}
		// Defense in depth: the engine already clamps a "./"/"../" specifier
		// to the bundle root before calling this loader (see the doc
		// comment above), so this should be unreachable in practice. Kept
		// because that clamping is an observed behavior, not a documented
		// contract this package can rely on staying true forever.
		clean := strings.TrimPrefix(specifier, "/")
		if clean == ".." || strings.HasPrefix(clean, "../") {
			return "", fmt.Errorf("module specifier %q escapes the bundle root", specifier)
		}
		src, ok := bundle[clean]
		if !ok {
			return "", fmt.Errorf(
				"module %q not found in bundle; if this is a bare (non-relative) import, "+
					"enable compat.nodejs for node_modules resolution", specifier)
		}
		return string(src), nil
	}
}

// FS returns a read-only fs.FS view of the bundle, for the Node-compat mode
// (3.5's "Node 互換モード": nodejs.ESMLoader + Config.FS). Built on the
// standard library's testing/fstest.MapFS, which already implements
// directory listing and fs.Stat over a flat map — exactly what Node's
// module resolver needs (package.json / node_modules directory walks) and
// what a hand-rolled flat loader cannot provide.
func (b Bundle) FS() fs.FS {
	m := make(fstest.MapFS, len(b))
	for name, data := range b {
		m[name] = &fstest.MapFile{Data: data, Mode: 0o444}
	}
	return m
}
