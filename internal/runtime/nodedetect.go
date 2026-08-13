package runtime

import "regexp"

// nodeCoreImportPattern matches the three ways a module specifier can name a
// "node:*" core module in source text: static `import ... from "node:x"`,
// a bare side-effect `import "node:x"`, a dynamic `import("node:x")`, and
// CommonJS `require("node:x")`. It intentionally does NOT try to parse
// JavaScript — see DetectNodeCoreImports's doc comment for why a cheap scan
// is the right tradeoff here.
var nodeCoreImportPattern = regexp.MustCompile(
	`(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"](node:[^'"]+)['"]`,
)

// DetectNodeCoreImports scans source (one module's text) for specifiers
// naming a "node:*" core module and returns the distinct set found, in
// first-seen order (nil if none). This is the deploy-time check
// 03-runtime.md 3.5 and 10's roadmap ask for: compat.nodejs's node_modules
// resolution works (item 7's other tests), but cfworkers.Pool has no hook
// to run nodejs.Install, so a "node:*" import fails only at first
// invocation without this — surfacing it at deploy time instead gives a
// function author an immediate, actionable error instead of a 500 on first
// request.
//
// This is deliberately a REGEX SCAN, not a real parser, because:
//   - It is single-pass and cheap enough to run on every file of every
//     deploy without pulling in a JS parser dependency (esbuild, acorn,
//     ...) into the server's dependency graph just for this one check.
//   - It only needs to be a SOUND-ENOUGH heuristic for the common cases
//     (ESM static/dynamic import, CJS require) a function author would
//     actually write; a determined author trying to hide a "node:*" string
//     from this scanner (string concatenation, a computed require(x)) would
//     still get the SAME clean, immediate failure the library itself
//     produces at pool warm-up (TestNodejsESMLoaderRejectsNodeCoreImportWithoutInstall)
//     — this check only trades a slow failure for a fast one, it is not a
//     security boundary.
//
// Known gaps worth stating plainly (see tmp/phase0-findings.md item 7 for
// the full discussion): a specifier built from a template literal or string
// concatenation is invisible to this scan; a "node:" string inside a
// comment or an unrelated string literal is a false positive. A real fix
// for either would mean parsing (at least tokenizing) the source, which is
// a reasonable escalation path if false negatives turn out to matter in
// practice — the roadmap's existing plan to esbuild-bundle deploys would
// also make this exact scan unnecessary (a bundler that doesn't know
// "node:*" already fails the build).
func DetectNodeCoreImports(source string) []string {
	matches := nodeCoreImportPattern.FindAllStringSubmatch(source, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	var out []string
	for _, m := range matches {
		spec := m[1]
		if seen[spec] {
			continue
		}
		seen[spec] = true
		out = append(out, spec)
	}
	return out
}
