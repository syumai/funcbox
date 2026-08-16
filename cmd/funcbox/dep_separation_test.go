package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// expectedDirectRequires is the exact set of direct dependencies the core
// module (github.com/syumai/funcbox) is allowed to have, per
// server-only (DB drivers, blob backends, OIDC, the management API
// handlers, dashboard assets, ...) lives in server/go.mod instead, in the
// separate github.com/syumai/funcbox/server module.
var expectedDirectRequires = []string{
	"github.com/fsnotify/fsnotify",
	"github.com/goccy/go-spidermonkey",
	"github.com/goccy/go-yaml",
	"github.com/modelcontextprotocol/go-sdk",
}

// requireLineRE matches one dependency line inside a `require (...)` block
// or the tail of a single-line `require path version` statement: a module
// path, a version, and an optional "// indirect" trailer.
var requireLineRE = regexp.MustCompile(`^(\S+)\s+\S+(?:\s+//\s*indirect\s*)?$`)

// TestDirectRequiresAreExactly is the go.mod snapshot test
// TestBinarySeparation (a `go list -deps` check over forbidden internal
// packages). That check is structurally obsolete now: bundle, manifest,
// policy, and runtime are their own top-level packages, cmd/funcbox
// cannot import another module's internal/ packages (server/internal/...),
// and server/go.mod simply doesn't require aws-sdk-go-v2, pgx, etc., so an
// accidental import of a server-only package fails to build long before
// any test would run.
//
// What CAN still happen by accident is a new direct dependency creeping
// into the root go.mod (e.g. someone reaches for a convenience library
// inside internal/cli) without anyone noticing the module graph grew. This
// test catches that by asserting the root go.mod's direct require set is
// exactly expectedDirectRequires -- no more, no less.
//
// go.mod is parsed with a plain text scan, not golang.org/x/mod/modfile,
// so that this guard itself adds zero dependencies to the module it's
// guarding.
func TestDirectRequiresAreExactly(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	var got []string
	inRequireBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "require (":
			inRequireBlock = true
		case inRequireBlock && trimmed == ")":
			inRequireBlock = false
		case inRequireBlock:
			if trimmed == "" {
				continue
			}
			m := requireLineRE.FindStringSubmatch(trimmed)
			if m == nil {
				t.Fatalf("go.mod: unparseable line inside require block: %q", line)
			}
			if !strings.HasSuffix(trimmed, "// indirect") {
				got = append(got, m[1])
			}
		case strings.HasPrefix(trimmed, "require "):
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "require "))
			if rest == "(" {
				inRequireBlock = true
				continue
			}
			m := requireLineRE.FindStringSubmatch(rest)
			if m == nil {
				t.Fatalf("go.mod: unparseable single-line require: %q", line)
			}
			if !strings.HasSuffix(rest, "// indirect") {
				got = append(got, m[1])
			}
		}
	}

	want := append([]string(nil), expectedDirectRequires...)
	sort.Strings(got)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("root go.mod direct requires = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("root go.mod direct requires = %v, want %v", got, want)
		}
	}
}
