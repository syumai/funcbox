package main

import (
	"os/exec"
	"strings"
	"testing"
)

// forbiddenImports are internal packages the funcbox CLI binary must never
// link (tmp/02-architecture.md "バイナリ分離と依存の最小化"): they pull in
// a DB driver, blob backend, OIDC/session handling, the management API
// handlers, the invocation path, or the dashboard's embedded assets — all
// of which are funcbox-server's concern only. internal/config is also
// forbidden: it's server-only environment-variable configuration, distinct
// from the CLI's own ~/.config/funcbox handling in internal/cli.
var forbiddenImports = []string{
	"github.com/syumai/funcbox/internal/store",
	"github.com/syumai/funcbox/internal/blob",
	"github.com/syumai/funcbox/internal/auth",
	"github.com/syumai/funcbox/internal/api",
	"github.com/syumai/funcbox/internal/service",
	"github.com/syumai/funcbox/internal/server",
	"github.com/syumai/funcbox/internal/invoke",
	"github.com/syumai/funcbox/internal/dashboard",
	"github.com/syumai/funcbox/internal/config",
}

// TestBinarySeparation enforces tmp/02-architecture.md's dependency
// boundary mechanically: `go list -deps` over the funcbox CLI binary's own
// package (cmd/funcbox) must never resolve to any of forbiddenImports.
// This is a whole-binary check — it also transitively covers
// internal/cli, which is where those imports would actually be
// introduced.
func TestBinarySeparation(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps .: %v\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	depSet := make(map[string]bool, len(deps))
	for _, d := range deps {
		depSet[d] = true
	}

	for _, forbidden := range forbiddenImports {
		if depSet[forbidden] {
			t.Errorf("cmd/funcbox must not depend on %s (tmp/02-architecture.md binary separation), but go list -deps reports it", forbidden)
		}
	}
}
