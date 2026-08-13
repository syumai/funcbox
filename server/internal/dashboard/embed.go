package dashboard

import (
	"embed"
	"io/fs"
)

// embeddedDist embeds dashboard/dist/** as it exists at `go build` time.
// The "all:" prefix is required, not decorative: without it, go:embed
// excludes any file/directory whose name starts with "." or "_", and
// dist/ exists in git even though its build output is .gitignored) starts
// with ".". Without "all:", a pristine checkout that hasn't run `pnpm
// build` yet -- where .gitkeep is the ONLY file in dist/ -- would fail this
// embed directive at COMPILE time with "pattern dist: no matching files
// found", turning a missing dashboard build into a Go build error instead
// of the clear runtime error page New/ServeHTTP are meant to produce (see
// server.go's dashboardNotBuiltError).
//
//go:embed all:dist
var embeddedDist embed.FS

// embeddedDistFS returns the "dist" subtree of embeddedDist, so the rest of
// this package (and its Config.DistDir override for development/tests --
// see server.go) can treat "server.js" / "assets/..." as fs.FS root paths
// regardless of which underlying filesystem backs them.
func embeddedDistFS() (fs.FS, error) {
	return fs.Sub(embeddedDist, "dist")
}
