package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/syumai/funcbox/internal/manifest"
)

// manifestFilenames mirrors internal/manifest's own search order
// (funcbox.yaml -> funcbox.yml -> funcbox.json); that list isn't exported,
// so it's restated here for the CLI's own "does this project have a
// manifest at all" probing (LoadProjectManifest needs to read the file
// directly off disk, before any bundle has been collected).
var manifestFilenames = []string{"funcbox.yaml", "funcbox.yml", "funcbox.json"}

// LoadProjectManifest looks for a manifest file directly at the root of
// dir and parses it, without touching any other file. This lets callers
// (deploy, dev) learn compat.nodejs and owner before deciding how to
// collect the rest of the bundle (CollectFiles needs compat.nodejs to know
// whether to exclude node_modules).
//
// A project with no manifest file is valid (tmp/04-manifest.md: "マニフェ
// ストが存在しない場合もデプロイは可能"); LoadProjectManifest returns an
// empty *manifest.Manifest (Source == "") in that case, matching
// manifest.Parse's own behavior.
func LoadProjectManifest(dir string) (*manifest.Manifest, error) {
	for _, name := range manifestFilenames {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("cli: read %s: %w", name, err)
		}
		return manifest.Parse(map[string][]byte{name: data})
	}
	return &manifest.Manifest{}, nil
}

// ResolveOwner implements the owner resolution precedence from
// tmp/07-http-api.md §7.5: "--owner フラグ > manifest の owner キー > 自分
// のユーザー handle". The CLI doesn't know the caller's own handle without
// an extra API round trip, so per the phase 5 spec it's explicit rather
// than implied: flagOwner wins, then the manifest's own owner field, and
// otherwise an actionable error asking the user to supply one (the server
// would otherwise derive it from the token's user, but v1's CLI makes this
// explicit rather than silent).
func ResolveOwner(flagOwner string, m *manifest.Manifest) (string, error) {
	if flagOwner != "" {
		return flagOwner, nil
	}
	if m.Owner != "" {
		return m.Owner, nil
	}
	return "", fmt.Errorf("owner not specified: pass --owner, or set \"owner\" in the manifest")
}
