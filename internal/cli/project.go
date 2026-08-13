package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/syumai/funcbox/manifest"
)

// manifestFilenames mirrors manifest's own search order
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
// public User ID". flagOwner wins, then the manifest's own owner field;
// if neither is set, meFallback (typically a GET /api/v1/me round trip —
// see callerUserID) is consulted for the caller's own User ID, called lazily
// so the common case (an explicit --owner or manifest owner) never pays
// for the extra request. meFallback may be nil, in which case a missing
// owner is an immediate actionable error instead of a nil-func panic —
// useful for callers (like tests) with no server to call.
func ResolveOwner(flagOwner string, m *manifest.Manifest, meFallback func() (string, error)) (string, error) {
	if flagOwner != "" {
		return flagOwner, nil
	}
	if m.Owner != "" {
		return m.Owner, nil
	}
	if meFallback == nil {
		return "", fmt.Errorf("owner not specified: pass --owner, or set \"owner\" in the manifest")
	}
	userID, err := meFallback()
	if err != nil {
		return "", fmt.Errorf("owner not specified: pass --owner, set \"owner\" in the manifest, or fix this error resolving your own User ID: %w", err)
	}
	if userID == "" {
		return "", fmt.Errorf("owner not specified: pass --owner, set \"owner\" in the manifest, or set a User ID for your account first")
	}
	return userID, nil
}
