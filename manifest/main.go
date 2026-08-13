package manifest

import (
	"errors"
	"fmt"
)

// DefaultMainCandidates is the entry-point search order used when a
// index.mjs").
var DefaultMainCandidates = []string{"index.js", "index.mjs"}

var (
	// ErrMainNotFound is returned by ResolveMain when the manifest
	// names an explicit main file that isn't present in the bundle.
	ErrMainNotFound = errors.New("manifest: main entry point not found in bundle")
	// ErrNoEntryPoint is returned by ResolveMain when the manifest
	// doesn't specify main and none of DefaultMainCandidates is
	// present in the bundle.
	ErrNoEntryPoint = errors.New("manifest: no entry point found")
)

// ResolveMain determines the actual entry-point path for a bundle:
// if main is non-empty, it must name a file present in files;
// otherwise DefaultMainCandidates are tried in order, and the first
// one present in files is returned.
//
// This resolution is deliberately not performed by Parse, since it
// describes it as validated at deploy time, once both are
// available).
func ResolveMain(main string, files map[string][]byte) (string, error) {
	if main != "" {
		if _, ok := files[main]; !ok {
			return "", fmt.Errorf("%w: %q", ErrMainNotFound, main)
		}
		return main, nil
	}

	for _, candidate := range DefaultMainCandidates {
		if _, ok := files[candidate]; ok {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: tried %v", ErrNoEntryPoint, DefaultMainCandidates)
}
