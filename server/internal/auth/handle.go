package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/manifest"
)

// maxHandleLength matches the DNS-label length limit manifest.ValidateHandle
// enforces (63 characters).
const maxHandleLength = 63

var handleSanitizeRE = regexp.MustCompile(`[^a-z0-9-]+`)

// DeriveHandle produces a fresh, unclaimed DNS-label handle for a
// newly-created user, from the local part of their email address
// (tmp/05-auth-and-permissions.md §5.1 first-login bootstrap;
// tmp/06-data-model.md's handle design note: "初回ログイン時に email
// ローカルパートから自動生成（衝突時サフィックス付与）"). On collision --
// or if the sanitized local part is empty or a reserved name -- it
// appends "-2", "-3", ... until an available, non-reserved candidate is
// found.
func DeriveHandle(ctx context.Context, st store.Store, email string) (string, error) {
	local, _, _ := strings.Cut(email, "@")
	base := sanitizeHandle(local)
	if base == "" {
		base = "user"
	}

	candidate := base
	for n := 2; ; n++ {
		if manifest.ValidateHandle(candidate) == nil {
			_, err := st.Handles().ByHandle(ctx, candidate)
			if errors.Is(err, store.ErrNotFound) {
				return candidate, nil
			}
			if err != nil {
				return "", fmt.Errorf("auth: look up handle %q: %w", candidate, err)
			}
		}
		candidate = suffixHandle(base, n)
	}
}

// sanitizeHandle lowercases local and replaces every run of characters
// outside [a-z0-9-] with a single "-", then trims leading/trailing
// hyphens and clamps to maxHandleLength -- the same DNS-label shape
// manifest.ValidateHandle requires, minus the reserved-name check (handled
// by the caller's retry loop instead, since a reserved base name should
// fall through to "-2" rather than to a different sanitization).
func sanitizeHandle(local string) string {
	s := strings.ToLower(local)
	s = handleSanitizeRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > maxHandleLength {
		s = strings.TrimRight(s[:maxHandleLength], "-")
	}
	return s
}

// suffixHandle appends "-n" to base, trimming base as needed to keep the
// whole candidate within maxHandleLength.
func suffixHandle(base string, n int) string {
	suffix := fmt.Sprintf("-%d", n)
	trimmed := base
	if len(trimmed)+len(suffix) > maxHandleLength {
		trimmed = trimmed[:maxHandleLength-len(suffix)]
		trimmed = strings.TrimRight(trimmed, "-")
	}
	return trimmed + suffix
}
