package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/syumai/funcbox/manifest"
	"github.com/syumai/funcbox/server/internal/store"
)

// maxUserIDLength is the DNS-label length limit enforced by
// manifest.ValidateUserID.
const maxUserIDLength = 63

var userIDSanitizeRE = regexp.MustCompile(`[^a-z0-9-]+`)

// DeriveUserID produces a fresh, unclaimed public User ID for a newly
// created user from the local part of their email address. On collision, or
// if the sanitized local part is empty or reserved, it appends "-2", "-3",
// and so on until an available candidate is found.
func DeriveUserID(ctx context.Context, st store.Store, email string) (string, error) {
	local, _, _ := strings.Cut(email, "@")
	base := sanitizeUserID(local)
	if base == "" {
		base = "user"
	}

	candidate := base
	for n := 2; ; n++ {
		if manifest.ValidateUserID(candidate) == nil {
			_, err := st.PublicUserIDs().ByUserID(ctx, candidate)
			if errors.Is(err, store.ErrNotFound) {
				return candidate, nil
			}
			if err != nil {
				return "", fmt.Errorf("auth: look up User ID %q: %w", candidate, err)
			}
		}
		candidate = suffixUserID(base, n)
	}
}

// sanitizeUserID converts an email local part into a DNS-label candidate.
func sanitizeUserID(local string) string {
	s := strings.ToLower(local)
	s = userIDSanitizeRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > maxUserIDLength {
		s = strings.TrimRight(s[:maxUserIDLength], "-")
	}
	return s
}

func suffixUserID(base string, n int) string {
	suffix := fmt.Sprintf("-%d", n)
	trimmed := base
	if len(trimmed)+len(suffix) > maxUserIDLength {
		trimmed = trimmed[:maxUserIDLength-len(suffix)]
		trimmed = strings.TrimRight(trimmed, "-")
	}
	return trimmed + suffix
}
