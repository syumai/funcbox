package auth

import (
	"path/filepath"
	"strings"

	"github.com/syumai/funcbox/internal/store"
)

// EvaluateLoginRules evaluates rules in order and reports whether email is
// permitted to authenticate (tmp/05-auth-and-permissions.md §5.4: "ログイ
// ン許可ルール。上から評価し最初にマッチしたものを適用"). rules must
// already be ordered by Ord ascending, which is what
// OrganizationRepo.ListLoginRules returns.
//
// An empty rule set denies everyone ("初期値は deny"). Callers are
// responsible for the one documented exception -- the very first login,
// which bootstraps the organization and always succeeds regardless of
// rules; see Auth.upsertUser.
func EvaluateLoginRules(rules []*store.LoginRule, email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	for _, r := range rules {
		if ruleMatches(r, email) {
			return r.Action == store.LoginRuleActionAllow
		}
	}
	return false
}

func ruleMatches(r *store.LoginRule, email string) bool {
	switch r.RuleType {
	case store.LoginRuleTypeDefault:
		return true
	case store.LoginRuleTypeEmailExact:
		return strings.EqualFold(strings.TrimSpace(r.Value), email)
	case store.LoginRuleTypeEmailDomain:
		_, domain, ok := strings.Cut(email, "@")
		return ok && strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(r.Value), "@"), domain)
	case store.LoginRuleTypeEmailGlob:
		ok, err := filepath.Match(strings.ToLower(strings.TrimSpace(r.Value)), email)
		return err == nil && ok
	default:
		return false
	}
}
