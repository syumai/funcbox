package auth

import (
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
)

func TestEvaluateLoginRules_EmptyRulesDeniesEveryone(t *testing.T) {
	if EvaluateLoginRules(nil, "anyone@example.com") {
		t.Fatal("empty rule set should deny everyone")
	}
}

func TestEvaluateLoginRules_EmailDomain(t *testing.T) {
	rules := []*store.LoginRule{
		{RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionAllow},
		{RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}
	if !EvaluateLoginRules(rules, "alice@example.com") {
		t.Error("alice@example.com should be allowed by the domain rule")
	}
	if EvaluateLoginRules(rules, "alice@other.com") {
		t.Error("alice@other.com should fall through to default deny")
	}
	// Case-insensitive.
	if !EvaluateLoginRules(rules, "Alice@EXAMPLE.COM") {
		t.Error("domain matching should be case-insensitive")
	}
}

func TestEvaluateLoginRules_EmailExact(t *testing.T) {
	rules := []*store.LoginRule{
		{RuleType: store.LoginRuleTypeEmailExact, Value: "partner@gmail.com", Action: store.LoginRuleActionAllow},
		{RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}
	if !EvaluateLoginRules(rules, "partner@gmail.com") {
		t.Error("exact match should be allowed")
	}
	if EvaluateLoginRules(rules, "other@gmail.com") {
		t.Error("non-matching email should be denied")
	}
}

func TestEvaluateLoginRules_EmailGlob(t *testing.T) {
	rules := []*store.LoginRule{
		{RuleType: store.LoginRuleTypeEmailGlob, Value: "*-dev@example.com", Action: store.LoginRuleActionAllow},
		{RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionDeny},
	}
	if !EvaluateLoginRules(rules, "alice-dev@example.com") {
		t.Error("glob should match alice-dev@example.com")
	}
	if EvaluateLoginRules(rules, "alice@example.com") {
		t.Error("glob should not match alice@example.com")
	}
}

func TestEvaluateLoginRules_OrderMattersFirstMatchWins(t *testing.T) {
	rules := []*store.LoginRule{
		{RuleType: store.LoginRuleTypeEmailDomain, Value: "example.com", Action: store.LoginRuleActionDeny},
		{RuleType: store.LoginRuleTypeEmailExact, Value: "vip@example.com", Action: store.LoginRuleActionAllow},
	}
	// The domain-deny rule comes first and matches, so it wins even
	// though a later, more specific rule would have allowed it.
	if EvaluateLoginRules(rules, "vip@example.com") {
		t.Error("first matching rule (domain deny) should win over a later allow")
	}
}

func TestEvaluateLoginRules_DefaultAllow(t *testing.T) {
	rules := []*store.LoginRule{
		{RuleType: store.LoginRuleTypeDefault, Action: store.LoginRuleActionAllow},
	}
	if !EvaluateLoginRules(rules, "anyone@anywhere.com") {
		t.Error("default allow rule should permit any email")
	}
}
