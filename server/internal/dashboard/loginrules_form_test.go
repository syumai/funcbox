package dashboard

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/syumai/funcbox/server/internal/store"
)

// promoteToAdmin promotes owner's user to org admin directly against the
// store (there's no self-service API for a member to grant themselves the
// role) -- used by this file's tests so the SSR /dashboard/org routes'
// admin-only gate passes for a session obtained through the real
// loginViaHTTP flow rather than the bootstrap() shortcut's admin.
func promoteToAdmin(t *testing.T, env *testEnv, owner string) {
	t.Helper()
	ctx := context.Background()
	id, err := env.store.PublicUserIDs().ByUserID(ctx, owner)
	if err != nil {
		t.Fatalf("look up User ID %s: %v", owner, err)
	}
	u, err := env.store.Users().ByID(ctx, id.InternalUserID)
	if err != nil {
		t.Fatalf("look up user %s: %v", owner, err)
	}
	u.Role = store.RoleAdmin
	if err := env.store.Users().Update(ctx, u); err != nil {
		t.Fatalf("promote %s to admin: %v", owner, err)
	}
}

// loginRulesForm builds the exact field shape org.tsx's login-rules editor
// submits: one row per rule (in order), followed by SPARE_LOGIN_RULE_ROWS
// blank rows -- see routes/org.tsx's ruleRow/SPARE_LOGIN_RULE_ROWS.
func loginRulesForm(rows [][3]string) url.Values {
	form := url.Values{}
	add := func(ruleType, value, action string) {
		form.Add("rule_type[]", ruleType)
		form.Add("rule_value[]", value)
		form.Add("rule_action[]", action)
	}
	for _, row := range rows {
		add(row[0], row[1], row[2])
	}
	const spareLoginRuleRows = 5 // matches org.tsx's SPARE_LOGIN_RULE_ROWS
	for i := 0; i < spareLoginRuleRows; i++ {
		add("", "", "allow")
	}
	return form
}

// TestDashboard_LoginRulesForm_EditsExistingRulePersists is the regression
// test for a reported bug: an admin editing an EXISTING login rule's action
// via the real /dashboard/org SSR form (not the raw PUT /api/v1/org/login-rules
// API) appeared not to persist. It drives the full real HTTP + real
// (embedded) dashboard build path -- login, promote to admin, GET the
// rendered form to confirm its shape matches what this test then submits,
// POST an edit to the existing "default" rule's action only, and assert the
// change actually reached the store, not just the redirect's flash message.
func TestDashboard_LoginRulesForm_EditsExistingRulePersists(t *testing.T) {
	env := newTestEnv(t, "") // "" -> embedded (real) dist, exactly what ships
	env.bootstrap(t)         // seeds [email_domain example.com allow, default deny]
	client := env.loginViaHTTP(t, "newuser@example.com")
	promoteToAdmin(t, env, "newuser")

	getResp, err := client.Get(env.baseURL + "/dashboard/org")
	if err != nil {
		t.Fatalf("GET /dashboard/org: %v", err)
	}
	getBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /dashboard/org status = %d, body = %s", getResp.StatusCode, getBody)
	}
	html := string(getBody)
	if !strings.Contains(html, "rule_type[]") {
		t.Fatalf("page does not contain the login rules form; body: %s", html)
	}
	// The existing "default" rule's action select must currently show deny
	// selected -- confirms this test's hand-built submission below actually
	// mirrors what the rendered form would submit unedited.
	if !strings.Contains(html, `<option value="deny" selected="">deny</option>`) {
		t.Fatalf("rendered form's default row does not show the expected pre-edit state (action=deny); body: %s", html)
	}

	// Submit the SAME two rules bootstrap() seeded, with ONLY the "default"
	// row's action flipped from deny to allow -- exactly the edit a real
	// admin would make by changing one <select>, leaving everything else
	// (including the OTHER existing rule) untouched.
	form := loginRulesForm([][3]string{
		{"email_domain", "example.com", "allow"},
		{"default", "", "allow"}, // was deny
	})
	postResp, err := client.PostForm(env.baseURL+"/dashboard/org/login-rules", form)
	if err != nil {
		t.Fatalf("POST /dashboard/org/login-rules: %v", err)
	}
	postBody, _ := io.ReadAll(postResp.Body)
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /dashboard/org/login-rules status = %d, want 303, body = %s", postResp.StatusCode, postBody)
	}
	if loc := postResp.Header.Get("Location"); !strings.Contains(loc, "notice=") {
		t.Fatalf("Location = %q, want a notice= flash (save must succeed)", loc)
	}

	rules, err := env.store.Organizations().ListLoginRules(context.Background())
	if err != nil {
		t.Fatalf("ListLoginRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("login rules after edit = %d rows, want 2 (the other existing rule must survive untouched); rows: %+v", len(rules), rules)
	}
	var sawDomain, sawDefault bool
	for _, r := range rules {
		switch r.RuleType {
		case store.LoginRuleTypeEmailDomain:
			sawDomain = true
			if r.Value != "example.com" || r.Action != store.LoginRuleActionAllow {
				t.Errorf("email_domain rule = %+v, want unchanged (example.com, allow)", r)
			}
		case store.LoginRuleTypeDefault:
			sawDefault = true
			if r.Action != store.LoginRuleActionAllow {
				t.Errorf("default rule action = %q, want %q -- the edit did not persist", r.Action, store.LoginRuleActionAllow)
			}
		}
	}
	if !sawDomain || !sawDefault {
		t.Fatalf("expected both an email_domain and a default rule after the edit; rows: %+v", rules)
	}
}

// TestDashboard_LoginRulesForm_SelfLockoutRejected covers the admin
// self-lockout guard (internal/api's handleLoginRulesPut) as reached through
// the SSR form: a submission that would deny the submitting admin's own
// email is rejected (the store is left untouched) and the resulting flash
// is an error, not "saved".
func TestDashboard_LoginRulesForm_SelfLockoutRejected(t *testing.T) {
	env := newTestEnv(t, "")
	env.bootstrap(t)
	client := env.loginViaHTTP(t, "newuser@example.com")
	promoteToAdmin(t, env, "newuser")
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	// Drop the email_domain row entirely (type=""), leaving only
	// default:deny -- a rule set that denies newuser@example.com too.
	form := loginRulesForm([][3]string{
		{"default", "", "deny"},
	})
	postResp, err := client.PostForm(env.baseURL+"/dashboard/org/login-rules", form)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusSeeOther && postResp.StatusCode != http.StatusFound {
		t.Fatalf("POST status = %d, want a redirect", postResp.StatusCode)
	}
	loc := postResp.Header.Get("Location")
	if !strings.Contains(loc, "error=") {
		t.Fatalf("Location = %q, want an error= flash (self-lockout must be rejected)", loc)
	}

	rules, err := env.store.Organizations().ListLoginRules(context.Background())
	if err != nil {
		t.Fatalf("ListLoginRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("login rules after a rejected self-lockout submission = %d rows, want the original 2 (unchanged); rows: %+v", len(rules), rules)
	}
}
