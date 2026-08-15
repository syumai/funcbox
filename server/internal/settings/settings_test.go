package settings_test

import (
	"reflect"
	"testing"

	"github.com/syumai/funcbox/bundle"
	"github.com/syumai/funcbox/server/internal/settings"
)

func TestParseOrg_EmptyJSONUsesDefaults(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{}`))
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	want := settings.DefaultOrg()
	if !reflect.DeepEqual(o, want) {
		t.Fatalf("ParseOrg({}) = %+v, want defaults %+v", o, want)
	}
}

func TestParseOrg_NilBytesUsesDefaults(t *testing.T) {
	o, err := settings.ParseOrg(nil)
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if !reflect.DeepEqual(o, settings.DefaultOrg()) {
		t.Fatalf("ParseOrg(nil) = %+v, want defaults", o)
	}
}

func TestParseOrg_PartialOverride(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{"allow_user_functions": false}`))
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if o.AllowUserFunctions {
		t.Fatal("allow_user_functions override was not applied")
	}
	if o.MaxVisibility != "public" {
		t.Fatalf("max_visibility = %q, want default %q", o.MaxVisibility, "public")
	}
}

// TestParseOrg_IgnoresLegacyAllowWorkspaceCreationKey covers the §14.1
// migration note: allow_workspace_creation was removed from the Org
// struct (workspace creation is now decided by role alone -- see
// internal/authz.CanCreateWorkspace), but an organization's persisted
// settings blob from before the change may still contain that key.
// json.Unmarshal must silently ignore it rather than erroring.
func TestParseOrg_IgnoresLegacyAllowWorkspaceCreationKey(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{"allow_workspace_creation": true, "allow_user_functions": false}`))
	if err != nil {
		t.Fatalf("ParseOrg with legacy allow_workspace_creation key: %v", err)
	}
	if o.AllowUserFunctions {
		t.Fatal("allow_user_functions override was not applied despite the legacy key being present")
	}
	// There's no field left to assert on for allow_workspace_creation
	// itself -- the point of this test is that decoding succeeds and the
	// rest of the document is still parsed correctly around the unknown
	// key.
}

func TestParseOrg_BundleUnpackedMaxClampedToSystemCeiling(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{"limits": {"bundle_unpacked_max": 999999999999}}`))
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if o.Limits.BundleUnpackedMax != bundle.MaxUnpackedBytes {
		t.Fatalf("BundleUnpackedMax = %d, want clamped to %d", o.Limits.BundleUnpackedMax, bundle.MaxUnpackedBytes)
	}
}

func TestParseOrg_BundleUnpackedMaxBelowCeilingIsRespected(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{"limits": {"bundle_unpacked_max": 1048576}}`))
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if o.Limits.BundleUnpackedMax != 1048576 {
		t.Fatalf("BundleUnpackedMax = %d, want 1048576", o.Limits.BundleUnpackedMax)
	}
}

func TestParseOrg_InvalidJSONErrors(t *testing.T) {
	if _, err := settings.ParseOrg([]byte(`not json`)); err == nil {
		t.Fatal("ParseOrg(invalid) = nil error, want error")
	}
}

func TestOrg_JSONRoundTrip(t *testing.T) {
	o := settings.DefaultOrg()
	o.AllowUserFunctions = false
	o.FetchPolicy = settings.FetchPolicy{Mode: "allowlist", Allow: []string{"*.example.com"}}

	got, err := settings.ParseOrg(o.JSON())
	if err != nil {
		t.Fatalf("ParseOrg(o.JSON()): %v", err)
	}
	if !reflect.DeepEqual(got, o) {
		t.Fatalf("round trip = %+v, want %+v", got, o)
	}
}

func TestLanguageResolution(t *testing.T) {
	if got := settings.EffectiveLanguage("ja", "en"); got != "ja" {
		t.Fatalf("user language should win: got %q, want %q", got, "ja")
	}
	if got := settings.EffectiveLanguage("", "ja"); got != "ja" {
		t.Fatalf("organization language should be used: got %q, want %q", got, "ja")
	}
	if got := settings.EffectiveLanguage("", ""); got != "en" {
		t.Fatalf("default language should be English: got %q, want %q", got, "en")
	}
}

// TestParseOrg_RequireApprovalAndMaxFunctionsPerUserDefaults covers the
// defaults: require_approval defaults to false and max_functions_per_user
// defaults to 0 (unlimited) for an
// organization that has never set either.
func TestParseOrg_RequireApprovalAndMaxFunctionsPerUserDefaults(t *testing.T) {
	o := settings.DefaultOrg()
	if o.RequireApproval {
		t.Error("DefaultOrg().RequireApproval = true, want false")
	}
	if o.MaxFunctionsPerUser != 0 {
		t.Errorf("DefaultOrg().MaxFunctionsPerUser = %d, want 0 (unlimited)", o.MaxFunctionsPerUser)
	}
}

func TestParseOrg_RequireApprovalAndMaxFunctionsPerUserOverride(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{"require_approval": true, "max_functions_per_user": 5}`))
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if !o.RequireApproval {
		t.Error("require_approval override was not applied")
	}
	if o.MaxFunctionsPerUser != 5 {
		t.Errorf("max_functions_per_user = %d, want 5", o.MaxFunctionsPerUser)
	}
}

func TestParseWorkspace_MaxFunctionsPerMemberDefaultsToUnlimited(t *testing.T) {
	w := settings.DefaultWorkspace()
	if w.MaxFunctionsPerMember != 0 {
		t.Errorf("DefaultWorkspace().MaxFunctionsPerMember = %d, want 0 (unlimited)", w.MaxFunctionsPerMember)
	}
	w2, err := settings.ParseWorkspace([]byte(`{"max_functions_per_member": 3}`))
	if err != nil {
		t.Fatalf("ParseWorkspace: %v", err)
	}
	if w2.MaxFunctionsPerMember != 3 {
		t.Errorf("max_functions_per_member = %d, want 3", w2.MaxFunctionsPerMember)
	}
}

// TestParseOrg_OpenModeAndExposeCallerIdentityDefaults covers the
// defaults: both open_mode and expose_caller_identity default to false
// for an organization that has
// never set either.
func TestParseOrg_OpenModeAndExposeCallerIdentityDefaults(t *testing.T) {
	o := settings.DefaultOrg()
	if o.OpenMode {
		t.Error("DefaultOrg().OpenMode = true, want false")
	}
	if o.ExposeCallerIdentity {
		t.Error("DefaultOrg().ExposeCallerIdentity = true, want false")
	}
}

func TestParseOrg_OpenModeAndExposeCallerIdentityOverride(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{"open_mode": true, "expose_caller_identity": true}`))
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if !o.OpenMode {
		t.Error("open_mode override was not applied")
	}
	if !o.ExposeCallerIdentity {
		t.Error("expose_caller_identity override was not applied")
	}
}

func TestParseOrg_InvalidLanguageFallsBackToEnglish(t *testing.T) {
	o, err := settings.ParseOrg([]byte(`{"language":"fr"}`))
	if err != nil {
		t.Fatalf("ParseOrg: %v", err)
	}
	if o.Language != "en" {
		t.Fatalf("Language = %q, want English fallback", o.Language)
	}
}

func TestParseWorkspace_EmptyJSONUsesDefaults(t *testing.T) {
	w, err := settings.ParseWorkspace([]byte(`{}`))
	if err != nil {
		t.Fatalf("ParseWorkspace: %v", err)
	}
	if !reflect.DeepEqual(w, settings.DefaultWorkspace()) {
		t.Fatalf("ParseWorkspace({}) = %+v, want defaults", w)
	}
	if w.FetchPolicy.Mode != "allow-all" {
		t.Fatalf("default fetch policy mode = %q, want %q (unconstrained at WS level)", w.FetchPolicy.Mode, "allow-all")
	}
	if !w.MemberCanDeploy {
		t.Fatal("default member_can_deploy should be true")
	}
}

func TestParseWorkspace_PartialOverride(t *testing.T) {
	w, err := settings.ParseWorkspace([]byte(`{"member_can_deploy": false}`))
	if err != nil {
		t.Fatalf("ParseWorkspace: %v", err)
	}
	if w.MemberCanDeploy {
		t.Fatal("member_can_deploy override was not applied")
	}
	if w.FetchPolicy.Mode != "allow-all" {
		t.Fatal("fetch_policy should have kept its default")
	}
}

func TestFetchPolicy_Policy(t *testing.T) {
	fp := settings.FetchPolicy{Mode: "allowlist", Allow: []string{"api.example.com", "*.internal.example.com"}}
	p, err := fp.Policy()
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if len(p.Allow) != 2 {
		t.Fatalf("len(p.Allow) = %d, want 2", len(p.Allow))
	}
}

func TestFetchPolicy_Policy_InvalidMode(t *testing.T) {
	fp := settings.FetchPolicy{Mode: "bogus"}
	if _, err := fp.Policy(); err == nil {
		t.Fatal("Policy() with invalid mode = nil error, want error")
	}
}
