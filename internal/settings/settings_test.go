package settings_test

import (
	"reflect"
	"testing"

	"github.com/syumai/funcbox/internal/bundle"
	"github.com/syumai/funcbox/internal/settings"
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
	if !o.AllowWorkspaceCreation {
		t.Fatal("allow_workspace_creation should have kept its default (true)")
	}
	if o.MaxVisibility != "public" {
		t.Fatalf("max_visibility = %q, want default %q", o.MaxVisibility, "public")
	}
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
