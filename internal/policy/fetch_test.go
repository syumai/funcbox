package policy

import "testing"

func mustPattern(t *testing.T, s string) Pattern {
	t.Helper()
	p, err := ParsePattern(s)
	if err != nil {
		t.Fatalf("ParsePattern(%q): %v", s, err)
	}
	return p
}

func TestParseFetchMode(t *testing.T) {
	tests := []struct {
		in      string
		want    FetchMode
		wantErr bool
	}{
		{in: "deny", want: FetchModeDeny},
		{in: "allowlist", want: FetchModeAllowlist},
		{in: "allow-all", want: FetchModeAllowAll},
		{in: "bogus", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseFetchMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseFetchMode(%q) = nil error, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFetchMode(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseFetchMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestFetchModeOrdering(t *testing.T) {
	if !(FetchModeDeny < FetchModeAllowlist && FetchModeAllowlist < FetchModeAllowAll) {
		t.Fatalf("FetchMode ordering violated: deny=%d allowlist=%d allow-all=%d", FetchModeDeny, FetchModeAllowlist, FetchModeAllowAll)
	}
}

func TestEffective_ModeIntersection(t *testing.T) {
	deny := FetchPolicy{Mode: FetchModeDeny}
	allowAll := FetchPolicy{Mode: FetchModeAllowAll}
	allowlist := FetchPolicy{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "api.example.com")}}

	tests := []struct {
		name   string
		levels []FetchPolicy
		want   FetchMode
	}{
		{name: "all allow-all", levels: []FetchPolicy{allowAll, allowAll, allowAll}, want: FetchModeAllowAll},
		{name: "any deny wins", levels: []FetchPolicy{allowAll, deny, allowlist}, want: FetchModeDeny},
		{name: "allowlist plus allow-all is allowlist", levels: []FetchPolicy{allowAll, allowlist}, want: FetchModeAllowlist},
		{name: "no levels fails closed", levels: nil, want: FetchModeDeny},
		{name: "single deny", levels: []FetchPolicy{deny}, want: FetchModeDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := Effective(tt.levels...)
			if ep.Mode() != tt.want {
				t.Fatalf("Effective(%v).Mode() = %v, want %v", tt.levels, ep.Mode(), tt.want)
			}
		})
	}
}

// TestEffective_DocumentedExample reproduces the example from
// tmp/05-auth-and-permissions.md §5.6: org = "*.example.com",
// workspace = "api.example.com", manifest = allow-all. The effective
// policy must allow only api.example.com (the URL that matches BOTH
// levels with an allowlist) and nothing else, including the org's own
// wildcard apex and unrelated subdomains.
func TestEffective_DocumentedExample(t *testing.T) {
	org := FetchPolicy{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "*.example.com")}}
	ws := FetchPolicy{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "api.example.com")}}
	manifest := FetchPolicy{Mode: FetchModeAllowAll}

	ep := Effective(org, ws, manifest)
	if ep.Mode() != FetchModeAllowlist {
		t.Fatalf("Mode() = %v, want allowlist", ep.Mode())
	}

	tests := []struct {
		host string
		port int
		want bool
	}{
		{host: "api.example.com", port: 443, want: true},
		{host: "api.example.com", port: 80, want: true},
		{host: "other.example.com", port: 443, want: false}, // matches org, not ws
		{host: "example.com", port: 443, want: false},       // apex: doesn't match org's wildcard at all
		{host: "api.example.com", port: 8443, want: false},  // no explicit port on either allowlist entry
		{host: "evil.com", port: 443, want: false},
	}
	for _, tt := range tests {
		got := ep.Decision(tt.host, tt.port)
		if got != tt.want {
			t.Errorf("Decision(%q, %d) = %v, want %v", tt.host, tt.port, got, tt.want)
		}
	}
}

func TestEffective_Decision(t *testing.T) {
	tests := []struct {
		name   string
		levels []FetchPolicy
		host   string
		port   int
		want   bool
	}{
		{
			name:   "deny blocks everything",
			levels: []FetchPolicy{{Mode: FetchModeDeny}},
			host:   "api.example.com", port: 443,
			want: false,
		},
		{
			name:   "allow-all permits everything",
			levels: []FetchPolicy{{Mode: FetchModeAllowAll}},
			host:   "anything.example.com", port: 12345,
			want: true,
		},
		{
			name: "allowlist requires match on every allowlisted level",
			levels: []FetchPolicy{
				{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "*.example.com")}},
				{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "*.internal.example.com")}},
			},
			host: "svc.internal.example.com", port: 443,
			want: true,
		},
		{
			name: "allowlist rejects when only one level matches",
			levels: []FetchPolicy{
				{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "*.example.com")}},
				{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "*.internal.example.com")}},
			},
			host: "public.example.com", port: 443,
			want: false,
		},
		{
			name: "empty allowlist denies everything",
			levels: []FetchPolicy{
				{Mode: FetchModeAllowlist, Allow: nil},
			},
			host: "api.example.com", port: 443,
			want: false,
		},
		{
			name: "personal function has no workspace level, two levels only",
			levels: []FetchPolicy{
				{Mode: FetchModeAllowlist, Allow: []Pattern{mustPattern(t, "api.github.com")}},
				{Mode: FetchModeAllowAll},
			},
			host: "api.github.com", port: 443,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := Effective(tt.levels...)
			got := ep.Decision(tt.host, tt.port)
			if got != tt.want {
				t.Fatalf("Decision(%q, %d) = %v, want %v", tt.host, tt.port, got, tt.want)
			}
		})
	}
}
