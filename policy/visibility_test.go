package policy

import "testing"

func TestParseVisibility(t *testing.T) {
	tests := []struct {
		in      string
		want    Visibility
		wantErr bool
	}{
		{in: "public", want: VisibilityPublic},
		{in: "org", want: VisibilityOrg},
		{in: "workspace", want: VisibilityWorkspace},
		{in: "bogus", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseVisibility(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseVisibility(%q) = nil error, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVisibility(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseVisibility(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestVisibilityOrdering(t *testing.T) {
	if !(VisibilityWorkspace < VisibilityOrg && VisibilityOrg < VisibilityPublic) {
		t.Fatalf("Visibility ordering violated: workspace=%d org=%d public=%d", VisibilityWorkspace, VisibilityOrg, VisibilityPublic)
	}
}

func TestMinVisibility(t *testing.T) {
	tests := []struct {
		name string
		in   []Visibility
		want Visibility
	}{
		{name: "public capped by org", in: []Visibility{VisibilityPublic, VisibilityOrg}, want: VisibilityOrg},
		{name: "public capped by workspace", in: []Visibility{VisibilityPublic, VisibilityOrg, VisibilityWorkspace}, want: VisibilityWorkspace},
		{name: "all public", in: []Visibility{VisibilityPublic, VisibilityPublic}, want: VisibilityPublic},
		{name: "no args fails closed", in: nil, want: VisibilityWorkspace},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MinVisibility(tt.in...)
			if got != tt.want {
				t.Fatalf("MinVisibility(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
