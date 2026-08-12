package policy

import "testing"

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{name: "exact host", pattern: "api.example.com"},
		{name: "wildcard host", pattern: "*.example.com"},
		{name: "exact host with port", pattern: "db.example.com:5432"},
		{name: "IPv4 literal", pattern: "10.0.3.7"},
		{name: "IPv4 literal with port", pattern: "10.0.3.7:8080"},
		{name: "single label host", pattern: "localhost"},
		{name: "empty pattern", pattern: "", wantErr: true},
		{name: "bare wildcard", pattern: "*.", wantErr: true},
		{name: "wildcard with no domain", pattern: "*", wantErr: true},
		{name: "invalid port", pattern: "example.com:notaport", wantErr: true},
		{name: "port out of range", pattern: "example.com:99999", wantErr: true},
		{name: "port zero", pattern: "example.com:0", wantErr: true},
		{name: "invalid host characters", pattern: "exa mple.com", wantErr: true},
		{name: "invalid host with underscore label too long", pattern: "-bad.example.com", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePattern(tt.pattern)
			if tt.wantErr && err == nil {
				t.Fatalf("ParsePattern(%q) = nil error, want error", tt.pattern)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ParsePattern(%q) unexpected error: %v", tt.pattern, err)
			}
		})
	}
}

func TestPattern_Matches(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		port    int
		want    bool
	}{
		// Exact match.
		{name: "exact match default port 443", pattern: "api.example.com", host: "api.example.com", port: 443, want: true},
		{name: "exact match default port 80", pattern: "api.example.com", host: "api.example.com", port: 80, want: true},
		{name: "exact match non-default port rejected", pattern: "api.example.com", host: "api.example.com", port: 8443, want: false},
		{name: "exact match wrong host", pattern: "api.example.com", host: "other.example.com", port: 443, want: false},
		{name: "exact match case-insensitive", pattern: "API.Example.COM", host: "api.example.com", port: 443, want: true},

		// Explicit port.
		{name: "explicit port match", pattern: "db.example.com:5432", host: "db.example.com", port: 5432, want: true},
		{name: "explicit port mismatch", pattern: "db.example.com:5432", host: "db.example.com", port: 5433, want: false},
		{name: "explicit port does not fall back to default", pattern: "db.example.com:5432", host: "db.example.com", port: 443, want: false},

		// Wildcard subdomain.
		{name: "wildcard matches one-level subdomain", pattern: "*.example.com", host: "api.example.com", port: 443, want: true},
		{name: "wildcard matches multi-level subdomain", pattern: "*.example.com", host: "a.b.example.com", port: 443, want: true},
		{name: "wildcard does not match apex", pattern: "*.example.com", host: "example.com", port: 443, want: false},
		{name: "wildcard does not match unrelated suffix", pattern: "*.example.com", host: "evil-example.com", port: 443, want: false},
		{name: "wildcard does not match different domain", pattern: "*.example.com", host: "api.other.com", port: 443, want: false},
		{name: "wildcard case-insensitive", pattern: "*.Example.com", host: "API.example.COM", port: 443, want: true},
		{name: "wildcard honors explicit port", pattern: "*.example.com:8443", host: "api.example.com", port: 8443, want: true},
		{name: "wildcard rejects wrong explicit port", pattern: "*.example.com:8443", host: "api.example.com", port: 443, want: false},

		// IP literal.
		{name: "IP literal exact match", pattern: "10.0.3.7", host: "10.0.3.7", port: 443, want: true},
		{name: "IP literal mismatch", pattern: "10.0.3.7", host: "10.0.3.8", port: 443, want: false},

		// Trailing dot (FQDN) normalization.
		{name: "trailing dot on request host is normalized", pattern: "api.example.com", host: "api.example.com.", port: 443, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParsePattern(tt.pattern)
			if err != nil {
				t.Fatalf("ParsePattern(%q): %v", tt.pattern, err)
			}
			got := p.Matches(tt.host, tt.port)
			if got != tt.want {
				t.Fatalf("Pattern(%q).Matches(%q, %d) = %v, want %v", tt.pattern, tt.host, tt.port, got, tt.want)
			}
		})
	}
}
