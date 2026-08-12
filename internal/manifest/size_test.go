package manifest

import "testing"

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "128MiB", want: 128 << 20},
		{in: "128mib", want: 128 << 20},
		{in: "1KiB", want: 1 << 10},
		{in: "1GiB", want: 1 << 30},
		{in: "10MB", want: 10 * 1000 * 1000},
		{in: "1KB", want: 1000},
		{in: "512B", want: 512},
		{in: "1048576", want: 1048576},
		{in: "0", want: 0},
		{in: "", wantErr: true},
		{in: "not-a-size", wantErr: true},
		{in: "-1MiB", wantErr: true},
		{in: "-5", wantErr: true},
		{in: "MiB", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseByteSize(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseByteSize(%q) = %d, nil, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseByteSize(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseByteSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
