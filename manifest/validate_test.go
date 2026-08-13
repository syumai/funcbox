package manifest

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate_Name(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "valid simple", value: "hello"},
		{name: "valid with digits and hyphen", value: "hello-world-123"},
		{name: "valid single char", value: "a"},
		{name: "valid max length 63", value: strings.Repeat("a", 63)},
		{name: "empty", value: "", wantErr: ErrInvalidName},
		{name: "too long 64 chars", value: strings.Repeat("a", 64), wantErr: ErrInvalidName},
		{name: "uppercase rejected", value: "Hello", wantErr: ErrInvalidName},
		{name: "leading hyphen rejected", value: "-hello", wantErr: ErrInvalidName},
		{name: "trailing hyphen rejected", value: "hello-", wantErr: ErrInvalidName},
		{name: "underscore rejected", value: "hello_world", wantErr: ErrInvalidName},
		{name: "reserved dashboard", value: "dashboard", wantErr: ErrReservedName},
		{name: "reserved api", value: "api", wantErr: ErrReservedName},
		{name: "reserved auth", value: "auth", wantErr: ErrReservedName},
		{name: "reserved dev", value: "dev", wantErr: ErrReservedName},
		{name: "reserved assets", value: "assets", wantErr: ErrReservedName},
		{name: "reserved healthz", value: "healthz", wantErr: ErrReservedName},
		// "_" isn't a valid DNS-label character, so an underscore-
		// rejected by the format check before reservation is even
		// consulted; IsReserved still reports it as reserved for
		// reuse elsewhere (see TestValidate_AllReservedNamesRejected
		// and TestIsReserved_UnderscorePrefix).
		{name: "underscore prefix rejected by format first", value: "_internal", wantErr: ErrInvalidName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manifest{Name: tt.value}
			err := Validate(m)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want error wrapping %v", err, tt.wantErr)
			}
		})
	}
}

// reservedNamesRoundTrip proves ReservedNames itself, one at a time,
// is rejected by Validate/IsReserved -- guarding against the list and
// the check function drifting apart.
func TestValidate_AllReservedNamesRejected(t *testing.T) {
	for _, name := range ReservedNames {
		if name == "favicon.ico" || name == "robots.txt" {
			// These contain a '.', so they can never satisfy the
			// DNS-label name regex in the first place; the format
			// check (ErrInvalidName) fires before reservation is
			// even consulted. They remain useful as router-level
			m := &Manifest{Name: name}
			if err := Validate(m); !errors.Is(err, ErrInvalidName) {
				t.Errorf("Validate(%q) error = %v, want ErrInvalidName", name, err)
			}
			continue
		}
		m := &Manifest{Name: name}
		if err := Validate(m); !errors.Is(err, ErrReservedName) {
			t.Errorf("Validate(%q) error = %v, want ErrReservedName", name, err)
		}
		if !IsReserved(name) {
			t.Errorf("IsReserved(%q) = false, want true", name)
		}
	}
}

func TestIsReserved_UnderscorePrefix(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "_internal", want: true},
		{name: "_", want: true},
		{name: "internal", want: false},
		{name: "hello-world", want: false},
	}
	for _, tt := range tests {
		if got := IsReserved(tt.name); got != tt.want {
			t.Errorf("IsReserved(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestValidate_Owner(t *testing.T) {
	tests := []struct {
		name    string
		owner   string
		wantErr error
	}{
		{name: "empty owner is allowed (optional)", owner: ""},
		{name: "valid owner", owner: "data-team"},
		{name: "invalid owner format", owner: "Data_Team", wantErr: ErrInvalidOwner},
		{name: "reserved owner", owner: "dashboard", wantErr: ErrReservedName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manifest{Name: "valid-name", Owner: tt.owner}
			err := Validate(m)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want error wrapping %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_DescriptionLength(t *testing.T) {
	m := &Manifest{Name: "valid-name", Description: strings.Repeat("a", 500)}
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() unexpected error at exactly 500 chars: %v", err)
	}

	m.Description = strings.Repeat("a", 501)
	if err := Validate(m); !errors.Is(err, ErrDescriptionTooLong) {
		t.Fatalf("Validate() error = %v, want ErrDescriptionTooLong", err)
	}
}

func TestValidate_DescriptionLength_MultibyteRunes(t *testing.T) {
	// 500 multi-byte runes should be fine (rune count, not byte count).
	m := &Manifest{Name: "valid-name", Description: strings.Repeat("あ", 500)}
	if err := Validate(m); err != nil {
		t.Fatalf("Validate() unexpected error for 500 multibyte runes: %v", err)
	}
	m.Description = strings.Repeat("あ", 501)
	if err := Validate(m); !errors.Is(err, ErrDescriptionTooLong) {
		t.Fatalf("Validate() error = %v, want ErrDescriptionTooLong", err)
	}
}

func TestValidate_Env(t *testing.T) {
	tests := []struct {
		name    string
		env     []string
		wantErr error
	}{
		{name: "valid", env: []string{"GITHUB_TOKEN", "REPORT_CHANNEL", "_leading_underscore"}},
		{name: "empty list", env: nil},
		{name: "invalid: hyphen", env: []string{"BAD-KEY"}, wantErr: ErrInvalidEnv},
		{name: "invalid: starts with digit", env: []string{"1KEY"}, wantErr: ErrInvalidEnv},
		{name: "invalid: empty string", env: []string{""}, wantErr: ErrInvalidEnv},
		{name: "duplicate", env: []string{"KEY", "KEY"}, wantErr: ErrInvalidEnv},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manifest{Name: "valid-name", Env: tt.env}
			err := Validate(m)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want error wrapping %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_NilManifest(t *testing.T) {
	if err := Validate(nil); err == nil {
		t.Fatal("Validate(nil) = nil error, want error")
	}
}

func TestValidateHandle(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{name: "valid", value: "alice"},
		{name: "invalid format", value: "Alice", wantErr: ErrInvalidName},
		{name: "reserved", value: "api", wantErr: ErrReservedName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHandle(tt.value)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateHandle(%q) unexpected error: %v", tt.value, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateHandle(%q) error = %v, want error wrapping %v", tt.value, err, tt.wantErr)
			}
		})
	}
}
