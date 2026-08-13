package cli

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func TestParseFlagsInterspersed(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantOwner      string
		wantDryRun     bool
		wantNote       string
		wantPositional []string
		wantErr        bool
	}{
		{
			name:           "flags before positional (already worked)",
			args:           []string{"--owner", "acme", "dir"},
			wantOwner:      "acme",
			wantPositional: []string{"dir"},
		},
		{
			name:           "flags after positional (the bug)",
			args:           []string{"dir", "--owner", "acme"},
			wantOwner:      "acme",
			wantPositional: []string{"dir"},
		},
		{
			name:           "flags interspersed around positional",
			args:           []string{"--dry-run", "dir", "--owner", "acme"},
			wantOwner:      "acme",
			wantDryRun:     true,
			wantPositional: []string{"dir"},
		},
		{
			name:           "equals-form flag after positional",
			args:           []string{"dir", "--owner=acme"},
			wantOwner:      "acme",
			wantPositional: []string{"dir"},
		},
		{
			name:           "multiple flags on both sides of positional",
			args:           []string{"--dry-run", "dir", "--owner", "acme", "--note", "hi"},
			wantOwner:      "acme",
			wantDryRun:     true,
			wantNote:       "hi",
			wantPositional: []string{"dir"},
		},
		{
			name:           "no positional at all",
			args:           []string{"--owner", "acme"},
			wantOwner:      "acme",
			wantPositional: nil,
		},
		{
			name:           "no flags at all",
			args:           []string{"dir"},
			wantPositional: []string{"dir"},
		},
		{
			name:           "empty args",
			args:           []string{},
			wantPositional: nil,
		},
		{
			name:    "unknown flag errors",
			args:    []string{"dir", "--bogus"},
			wantErr: true,
		},
		{
			name:    "missing value for a flag that needs one errors",
			args:    []string{"dir", "--owner"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			owner := fs.String("owner", "", "")
			note := fs.String("note", "", "")
			dryRun := fs.Bool("dry-run", false, "")

			positional, err := parseFlagsInterspersed(fs, tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFlagsInterspersed: %v", err)
			}
			if *owner != tt.wantOwner {
				t.Errorf("owner = %q, want %q", *owner, tt.wantOwner)
			}
			if *note != tt.wantNote {
				t.Errorf("note = %q, want %q", *note, tt.wantNote)
			}
			if *dryRun != tt.wantDryRun {
				t.Errorf("dry-run = %v, want %v", *dryRun, tt.wantDryRun)
			}
			if !reflect.DeepEqual(positional, tt.wantPositional) {
				t.Errorf("positional = %v, want %v", positional, tt.wantPositional)
			}
		})
	}
}

// TestParseFlagsInterspersedMultiplePositionals covers a FlagSet whose
// caller cares about more than one positional argument (funcbox's own
// subcommands only ever have one, but the helper itself is general).
func TestParseFlagsInterspersedMultiplePositionals(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	verbose := fs.Bool("verbose", false, "")

	positional, err := parseFlagsInterspersed(fs, []string{"one", "--verbose", "two", "three"})
	if err != nil {
		t.Fatalf("parseFlagsInterspersed: %v", err)
	}
	if !*verbose {
		t.Error("verbose flag was not parsed")
	}
	want := []string{"one", "two", "three"}
	if !reflect.DeepEqual(positional, want) {
		t.Errorf("positional = %v, want %v", positional, want)
	}
}
