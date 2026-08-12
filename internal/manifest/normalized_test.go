package manifest

import (
	"encoding/json"
	"testing"
)

func TestNormalized_FullExample(t *testing.T) {
	m, err := Parse(map[string][]byte{"funcbox.yaml": []byte(fullExampleYAML)})
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	n := m.Normalized()
	if n.Name != "hello-world" || n.Owner != "data" || n.Main != "src/index.js" {
		t.Fatalf("unexpected normalized identity fields: %+v", n)
	}
	if n.Timeout != "10s" {
		t.Errorf("Timeout = %q, want 10s", n.Timeout)
	}
	if n.Memory != 128<<20 {
		t.Errorf("Memory = %d, want %d", n.Memory, 128<<20)
	}
	if !n.Compat.Nodejs {
		t.Errorf("Compat.Nodejs = false, want true")
	}
	if n.Permissions.Fetch.Mode != "allowlist" {
		t.Errorf("Fetch.Mode = %q, want allowlist", n.Permissions.Fetch.Mode)
	}
	if len(n.Permissions.Fetch.Allow) != 2 {
		t.Fatalf("Fetch.Allow = %v, want 2 entries", n.Permissions.Fetch.Allow)
	}
	if n.Visibility != "org" {
		t.Errorf("Visibility = %q, want org", n.Visibility)
	}

	data, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}

	var round map[string]any
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if round["name"] != "hello-world" {
		t.Fatalf("round-tripped name = %v, want hello-world", round["name"])
	}
}

func TestNormalized_DefaultsOmittedWhenUnset(t *testing.T) {
	m, err := Parse(map[string][]byte{"funcbox.yaml": []byte("name: minimal\n")})
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	n := m.Normalized()
	if n.Timeout != "" {
		t.Errorf("Timeout = %q, want empty", n.Timeout)
	}
	if n.Memory != 0 {
		t.Errorf("Memory = %d, want 0", n.Memory)
	}
	if n.Visibility != "" {
		t.Errorf("Visibility = %q, want empty", n.Visibility)
	}
	if n.Permissions.Fetch.Mode != "deny" {
		t.Errorf("Fetch.Mode = %q, want deny", n.Permissions.Fetch.Mode)
	}

	// Must still be marshalable.
	if _, err := json.Marshal(n); err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
}
