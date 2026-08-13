package manifest

import (
	"errors"
	"testing"
	"time"

	"github.com/syumai/funcbox/policy"
)

const fullExampleYAML = `
name: hello-world
owner: data
main: src/index.js
description: A sample function

timeout: 10s
memory: 128MiB

compat:
  nodejs: true

permissions:
  fetch:
    mode: allowlist
    allow:
      - api.github.com
      - "*.internal.example.com"

env:
  - GITHUB_TOKEN
  - REPORT_CHANNEL

visibility: org
`

func TestParse_NoManifestFile(t *testing.T) {
	m, err := Parse(map[string][]byte{
		"index.js": []byte("export default {}"),
	})
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if m.Source != "" {
		t.Fatalf("Source = %q, want empty", m.Source)
	}
	if m.Name != "" || m.Owner != "" || m.Main != "" {
		t.Fatalf("expected all-zero manifest, got %+v", m)
	}
	if m.Permissions.Fetch.Mode != policy.FetchModeDeny {
		t.Fatalf("default fetch mode = %v, want deny", m.Permissions.Fetch.Mode)
	}
}

func TestParse_FullExample(t *testing.T) {
	files := map[string][]byte{
		"funcbox.yaml": []byte(fullExampleYAML),
		"src/index.js": []byte("export default {}"),
	}
	m, err := Parse(files)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}

	if m.Source != "funcbox.yaml" {
		t.Errorf("Source = %q, want funcbox.yaml", m.Source)
	}
	if m.Name != "hello-world" {
		t.Errorf("Name = %q, want hello-world", m.Name)
	}
	if m.Owner != "data" {
		t.Errorf("Owner = %q, want data", m.Owner)
	}
	if m.Main != "src/index.js" {
		t.Errorf("Main = %q, want src/index.js", m.Main)
	}
	if m.Description != "A sample function" {
		t.Errorf("Description = %q", m.Description)
	}
	if m.Timeout == nil || *m.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", m.Timeout)
	}
	if m.Memory == nil || *m.Memory != 128<<20 {
		t.Errorf("Memory = %v, want 128MiB", m.Memory)
	}
	if !m.Compat.Nodejs {
		t.Errorf("Compat.Nodejs = false, want true")
	}
	if m.Permissions.Fetch.Mode != policy.FetchModeAllowlist {
		t.Errorf("Fetch.Mode = %v, want allowlist", m.Permissions.Fetch.Mode)
	}
	if len(m.Permissions.Fetch.Allow) != 2 {
		t.Fatalf("Fetch.Allow = %v, want 2 entries", m.Permissions.Fetch.Allow)
	}
	if !m.Permissions.Fetch.Allow[0].Matches("api.github.com", 443) {
		t.Errorf("Fetch.Allow[0] does not match api.github.com:443")
	}
	if !m.Permissions.Fetch.Allow[1].Matches("svc.internal.example.com", 443) {
		t.Errorf("Fetch.Allow[1] does not match svc.internal.example.com:443")
	}
	wantEnv := []string{"GITHUB_TOKEN", "REPORT_CHANNEL"}
	if len(m.Env) != len(wantEnv) || m.Env[0] != wantEnv[0] || m.Env[1] != wantEnv[1] {
		t.Errorf("Env = %v, want %v", m.Env, wantEnv)
	}
	if m.Visibility == nil || *m.Visibility != policy.VisibilityOrg {
		t.Errorf("Visibility = %v, want org", m.Visibility)
	}
}

func TestParse_JSONVariant(t *testing.T) {
	files := map[string][]byte{
		"funcbox.json": []byte(`{"name": "hello-json", "main": "index.js"}`),
	}
	m, err := Parse(files)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if m.Source != "funcbox.json" {
		t.Errorf("Source = %q, want funcbox.json", m.Source)
	}
	if m.Name != "hello-json" {
		t.Errorf("Name = %q, want hello-json", m.Name)
	}
}

func TestParse_FilePriority(t *testing.T) {
	files := map[string][]byte{
		"funcbox.yaml": []byte(`name: from-yaml`),
		"funcbox.yml":  []byte(`name: from-yml`),
		"funcbox.json": []byte(`{"name": "from-json"}`),
	}
	m, err := Parse(files)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if m.Name != "from-yaml" || m.Source != "funcbox.yaml" {
		t.Fatalf("got name=%q source=%q, want from-yaml/funcbox.yaml", m.Name, m.Source)
	}

	delete(files, "funcbox.yaml")
	m, err = Parse(files)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if m.Name != "from-yml" || m.Source != "funcbox.yml" {
		t.Fatalf("got name=%q source=%q, want from-yml/funcbox.yml", m.Name, m.Source)
	}

	delete(files, "funcbox.yml")
	m, err = Parse(files)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if m.Name != "from-json" || m.Source != "funcbox.json" {
		t.Fatalf("got name=%q source=%q, want from-json/funcbox.json", m.Name, m.Source)
	}
}

func TestParse_Errors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr error
	}{
		{name: "unknown field", yaml: "name: ok\nbogusField: 1\n", wantErr: ErrParse},
		{name: "invalid timeout", yaml: "name: ok\ntimeout: not-a-duration\n", wantErr: ErrInvalidTimeout},
		{name: "zero timeout", yaml: "name: ok\ntimeout: 0s\n", wantErr: ErrInvalidTimeout},
		{name: "invalid memory", yaml: "name: ok\nmemory: not-a-size\n", wantErr: ErrInvalidMemory},
		{name: "invalid fetch mode", yaml: "name: ok\npermissions:\n  fetch:\n    mode: bogus\n", wantErr: ErrInvalidFetchPolicy},
		{name: "invalid fetch pattern", yaml: "name: ok\npermissions:\n  fetch:\n    mode: allowlist\n    allow:\n      - \"not a host\"\n", wantErr: ErrInvalidFetchPolicy},
		{name: "invalid visibility", yaml: "name: ok\nvisibility: everyone\n", wantErr: ErrInvalidVisibility},
		{name: "malformed yaml", yaml: "name: [unterminated\n", wantErr: ErrParse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(map[string][]byte{"funcbox.yaml": []byte(tt.yaml)})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Parse() error = %v, want error wrapping %v", err, tt.wantErr)
			}
		})
	}
}

func TestParse_FetchModeDefaultsToDenyWhenOmitted(t *testing.T) {
	m, err := Parse(map[string][]byte{"funcbox.yaml": []byte("name: ok\n")})
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if m.Permissions.Fetch.Mode != policy.FetchModeDeny {
		t.Fatalf("Fetch.Mode = %v, want deny", m.Permissions.Fetch.Mode)
	}
}
