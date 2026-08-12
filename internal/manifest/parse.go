package manifest

import (
	"errors"
	"fmt"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/syumai/funcbox/internal/policy"
)

// manifestFilenames lists the accepted manifest filenames in priority
// order (tmp/04-manifest.md: "上から優先"). All three are parsed with
// the same YAML parser, since JSON is a syntactic subset of YAML.
var manifestFilenames = []string{"funcbox.yaml", "funcbox.yml", "funcbox.json"}

// ErrParse is returned when a manifest file exists but fails to
// decode (bad YAML/JSON syntax, unknown fields, or a field with the
// wrong shape).
var ErrParse = errors.New("manifest: parse error")

// ErrInvalidTimeout is returned for a timeout field that isn't a
// valid Go duration string.
var ErrInvalidTimeout = errors.New("manifest: invalid timeout")

// ErrInvalidFetchPolicy is returned for a malformed
// permissions.fetch.mode or permissions.fetch.allow entry.
var ErrInvalidFetchPolicy = errors.New("manifest: invalid fetch policy")

// ErrInvalidVisibility is returned for a visibility field that isn't
// one of the recognized values.
var ErrInvalidVisibility = errors.New("manifest: invalid visibility")

// rawManifest is the direct YAML/JSON decoding target, mirroring the
// v1 schema in tmp/04-manifest.md field-for-field before any type
// conversion or validation.
type rawManifest struct {
	Name        string         `yaml:"name"`
	Owner       string         `yaml:"owner"`
	Main        string         `yaml:"main"`
	Description string         `yaml:"description"`
	Timeout     string         `yaml:"timeout"`
	Memory      string         `yaml:"memory"`
	Compat      rawCompat      `yaml:"compat"`
	Permissions rawPermissions `yaml:"permissions"`
	Env         []string       `yaml:"env"`
	Visibility  string         `yaml:"visibility"`
}

type rawCompat struct {
	Nodejs bool `yaml:"nodejs"`
}

type rawPermissions struct {
	Fetch rawFetch `yaml:"fetch"`
}

type rawFetch struct {
	Mode  string   `yaml:"mode"`
	Allow []string `yaml:"allow"`
}

// Parse locates a manifest file at the root of an unpacked bundle
// (see internal/bundle.Unpack) and decodes it.
//
// If no manifest file is present, Parse returns a Manifest with all
// fields at their zero value and Source == "" — this is a valid
// state (tmp/04-manifest.md: deploy is still possible, with all
// defaults applied by the caller). Name in particular may be empty
// even when a manifest file IS present, since it may instead be
// supplied as a deploy API parameter; Parse does not require it.
//
// Parse converts every field to its typed form (durations, byte
// sizes, fetch patterns, fetch mode, visibility), so it fails for
// syntactically invalid values in those fields. It does NOT perform
// full semantic validation (name format, reserved names, description
// length, env syntax) — call Validate once the caller has filled in
// any fields (like Name) that come from outside the manifest file.
func Parse(files map[string][]byte) (*Manifest, error) {
	name, data, found := findManifestFile(files)
	if !found {
		return &Manifest{}, nil
	}

	var raw rawManifest
	if err := yaml.UnmarshalWithOptions(data, &raw, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrParse, name, err)
	}

	m, err := buildManifest(&raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	m.Source = name
	return m, nil
}

func findManifestFile(files map[string][]byte) (name string, data []byte, found bool) {
	for _, candidate := range manifestFilenames {
		if data, ok := files[candidate]; ok {
			return candidate, data, true
		}
	}
	return "", nil, false
}

func buildManifest(raw *rawManifest) (*Manifest, error) {
	m := &Manifest{
		Name:        raw.Name,
		Owner:       raw.Owner,
		Main:        raw.Main,
		Description: raw.Description,
		Compat:      Compat{Nodejs: raw.Compat.Nodejs},
		Env:         append([]string(nil), raw.Env...),
	}

	if raw.Timeout != "" {
		d, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidTimeout, raw.Timeout, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("%w: %q: must be positive", ErrInvalidTimeout, raw.Timeout)
		}
		m.Timeout = &d
	}

	if raw.Memory != "" {
		n, err := parseByteSize(raw.Memory)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return nil, fmt.Errorf("%w: %q: must be positive", ErrInvalidMemory, raw.Memory)
		}
		m.Memory = &n
	}

	fetch, err := buildFetchPermission(raw.Permissions.Fetch)
	if err != nil {
		return nil, err
	}
	m.Permissions = Permissions{Fetch: fetch}

	if raw.Visibility != "" {
		v, err := policy.ParseVisibility(raw.Visibility)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidVisibility, raw.Visibility, err)
		}
		m.Visibility = &v
	}

	return m, nil
}

func buildFetchPermission(raw rawFetch) (FetchPermission, error) {
	// permissions.fetch omitted entirely => deny-all
	// (tmp/04-manifest.md: "省略時 fetch は deny-all").
	mode := policy.FetchModeDeny
	if raw.Mode != "" {
		parsed, err := policy.ParseFetchMode(raw.Mode)
		if err != nil {
			return FetchPermission{}, fmt.Errorf("%w: mode %q: %v", ErrInvalidFetchPolicy, raw.Mode, err)
		}
		mode = parsed
	}

	allow := make([]policy.Pattern, 0, len(raw.Allow))
	for _, s := range raw.Allow {
		p, err := policy.ParsePattern(s)
		if err != nil {
			return FetchPermission{}, fmt.Errorf("%w: allow %q: %v", ErrInvalidFetchPolicy, s, err)
		}
		allow = append(allow, p)
	}

	return FetchPermission{Mode: mode, Allow: allow}, nil
}
