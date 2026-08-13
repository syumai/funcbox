package manifest

import "github.com/syumai/funcbox/policy"

// Normalized is the JSON-serializable, storage-ready form of a
// Manifest. This is what gets persisted as the manifest snapshot for
// optional fields simply serialize to zero values / omitted keys
// rather than distinguishing "unset" via pointers, since by the time
// a version is stored, name resolution (and any other
// caller-supplied defaults) has already happened.
type Normalized struct {
	Source      string                `json:"source,omitempty"`
	Name        string                `json:"name"`
	Owner       string                `json:"owner,omitempty"`
	Main        string                `json:"main,omitempty"`
	Description string                `json:"description,omitempty"`
	Timeout     string                `json:"timeout,omitempty"` // Go duration string, e.g. "10s"
	Memory      int64                 `json:"memory,omitempty"`  // bytes
	Compat      NormalizedCompat      `json:"compat"`
	Permissions NormalizedPermissions `json:"permissions"`
	Env         []string              `json:"env,omitempty"`
	Visibility  string                `json:"visibility,omitempty"`
}

// NormalizedCompat is the normalized form of Compat.
type NormalizedCompat struct {
	Nodejs bool `json:"nodejs"`
}

// NormalizedPermissions is the normalized form of Permissions.
type NormalizedPermissions struct {
	Fetch NormalizedFetch `json:"fetch"`
}

// NormalizedFetch is the normalized form of FetchPermission.
type NormalizedFetch struct {
	Mode  string   `json:"mode"`
	Allow []string `json:"allow,omitempty"`
}

// Normalized converts m into its JSON-serializable storage form.
func (m *Manifest) Normalized() *Normalized {
	n := &Normalized{
		Source:      m.Source,
		Name:        m.Name,
		Owner:       m.Owner,
		Main:        m.Main,
		Description: m.Description,
		Compat:      NormalizedCompat{Nodejs: m.Compat.Nodejs},
		Env:         append([]string(nil), m.Env...),
		Permissions: NormalizedPermissions{
			Fetch: NormalizedFetch{
				Mode:  m.Permissions.Fetch.Mode.String(),
				Allow: patternStrings(m.Permissions.Fetch.Allow),
			},
		},
	}
	if m.Timeout != nil {
		n.Timeout = m.Timeout.String()
	}
	if m.Memory != nil {
		n.Memory = *m.Memory
	}
	if m.Visibility != nil {
		n.Visibility = m.Visibility.String()
	}
	return n
}

func patternStrings(patterns []policy.Pattern) []string {
	if len(patterns) == 0 {
		return nil
	}
	out := make([]string, len(patterns))
	for i, p := range patterns {
		out[i] = p.String()
	}
	return out
}
