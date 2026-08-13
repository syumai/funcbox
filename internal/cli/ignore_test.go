package cli

import "testing"

func TestMatcherIgnored(t *testing.T) {
	tests := []struct {
		name    string
		ignore  string
		path    string
		isDir   bool
		ignored bool
	}{
		{
			name:    "plain filename matches at any depth",
			ignore:  "*.log\n",
			path:    "a.log",
			ignored: true,
		},
		{
			name:    "plain filename matches nested",
			ignore:  "*.log\n",
			path:    "sub/dir/a.log",
			ignored: true,
		},
		{
			name:    "plain filename does not match unrelated file",
			ignore:  "*.log\n",
			path:    "a.txt",
			ignored: false,
		},
		{
			name:    "anchored pattern only matches at root",
			ignore:  "/build\n",
			path:    "build",
			isDir:   true,
			ignored: true,
		},
		{
			name:    "anchored pattern does not match nested",
			ignore:  "/build\n",
			path:    "sub/build",
			isDir:   true,
			ignored: false,
		},
		{
			name:    "internal slash anchors implicitly",
			ignore:  "src/gen\n",
			path:    "sub/src/gen",
			isDir:   true,
			ignored: false,
		},
		{
			name:    "internal slash anchors implicitly (matches at root)",
			ignore:  "src/gen\n",
			path:    "src/gen",
			isDir:   true,
			ignored: true,
		},
		{
			name:    "dir-only pattern does not match a file of the same name",
			ignore:  "dist/\n",
			path:    "dist",
			isDir:   false,
			ignored: false,
		},
		{
			name:    "dir-only pattern matches the directory",
			ignore:  "dist/\n",
			path:    "dist",
			isDir:   true,
			ignored: true,
		},
		{
			name:    "negation re-includes a specific file",
			ignore:  "*.log\n!keep.log\n",
			path:    "keep.log",
			ignored: false,
		},
		{
			name:    "negation does not affect other matches",
			ignore:  "*.log\n!keep.log\n",
			path:    "drop.log",
			ignored: true,
		},
		{
			name:    "later rule wins over earlier rule",
			ignore:  "!a.txt\na.txt\n",
			path:    "a.txt",
			ignored: true,
		},
		{
			name:    "double-star matches across any depth",
			ignore:  "src/**/*.gen.js\n",
			path:    "src/a/b/c.gen.js",
			ignored: true,
		},
		{
			name:    "double-star matches zero segments",
			ignore:  "src/**/*.gen.js\n",
			path:    "src/c.gen.js",
			ignored: true,
		},
		{
			name:    "blank lines and comments are skipped",
			ignore:  "\n# comment\n*.tmp\n",
			path:    "a.tmp",
			ignored: true,
		},
		{
			name:    "comment line itself is not a pattern",
			ignore:  "# *.tmp\n",
			path:    "a.tmp",
			ignored: false,
		},
		{
			name:    "character class pattern",
			ignore:  "file[0-9].txt\n",
			path:    "file5.txt",
			ignored: true,
		},
		{
			name:    "no rules never ignores",
			ignore:  "",
			path:    "anything",
			ignored: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMatcher([]byte(tt.ignore))
			got := m.Match(tt.path, tt.isDir)
			if got != tt.ignored {
				t.Errorf("Match(%q, isDir=%v) = %v, want %v", tt.path, tt.isDir, got, tt.ignored)
			}
		})
	}
}

func TestMatcherNilAndEmptyPath(t *testing.T) {
	var m *Matcher
	if m.Match("anything", false) {
		t.Error("nil Matcher should never report a match")
	}
	m = NewMatcher([]byte("*\n"))
	if m.Match("", false) {
		t.Error("empty path should never be reported as matched")
	}
}
