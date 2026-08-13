package cli

import (
	"path"
	"strings"
)

// §7.5: "gitignore 構文") against candidate paths during bundle collection.
//
// Supported subset of gitignore syntax:
//   - blank lines and lines starting with "#" are ignored
//   - "!pattern" re-includes a path a previous pattern excluded
//   - a trailing "/" makes the pattern match directories only
//   - a leading "/" anchors the pattern to the collection root; without
//     one, the pattern matches at any depth (e.g. "*.log" matches
//     "a.log" and "sub/dir/a.log" alike)
//   - "*" matches any run of characters within one path segment; "?" and
//     "[...]" character classes are also supported (see path.Match)
//   - "**" matches zero or more whole path segments, so it can appear
//     anywhere in a multi-segment pattern (e.g. "src/**/*.gen.js")
//
// Known limitations (documented rather than fixed, per the "reasonable
// subset" scope of this matcher):
//   - no backslash-escaping of a leading "#" or "!" — such a line is
//     always treated as a comment/negation, never a literal pattern
//   - no "{a,b}" brace-expansion (not part of core gitignore either)
//   - negating a path whose ancestor directory is itself excluded does
//     not "resurrect" it the way real git does (git only re-includes
//     children of a non-excluded, individually-negated directory); this
//     matcher applies the last-matching-rule-wins strictly per path,
//     without that ancestor-exclusion special case
//   - a rule's match state is decided independently for every candidate
//     path; there is no notion of a rule "not applying" because a
//     shallower directory was already pruned — collect.go handles
//     directory pruning itself using the same Matcher on directory paths
type Matcher struct {
	rules []ignoreRule
}

type ignoreRule struct {
	negate   bool
	dirOnly  bool
	anchored bool
	segments []string // pattern split on "/", with ** kept as a literal segment
}

// NewMatcher parses the contents of a .funcboxignore file. A nil/empty data
// produces a Matcher with no rules (Match always returns false).
func NewMatcher(data []byte) *Matcher {
	m := &Matcher{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if rule, ok := parseIgnoreLine(trimmed); ok {
			m.rules = append(m.rules, rule)
		}
	}
	return m
}

func parseIgnoreLine(pattern string) (ignoreRule, bool) {
	var rule ignoreRule
	if strings.HasPrefix(pattern, "!") {
		rule.negate = true
		pattern = pattern[1:]
	}
	if pattern == "" {
		return ignoreRule{}, false
	}
	if strings.HasPrefix(pattern, "/") {
		rule.anchored = true
		pattern = pattern[1:]
	}
	if strings.HasSuffix(pattern, "/") {
		rule.dirOnly = true
		pattern = strings.TrimSuffix(pattern, "/")
	}
	if pattern == "" {
		return ignoreRule{}, false
	}
	// A pattern containing an internal "/" is anchored to the root even
	// without a leading "/" (gitignore rule: "a separator at the
	// beginning or middle" anchors it).
	segments := strings.Split(pattern, "/")
	if len(segments) > 1 {
		rule.anchored = true
	}
	rule.segments = segments
	return rule, true
}

// Match reports whether relPath (a "/"-separated path relative to the
// collection root, no leading "/") is excluded by m's rules. isDir must be
// true when relPath names a directory, so dirOnly rules only apply where
// they should. Rules are evaluated in file order; the last rule that
// matches wins (gitignore semantics), so a later "!pattern" can re-include
// a path an earlier pattern excluded.
func (m *Matcher) Match(relPath string, isDir bool) bool {
	if m == nil || relPath == "" {
		return false
	}
	segments := strings.Split(relPath, "/")
	ignored := false
	for _, rule := range m.rules {
		if rule.dirOnly && !isDir {
			continue
		}
		if ruleMatches(rule, segments) {
			ignored = !rule.negate
		}
	}
	return ignored
}

// ruleMatches reports whether rule matches pathSegments, per the anchoring
// rule described in Matcher's doc comment: an anchored pattern must match
// starting at segment 0; an unanchored (single-segment, no "/") pattern may
// match starting at any offset.
func ruleMatches(rule ignoreRule, pathSegments []string) bool {
	if rule.anchored {
		return segmentsMatch(rule.segments, pathSegments)
	}
	for start := 0; start <= len(pathSegments); start++ {
		if segmentsMatch(rule.segments, pathSegments[start:]) {
			return true
		}
	}
	return false
}

// segmentsMatch reports whether pattern segments (which may contain a "**"
// wildcard-any-depth segment) match path segments exactly, start to end.
func segmentsMatch(pattern, pathSegs []string) bool {
	if len(pattern) == 0 {
		return len(pathSegs) == 0
	}
	if pattern[0] == "**" {
		if segmentsMatch(pattern[1:], pathSegs) {
			return true
		}
		if len(pathSegs) > 0 && segmentsMatch(pattern, pathSegs[1:]) {
			return true
		}
		return false
	}
	if len(pathSegs) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], pathSegs[0])
	if err != nil || !ok {
		return false
	}
	return segmentsMatch(pattern[1:], pathSegs[1:])
}
