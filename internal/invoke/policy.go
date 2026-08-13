// Package invoke implements the function-invocation path
// (/{owner}/{func}[/...], tmp/02-architecture.md "関数呼び出し"): resolve
// owner/function/active-version from the store, load the version's bundle
// from blob storage, obtain its runtime.Manager-owned pool, and serve the
// request through it.
//
// This package is server-only (not shared with the funcbox CLI binary), so
// it is free to depend on internal/store, internal/blob, and
// internal/policy alongside the shared internal/runtime package.
package invoke

import (
	"net"

	"github.com/syumai/funcbox/internal/policy"
)

// fetchPolicyAdapter implements runtime.FetchPolicy on top of
// policy.EffectivePolicy + policy.BlockedIP, matching tmp/03-runtime.md
// 3.4's two-gate split: AllowHost consults the host-pattern policy,
// AllowIP applies the SSRF/metadata-address guard to whatever address is
// actually being dialed.
//
// Loopback/link-local exemption rule (this task's explicit design
// decision, since it isn't in the source docs): BlockedIP's blanket denial
// of loopback/link-local/metadata addresses is skipped for an IP that is
// itself explicitly present, as an IP literal, in the manifest's fetch
// allowlist. This lets a function opt a specific loopback/private target
// back in (e.g. tests fetching an httptest.Server on 127.0.0.1) without a
// global "allow all loopback" escape hatch — the author had to name that
// exact address in permissions.fetch.allow. A wildcard or DNS-name pattern
// never counts, only a literal IP.
type fetchPolicyAdapter struct {
	effective  policy.EffectivePolicy
	literalIPs map[string]bool // canonical net.IP.String() form
}

func newFetchPolicyAdapter(effective policy.EffectivePolicy, manifestAllow []policy.Pattern) *fetchPolicyAdapter {
	literalIPs := make(map[string]bool)
	for _, p := range manifestAllow {
		if ip := patternLiteralIP(p); ip != nil {
			literalIPs[ip.String()] = true
		}
	}
	return &fetchPolicyAdapter{effective: effective, literalIPs: literalIPs}
}

// AllowHost implements runtime.FetchPolicy.
func (a *fetchPolicyAdapter) AllowHost(host string, port int) bool {
	return a.effective.Decision(host, port)
}

// AllowIP implements runtime.FetchPolicy.
func (a *fetchPolicyAdapter) AllowIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		// Fail closed on an address we can't even parse.
		return false
	}
	if a.literalIPs[parsed.String()] {
		return true
	}
	return !policy.BlockedIP(parsed)
}

// patternLiteralIP reports the IP address p names, if p's host text is
// itself a literal IP address rather than a DNS name or wildcard pattern.
func patternLiteralIP(p policy.Pattern) net.IP {
	host := p.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}
