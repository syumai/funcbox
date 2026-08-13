package runtime

// FetchPolicy is the minimal decision interface hooks.go needs to build
// spidermonkey's Resolve/Dial hooks. It intentionally does NOT import
// internal/policy (out of scope for this package — see 03-runtime.md 3.4);
// the real policy package is expected to satisfy this interface once it
// exists.
//
// The split mirrors config.go's own Resolve/Dial split: Resolve is called
// with only a hostname, before any port is known, while Dial is called with
// hostname + resolved IP + port. AllowHost is consulted at both points (with
// port 0 meaning "port not yet known" at Resolve time); AllowIP is the
// SSRF/metadata-address backstop applied to every resolved (or literal)
// address regardless of which host pattern matched.
type FetchPolicy interface {
	// AllowHost reports whether host may be used at all. host is either a
	// DNS name the guest is resolving/dialing, or — for a literal-IP dial,
	// where the guest gave no name (see DialHook) — the IP string itself
	// standing in as "host". port is the destination port for a Dial call,
	// or 0 for a Resolve call (the port is not yet known during name
	// resolution); implementations should treat port 0 as "allowed for at
	// least one port" and defer the exact port check to the paired Dial
	// call, which always supplies the real port.
	AllowHost(host string, port int) bool

	// AllowIP reports whether ip — the address a name resolved to, or the
	// literal address of an IP-literal dial — may actually be connected to.
	// This is where a policy rejects loopback / link-local / cloud-metadata
	// ranges (169.254.0.0/16 etc.) regardless of which host pattern the
	// request matched, guarding against DNS rebinding and misconfigured
	// allowlists alike.
	AllowIP(ip string) bool
}

// ResolveHook builds a spidermonkey Config.Resolve hook from policy. A nil
// policy denies all name resolution — the same fail-closed behavior a nil
// Config.Resolve already has, kept explicit here so a caller can pass a nil
// FetchPolicy on purpose (e.g. a function with no fetch permission at all)
// without needing a special-case Config.Resolve of its own.
func ResolveHook(policy FetchPolicy) func(host string) bool {
	return func(host string) bool {
		if policy == nil {
			return false
		}
		return policy.AllowHost(host, 0)
	}
}

// DialHook builds a spidermonkey Config.Dial hook from policy. A nil policy
// denies all outbound connections.
//
// config.go documents Dial's host parameter as "" for a literal-IP dial
// (the guest gave no name, so none was resolved) — in that case there is no
// hostname to match against a host-pattern allowlist, so the literal IP
// itself is used as the host to check (a policy that wants to allow bare-IP
// fetches at all must match on the IP's string form). For a named dial, both
// the resolved host pattern (AllowHost) and the IP-level SSRF guard
// (AllowIP) must pass — defense in depth against a DNS answer or an
// allowlist entry alone opening more than intended.
func DialHook(policy FetchPolicy) func(network, host, ip string, port int) bool {
	return func(network, host, ip string, port int) bool {
		if policy == nil {
			return false
		}
		matchHost := host
		if matchHost == "" {
			matchHost = ip
		}
		if !policy.AllowHost(matchHost, port) {
			return false
		}
		return policy.AllowIP(ip)
	}
}

// Listen and Exec are deliberately not built here: 03-runtime.md 3.4 requires
// funcbox to always deny inbound sockets and subprocess execution, and
// config.go's hooks are fail-closed on nil, so leaving
// spidermonkey.Config.Listen and .Exec unset already enforces that. There is
// no funcbox use case that ever sets them.
