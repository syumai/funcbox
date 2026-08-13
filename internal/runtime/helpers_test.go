package runtime

import spidermonkey "github.com/goccy/go-spidermonkey"

// buildFetchConfig is shared test scaffolding: a spidermonkey.Config with
// Resolve/Dial wired from policy via this package's own hooks.go, exactly
// as a real Manager.HandlerFor's spec.Build would do.
func buildFetchConfig(policy FetchPolicy) spidermonkey.Config {
	return spidermonkey.Config{
		Resolve: ResolveHook(policy),
		Dial:    DialHook(policy),
	}
}
