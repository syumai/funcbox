# fetch-allowlist

Demonstrates `permissions.fetch` with `mode: allowlist`, plus a declared
`env` key.

```yaml
permissions:
  fetch:
    mode: allowlist
    allow:
      - api.github.com
env:
  - API_HOST
```

`index.js` reads the target host from the `API_HOST` env var (declared,
not hardcoded, so it can be set per-deployment without editing the
manifest) and fetches `https://<API_HOST>/zen`.

## The 3-level intersection

The effective fetch policy is the **intersection** of three levels
(organization ∩ workspace ∩ this manifest — see the top-level README's
"Permissions model" section): each level can only narrow what's below it.
`funcbox dev` only has the manifest level to apply (there's no
organization/workspace locally), which is why it prints a reminder that a
real deployment may narrow this further.

## Known issue found while writing this example (not fixed here)

While verifying this example against the current build, a name-based
(DNS hostname) `fetch()` under `mode: allowlist` was **always denied**,
regardless of whether the host was on the `allow` list:

```
fetch to api.github.com was denied: resolve "api.github.com": permission denied
```

Root cause (traced, not fixed — out of scope for this docs/CI change):
`internal/runtime/hooks.go`'s `ResolveHook` calls `FetchPolicy.AllowHost(host, 0)`
before DNS resolution happens, and its own doc comment says implementations
should treat port `0` as "allowed for at least one port" and defer the
exact check to the paired `Dial` call. `internal/policy.Pattern.portMatches`
(`internal/policy/pattern.go`) doesn't implement that: it requires an exact
port match (or 80/443 for a pattern with no port suffix), which port `0`
never satisfies — so `Resolve` denies every hostname under `allowlist`
mode before `Dial` ever gets the real port. `mode: allow-all` is
unaffected (it doesn't consult patterns), and IP-literal targets are
unaffected (they skip `Resolve` and go straight to `Dial` with the real
port) — which is also why the existing `TestE2E_FetchPolicy` test in
`e2e_test.go` didn't catch this: it allowlists an `httptest.Server`'s
`127.0.0.1:port`, an IP literal.

This example still ships with the intended, schema-correct manifest
(a hostname pattern), since that's what a real deployment should look
like once this is fixed. Until then, expect the "allowed host" case below
to fail the same way the "disallowed host" case does.

## Run it locally

```sh
go run ./cmd/funcbox dev --env API_HOST=api.github.com examples/fetch-allowlist
curl http://127.0.0.1:8787/dev/fetch-allowlist
```

Flags must precede the directory argument.

## Deploy it

```sh
funcbox deploy --owner <your-user-id> examples/fetch-allowlist
# then register API_HOST for this deployment via the dashboard or the
# management API (funcbox.yaml only declares the KEY, never a value)
```
