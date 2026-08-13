// Effective fetch permission is the INTERSECTION of three levels
// (tmp/05-auth-and-permissions.md §5.6):
//
//   organization policy  ∩  workspace policy  ∩  this manifest
//
// Each level can only narrow what's below it -- an org can't be
// overridden into allowing more than it permits, no matter what a
// workspace or manifest declares. `funcbox dev` only enforces the
// manifest level (there's no org/workspace to intersect with locally),
// which is why the CLI prints a reminder that production may be
// stricter.
//
// This handler calls the host declared in the API_HOST env var (see
// funcbox.yaml's `env:` list) and only succeeds if that host also
// appears in permissions.fetch.allow.
export default {
	async fetch(request, env) {
		const host = env.API_HOST;
		if (!host) {
			return new Response("API_HOST is not set (funcbox dev --env API_HOST=api.github.com, or register it in the dashboard)\n", { status: 500 });
		}

		try {
			const upstream = await fetch(`https://${host}/zen`);
			const text = await upstream.text();
			return new Response(`fetch to ${host} succeeded: ${text}\n`);
		} catch (err) {
			// A denied host fails the fetch() call itself with a guest-visible
			// error -- it never reaches the network.
			return new Response(`fetch to ${host} was denied: ${String(err && err.message || err)}\n`, { status: 502 });
		}
	},
};
