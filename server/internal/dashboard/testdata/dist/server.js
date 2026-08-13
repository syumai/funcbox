// server.js is a hand-written test fixture, NOT an esbuild output -- it
// exists so internal/dashboard's hosting-path tests (asset serving,
// session-check redirect, the deadline-ctx invariant, the INTERNAL_API
// identity plumbing) don't need pnpm/esbuild to run `go test`. It
// deliberately mimics the real dist/server.js's shape (a cfworkers worker
// module: `export default { fetch(request, env, ctx) }`) without any of
// hono/jsx's actual rendering.
export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);

		if (url.pathname === "/dashboard/whoami") {
			const token = request.headers.get("X-Funcbox-Caller-Token") || "";
			try {
				const raw = await env.INTERNAL_API("GET", "/me", "", token);
				return new Response(raw, { headers: { "content-type": "application/json" } });
			} catch (e) {
				return new Response("internal_api_error:" + String((e && e.message) || e), { status: 502 });
			}
		}

		if (url.pathname === "/dashboard/forge") {
			// Attempts to call INTERNAL_API with a fabricated token instead of
			// the one the Go host actually injected -- proving a compromised
			// guest can't just make up an identity even though it CAN see the
			// binding and knows the call shape.
			try {
				await env.INTERNAL_API("GET", "/me", "", "forged." + "0".repeat(64));
				return new Response("forged call should not have succeeded", { status: 500 });
			} catch (e) {
				return new Response("rejected:" + String((e && e.message) || e), { status: 403 });
			}
		}

		return new Response("dashboard test fixture: " + url.pathname, { status: 200 });
	},
};
