import { greeting } from "./lib/x.js";

export default {
	async fetch(request) {
		const url = new URL(request.url);
		// X-Funcbox-* is reserved response-header namespace (tmp/07-http-api.md
		// §7.2: guest code may not set/override it), so this fixture proves
		// "response headers pass through unmodified" with a header outside
		// that namespace instead.
		return new Response(greeting() + " path=" + url.pathname, {
			status: 200,
			headers: { "X-Test-Marker": "hello" },
		});
	},
};
