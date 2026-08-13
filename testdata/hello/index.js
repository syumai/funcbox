import { greeting } from "./lib/x.js";

export default {
	async fetch(request) {
		const url = new URL(request.url);
		return new Response(greeting() + " path=" + url.pathname, {
			status: 200,
			headers: { "X-Funcbox-Test": "hello" },
		});
	},
};
