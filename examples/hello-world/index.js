// The handler shape is `export default { fetch(request, env, ctx) }`,
// the same contract used by Deno's `Deno.serve` and Bun's `Bun.serve`
// default export, and by Cloudflare Workers. funcbox invokes it directly
// via go-spidermonkey's compat/cfworkers -- there is no extra framework
// layer in between.
export default {
	async fetch(request) {
		const url = new URL(request.url);
		return new Response(`Hello from funcbox! You requested ${url.pathname}\n`, {
			status: 200,
			headers: { "Content-Type": "text/plain; charset=utf-8" },
		});
	},
};
