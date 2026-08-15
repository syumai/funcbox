// The handler shape is `export default { fetch(request) }`, the same
// contract used by Deno's `Deno.serve` and Bun's `Bun.serve` default
// export. funcbox invokes it directly via its own runtime
// (runtime/enginepool) -- there is no extra framework layer in between,
// and no env/ctx arguments: environment variables come from
// import.meta.env instead (see examples/fetch-allowlist).
export default {
	async fetch(request) {
		const url = new URL(request.url);
		return new Response(`Hello from funcbox! You requested ${url.pathname}\n`, {
			status: 200,
			headers: { "Content-Type": "text/plain; charset=utf-8" },
		});
	},
};
