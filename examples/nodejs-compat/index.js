// "camelcase" is a bare specifier (no "./" / "../" prefix): resolving it
// requires compat.nodejs: true in funcbox.yaml, which installs
// go-spidermonkey's compat/nodejs module loader (node_modules resolution
// with exports-map support, plus CommonJS interop). Without that flag
// this import fails with an actionable "did you mean to enable
// compat.nodejs" error at deploy time.
//
// IMPORTANT: node_modules must exist in this directory (run `pnpm install`
// or `npm install` first) and is only included in the deploy bundle when
// compat.nodejs is true -- otherwise it's excluded like any other
// dependency directory. See this example's README for the full 5 MiB
// unpacked-bundle-size implication.
import camelCase from "camelcase";

export default {
	async fetch(request) {
		const url = new URL(request.url);
		const input = url.searchParams.get("text") ?? "hello nodejs compat";
		return new Response(`${input} -> ${camelCase(input)}\n`);
	},
};
