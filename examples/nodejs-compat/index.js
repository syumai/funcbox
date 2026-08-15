// "camelcase" is a bare specifier (no "./" / "../" prefix): resolving it
// requires compat.nodejs: true in funcbox.yaml, which installs
// go-spidermonkey's compat/nodejs module loader (node_modules resolution
// with exports-map support, plus CommonJS interop). Without that flag
// this import fails with an actionable "enable compat.nodejs" error at
// deploy time.
//
// "node:crypto" is a node: core module -- compat.nodejs installs the full
// Node runtime (not just module resolution), so core modules are usable
// directly, with no extra flag beyond compat.nodejs itself.
//
// IMPORTANT: node_modules must exist in this directory (run `pnpm install`
// or `npm install` first) and is only included in the deploy bundle when
// compat.nodejs is true -- otherwise it's excluded like any other
// dependency directory. See this example's README for the full 5 MiB
// unpacked-bundle-size implication.
import camelCase from "camelcase";
import { createHash } from "node:crypto";

export default {
	async fetch(request) {
		const url = new URL(request.url);
		const input = url.searchParams.get("text") ?? "hello nodejs compat";
		const hash = createHash("sha256").update(input).digest("hex").slice(0, 12);
		return new Response(`${input} -> ${camelCase(input)} (sha256: ${hash}...)\n`);
	},
};
