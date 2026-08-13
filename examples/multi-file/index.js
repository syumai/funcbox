// Relative imports are resolved against the bundle's virtual filesystem.
// Two rules apply here that are stricter than a bundler-based setup:
//
//   1. Only "./" / "../" relative specifiers are resolved this way --
//      bare specifiers (e.g. "lib/greet") are rejected unless
//      compat.nodejs is enabled (see examples/nodejs-compat).
//   2. The file extension is REQUIRED. "./lib/greet" fails; it must be
//      "./lib/greet.js". This lets the module loader distinguish a
//      genuine relative import from a bundle-root-relative bare
//      specifier without guessing.
import { greet } from "./lib/greet.js";
import { shout } from "./lib/format/shout.js";

export default {
	async fetch(request) {
		const url = new URL(request.url);
		const name = url.searchParams.get("name") ?? "world";
		return new Response(shout(greet(name)) + "\n");
	},
};
