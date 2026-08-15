import fs from "node:fs";
export default {
	async fetch(req) {
		return new Response("unreachable: " + typeof fs);
	},
};
