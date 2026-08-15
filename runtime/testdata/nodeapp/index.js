import { greet } from "tinypkg";
export default {
	async fetch(req) {
		return new Response(greet("world"));
	},
};
