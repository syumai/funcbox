// funcbox delivers a ReadableStream Response to the client chunk-by-chunk
// as the stream produces data, rather than buffering the whole body first
// (see internal/runtime/streaming_test.go). This handler emits three
// chunks, 200ms apart, so the effect is observable with:
//
//   curl -N http://127.0.0.1:8787/dev/streaming
//
// (-N disables curl's output buffering so chunks are printed as they
// arrive instead of all at once at the end.)
export default {
	async fetch() {
		const encoder = new TextEncoder();
		const stream = new ReadableStream({
			async start(controller) {
				for (let i = 1; i <= 3; i++) {
					controller.enqueue(encoder.encode(`chunk ${i}\n`));
					await new Promise((resolve) => setTimeout(resolve, 200));
				}
				controller.close();
			},
		});
		return new Response(stream, {
			status: 200,
			headers: { "Content-Type": "text/plain; charset=utf-8" },
		});
	},
};
