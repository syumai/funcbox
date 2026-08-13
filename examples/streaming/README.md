# streaming

Returns a `Response` wrapping a `ReadableStream`, and funcbox delivers it
to the client chunk-by-chunk as the stream produces data rather than
buffering the whole body first.

`index.js` enqueues three chunks 200ms apart. Time-to-first-byte should be
close to 0ms (the first chunk is enqueued immediately); total response
time should be roughly 400ms (two 200ms waits between the three chunks).

## Run it locally

```sh
go run ./cmd/funcbox dev examples/streaming
curl -N http://127.0.0.1:8787/dev/streaming
```

`-N` disables curl's output buffering, so `chunk 1`, `chunk 2`, `chunk 3`
print roughly 200ms apart instead of all at once when the response
finishes. Without `-N` curl still receives the bytes incrementally over
the wire (verified with a Go client that measures time-to-first-byte vs.
total time) — it just buffers its own stdout output by default.

## Deploy it

```sh
funcbox deploy --owner <your-user-id> examples/streaming
```

Notes: server-side WebSocket upgrades are not supported by the underlying
runtime, but streaming responses like this one are — see the top-level
README's "What funcbox is" section.
