// funcbox enginepool glue: the guest half of the request/response plumbing.
// Derived from go-spidermonkey's compat/cfworkers package (MIT License,
// Copyright (c) 2026 Masaaki Goshima) — see ../NOTICE for the full notice and
// a summary of what changed. Evaluated once per worker instance, after
// compat/web's (and, when NodeCompat is enabled, compat/nodejs's) builtins,
// and before the function module boots.
(() => {
	"use strict";
	const state = { result: null };
	// SpiderMonkey stacks do not include the message line; compose name+message
	// so a host error (fetch handler throw) is diagnosable.
	const fmtErr = (err) => (err instanceof Error
		? `${err.name}: ${err.message}${err.stack ? "\n" + err.stack : ""}`
		: String(err));

	// The shared web-layer timer wrapper (runTimerCb) routes a background
	// setTimeout/setInterval callback throw here. Without a handler the throw
	// would rethrow out of the loop, abort RunUntil, and fail an otherwise-valid
	// in-flight fetch response.
	globalThis.__emit_uncaught = (e) => {
		try { console.error("Uncaught (in background task):", (e && e.stack) || e); } catch { /* ignore */ }
		return true;
	};

	// ------------------------------------------------------------- Cache API
	// In-memory caches.default / caches.open(name). Keys are the request URL;
	// values are cloned Responses. Per-instance (a warm instance keeps it).

	const cacheStores = new Map();
	function makeCache() {
		const store = new Map();
		return {
			async match(request) {
				const url = typeof request === "string" ? request : request.url;
				const cached = store.get(url);
				return cached ? cached.clone() : undefined;
			},
			async put(request, response) {
				const url = typeof request === "string" ? request : request.url;
				if (response.status === 206) throw new TypeError("Cannot cache a partial response");
				store.set(url, response.clone());
			},
			async delete(request) {
				const url = typeof request === "string" ? request : request.url;
				return store.delete(url);
			},
		};
	}
	globalThis.caches = {
		default: makeCache(),
		async open(name) {
			if (!cacheStores.has(name)) cacheStores.set(name, makeCache());
			return cacheStores.get(name);
		},
		async has(name) { return cacheStores.has(name); },
		async delete(name) { return cacheStores.delete(name); },
	};

	// ---------------------------------------------------------- WebSocketPair
	// An in-process client/server socket pair (no external upgrade). Messages
	// sent on one end arrive on the other.

	class InProcessWebSocket extends EventTarget {
		constructor() {
			super();
			this.readyState = 0; // CONNECTING
			this._peer = null;
			this.OPEN = 1;
		}
		accept() { this.readyState = 1; }
		send(data) {
			if (this._peer) {
				const ev = new Event("message");
				ev.data = data;
				queueMicrotask(() => this._peer.dispatchEvent(ev));
			}
		}
		close(code, reason) {
			this.readyState = 3;
			if (this._peer && this._peer.readyState !== 3) {
				const ev = new Event("close");
				ev.code = code ?? 1000;
				ev.reason = reason ?? "";
				queueMicrotask(() => this._peer.dispatchEvent(ev));
			}
		}
		addEventListener(type, fn) { super.addEventListener(type, fn); }
	}
	globalThis.WebSocketPair = function WebSocketPair() {
		const a = new InProcessWebSocket();
		const b = new InProcessWebSocket();
		a._peer = b;
		b._peer = a;
		return { 0: a, 1: b };
	};

	// Build the Request the handler sees from host-supplied parts.
	globalThis.__fbw_make_request = (method, url, headerPairs, body) => {
		return new Request(url, {
			method,
			headers: headerPairs,
			body: body === null || body === undefined ? undefined : body,
		});
	};

	// Kick the handler; completion lands in state.result via the microtask
	// queue (drained by the host loop). fetch(request) ONLY — no env/ctx.
	globalThis.__fbw_run = (req) => {
		state.result = null;
		Promise.resolve()
			.then(() => globalThis.__fbw_handler.fetch(req))
			.then((resp) => { state.result = { ok: true, resp }; })
			.catch((err) => { state.result = { ok: false, error: fmtErr(err) }; });
	};

	// A response is streamed (not buffered) when its body only exists as a
	// ReadableStream: a guest `new Response(readable)` (_bodyStream), or a native
	// fetch() Response returned straight through (the reverse-proxy pattern —
	// no `_body` field at all, body is the host-backed stream).
	globalThis.__fbw_response_needs_stream = () => {
		const r = state.result && state.result.resp;
		if (!r || typeof r !== "object") return false;
		if (r._bodyStream) return true;
		return r._body === undefined && !!r.body;
	};

	// Pump the response's stream body to the host: `write(gen, chunkU8)`
	// writes+flushes one chunk to the client, `done(gen)` ends the response,
	// `fail(gen, msg)` aborts it. All three are SHARED per-worker Go functions;
	// gen ties this pump to its own request so a stale pump (client vanished,
	// worker kept the stream alive) can never write into a later response.
	globalThis.__fbw_stream_body = (gen, write, done, fail) => {
		const r = state.result.resp;
		const stream = (r._bodyStream ?? r.body) || null;
		if (!stream) { done(gen); return; }
		let reader;
		try { reader = stream.getReader(); }
		catch (e) { fail(gen, fmtErr(e)); return; }
		const enc = new TextEncoder();
		const pump = () => reader.read().then(({ value, done: eof }) => {
			if (eof) { done(gen); return; }
			// Normalize the chunk guest-side: the host op takes raw bytes.
			let u8;
			if (typeof value === "string") u8 = enc.encode(value);
			else if (value instanceof Uint8Array) u8 = value;
			else if (value instanceof ArrayBuffer) u8 = new Uint8Array(value);
			else if (ArrayBuffer.isView(value)) u8 = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
			else throw new TypeError("response stream chunks must be strings or BufferSource");
			if (u8.length > 0) write(gen, u8);
			return pump();
		}).catch((e) => {
			// A failed client write or an errored stream: release the source and
			// tell the host to abort the response.
			try { reader.cancel(e); } catch { /* already done */ }
			fail(gen, fmtErr(e));
		});
		pump();
	};

	globalThis.__fbw_status = () => (state.result === null ? "pending" : state.result.ok ? "ok" : "error");
	globalThis.__fbw_error = () => String(state.result.error);

	globalThis.__fbw_response_meta = () => {
		const r = state.result.resp;
		if (!r || typeof r !== "object" || typeof r.status !== "number"
			|| !r.headers || typeof r.headers.entries !== "function") {
			throw new TypeError("handler did not return a Response");
		}
		// entries() combines multiple Set-Cookie into one comma-joined value,
		// which corrupts cookies on the wire — emit each Set-Cookie as its own
		// header pair instead.
		const pairs = [];
		for (const [k, v] of r.headers.entries()) {
			if (k === "set-cookie") continue;
			pairs.push([k, v]);
		}
		if (typeof r.headers.getSetCookie === "function") {
			for (const c of r.headers.getSetCookie()) pairs.push(["set-cookie", c]);
		}
		return JSON.stringify({
			status: r.status,
			statusText: String(r.statusText || ""),
			headers: pairs,
		});
	};

	// The buffered body bytes (Uint8Array) or null.
	globalThis.__fbw_response_body = () => {
		const r = state.result.resp;
		return r._body === null || r._body === undefined ? null : r._body;
	};

	// Fetch-only handler validation (requirement 4): the default export must
	// be an object with a fetch(request) function. Any OTHER own key
	// (scheduled, queue, ...) is reported back to Go as a warning, not an
	// error — funcbox does not support them, but a function ported from
	// another runtime should fail loudly only on the thing that actually
	// matters (no fetch), not on unrelated extra exports.
	globalThis.__fbw_validate_handler = () => {
		const h = globalThis.__fbw_handler;
		if (typeof h !== "object" || h === null) {
			throw new TypeError("the module's default export must be an object with a fetch(request) handler");
		}
		if (typeof h.fetch !== "function") {
			throw new TypeError("the module's default export has no fetch(request) handler");
		}
		return JSON.stringify(Object.keys(h).filter((k) => k !== "fetch"));
	};
})();
