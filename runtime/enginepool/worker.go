package enginepool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/web"
)

// worker is one warmed engine instance plus its resolved glue functions.
type worker struct {
	js          *spidermonkey.JS
	web         *web.Web
	makeReq     *spidermonkey.Object
	run         *spidermonkey.Object
	status      *spidermonkey.Object
	errMsg      *spidermonkey.Object
	meta        *spidermonkey.Object
	body        *spidermonkey.Object
	needsStream *spidermonkey.Object // __fbw_response_needs_stream(): body is a ReadableStream
	streamBody  *spidermonkey.Object // __fbw_stream_body(gen, write, done, fail): pump the stream

	// Streaming callbacks are created ONCE per worker: a NewFunction
	// registration lives for the interpreter's lifetime, so per-request
	// functions would permanently leak their closures (and pin every past
	// request's ResponseWriter). The shared callbacks dispatch through sink,
	// which is set for the duration of one streamed response and cleared
	// after; gen invalidates any stale pump from an earlier request so it can
	// never write into a later response.
	hostWrite *spidermonkey.Object
	hostDone  *spidermonkey.Object
	hostFail  *spidermonkey.Object
	sink      *streamSink
	streamGen int64
}

// streamSink is the per-request target of the shared streaming callbacks. The
// pump runs on the instance's event loop while RunUntil drives it from the
// serving goroutine, so no locking is needed.
type streamSink struct {
	rw       http.ResponseWriter
	fl       http.Flusher
	pumpDone bool
	failed   bool
}

func newWorker(cfg Config) (*worker, error) {
	js, err := spidermonkey.New(cfg.Engine)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			js.Close()
		}
	}()

	w, err := web.Install(js)
	if err != nil {
		return nil, err
	}
	wk := &worker{js: js, web: w}
	if cfg.Loader != nil {
		js.SetModuleLoader(wrapLoaderWithEnv(cfg.Loader))
	}

	if err := installEnv(js, cfg.Env); err != nil {
		return nil, fmt.Errorf("installing import.meta.env: %w", err)
	}

	ctx := context.Background()
	if r, err := js.Eval(ctx, glueJS); err != nil {
		return nil, err
	} else if r.Error != nil {
		return nil, fmt.Errorf("glue threw: %w", r.Error)
	}

	entry := cfg.Entry
	if entry == "" {
		entry = "index.js"
	}
	mr, err := js.EvalModule(ctx, "funcbox:boot",
		fmt.Sprintf(`import handler from %q; globalThis.__fbw_handler = handler;`, entry))
	if err != nil {
		return nil, err
	}
	if mr.Error != nil {
		return nil, fmt.Errorf("function module threw: %w", mr.Error)
	}

	if err := wk.validateHandler(ctx, cfg.Warn); err != nil {
		return nil, err
	}

	for name, dst := range map[string]**spidermonkey.Object{
		"__fbw_make_request":          &wk.makeReq,
		"__fbw_run":                   &wk.run,
		"__fbw_status":                &wk.status,
		"__fbw_error":                 &wk.errMsg,
		"__fbw_response_meta":         &wk.meta,
		"__fbw_response_body":         &wk.body,
		"__fbw_response_needs_stream": &wk.needsStream,
		"__fbw_stream_body":           &wk.streamBody,
	} {
		v, gerr := js.Global().Get(name)
		if gerr != nil {
			return nil, gerr
		}
		o := v.Object()
		if o == nil || !o.IsFunction() {
			return nil, fmt.Errorf("glue function %s missing", name)
		}
		*dst = o
	}
	if wk.hostWrite, err = js.NewFunction("__fbw_host_write", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("write: (gen, chunk) required")
		}
		o := args[1].Object()
		if o == nil {
			return nil, fmt.Errorf("write: chunk must be bytes")
		}
		chunk, berr := o.Bytes()
		o.Free()
		if berr != nil {
			return nil, berr
		}
		sink := wk.sink
		if sink == nil || int64(args[0].Float()) != wk.streamGen {
			// A stale pump from a finished request. Erroring it makes the guest
			// cancel its source; it must never reach a later response's writer.
			return nil, fmt.Errorf("response stream finished")
		}
		if _, werr := sink.rw.Write(chunk); werr != nil {
			// The client went away mid-stream. Throwing into the guest pump makes
			// it cancel the source stream and report fail().
			return nil, werr
		}
		if sink.fl != nil {
			sink.fl.Flush()
		}
		return spidermonkey.Undefined(), nil
	}); err != nil {
		return nil, err
	}
	if wk.hostDone, err = js.NewFunction("__fbw_host_done", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
		if s := wk.sink; s != nil && len(args) > 0 && int64(args[0].Float()) == wk.streamGen {
			s.pumpDone = true
		}
		return spidermonkey.Undefined(), nil
	}); err != nil {
		return nil, err
	}
	if wk.hostFail, err = js.NewFunction("__fbw_host_fail", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
		if s := wk.sink; s != nil && len(args) > 0 && int64(args[0].Float()) == wk.streamGen {
			s.pumpDone = true
			s.failed = true
		}
		return spidermonkey.Undefined(), nil
	}); err != nil {
		return nil, err
	}
	ok = true
	return wk, nil
}

// validateHandler runs the glue's __fbw_validate_handler() (requirement 4):
// the default export must be an object with a fetch(request) function (a
// boot error otherwise), and any other own key is reported to warn (a
// scheduled/queue handler ported from elsewhere — funcbox ignores it rather
// than rejecting the whole module over it).
func (wk *worker) validateHandler(ctx context.Context, warn func(string)) error {
	r, err := wk.js.Eval(ctx, `__fbw_validate_handler()`)
	if err != nil {
		return err
	}
	if r.Error != nil {
		return fmt.Errorf("function module's default export is invalid: %w", r.Error)
	}
	var extra []string
	if err := json.Unmarshal([]byte(r.Value.String()), &extra); err != nil {
		return fmt.Errorf("decoding handler validation result: %w", err)
	}
	if warn != nil {
		for _, key := range extra {
			warn(key)
		}
	}
	return nil
}

func (wk *worker) close() error {
	wk.web.Close()
	return wk.js.Close()
}

type responseMeta struct {
	Status     int         `json:"status"`
	StatusText string      `json:"statusText"`
	Headers    [][2]string `json:"headers"`
}

// maxRequestBody caps a buffered request body so a large/slow upload can't
// exhaust memory while holding a pool slot.
const maxRequestBody = 100 << 20 // 100 MiB

func (wk *worker) serve(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	// A panic in the handler path (e.g. an out-of-range WriteHeader) must not
	// return a mid-operation instance to the pool. Recover, best-effort 500,
	// and always clear leftover loop state (timers/pending ops) so one
	// request's un-awaited work can't fire during the next on this instance.
	defer func() {
		if r := recover(); r != nil {
			// net/http uses ErrAbortHandler as a sentinel to abort the response
			// without logging; re-panic it (after clearing loop state) so the
			// server handles it as intended rather than turning it into a 500.
			if r == http.ErrAbortHandler {
				wk.web.ResetPerRequest()
				wk.web.Loop().Reset()
				panic(r)
			}
			func() {
				defer func() { _ = recover() }()
				http.Error(rw, "internal error", http.StatusInternalServerError)
			}()
		}
		wk.web.ResetPerRequest()
		wk.web.Loop().Reset()
	}()
	fail := func(status int, format string, args ...any) {
		http.Error(rw, fmt.Sprintf(format, args...), status)
	}

	reqBody, err := io.ReadAll(http.MaxBytesReader(rw, req.Body, maxRequestBody))
	if err != nil {
		fail(http.StatusRequestEntityTooLarge, "reading request body: %v", err)
		return
	}

	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	fullURL := scheme + "://" + req.Host + req.URL.RequestURI()

	headerPairs := make([][2]string, 0, len(req.Header))
	for k, vs := range req.Header {
		for _, v := range vs {
			headerPairs = append(headerPairs, [2]string{k, v})
		}
	}

	var bodyVal spidermonkey.Value = spidermonkey.Null()
	if len(reqBody) > 0 {
		u8, berr := wk.js.NewBytes(reqBody)
		if berr != nil {
			fail(http.StatusInternalServerError, "building request body: %v", berr)
			return
		}
		defer u8.Free()
		bodyVal = u8
	}

	reqV, err := wk.makeReq.Call(
		spidermonkey.ValueOf(req.Method),
		spidermonkey.ValueOf(fullURL),
		spidermonkey.ValueOf(headerPairs),
		bodyVal,
	)
	if err != nil {
		fail(http.StatusInternalServerError, "building Request: %v", err)
		return
	}
	reqObj := reqV.Object()
	if reqObj == nil {
		fail(http.StatusInternalServerError, "building Request: not an object")
		return
	}
	if _, err := wk.run.Call(reqObj); err != nil {
		reqObj.Free()
		fail(http.StatusInternalServerError, "invoking handler: %v", err)
		return
	}
	reqObj.Free()

	// Drive the loop until the handler's promise settles — NOT until the loop
	// is fully idle. A handler can settle while leaving timers running (a
	// setInterval, an un-fired AbortSignal.timeout); waiting for idle would
	// delay or hang the already-available response and pin the pooled
	// instance. RunUntil returns as soon as status flips, or when the loop
	// goes idle while still pending (the promise awaits something nothing
	// will resolve) — OR when ctx is done (the caller's deadline fires),
	// which is the ONLY mechanism that frees a slot stuck in a runaway
	// handler; see enginepool.Pool.ServeHTTP's doc comment.
	stop := func() bool {
		st, serr := wk.status.Call()
		return serr != nil || st.String() != "pending"
	}
	if werr := wk.web.Loop().RunUntil(ctx, stop); werr != nil {
		fail(http.StatusInternalServerError, "handler failed: %v", werr)
		return
	}
	// Check the real status after the loop returns (it may have returned
	// because the loop went idle, coinciding with the handler settling):
	// pending here means the promise awaits something nothing will resolve.
	if st, _ := wk.status.Call(); st == nil || st.String() == "pending" {
		fail(http.StatusInternalServerError, "handler never settled")
		return
	}

	if st, _ := wk.status.Call(); st != nil && st.String() == "error" {
		msg, _ := wk.errMsg.Call()
		fail(http.StatusInternalServerError, "worker error: %s", msg.String())
		return
	}

	metaV, err := wk.meta.Call()
	if err != nil {
		fail(http.StatusInternalServerError, "reading response: %v", err)
		return
	}
	var meta responseMeta
	if err := json.Unmarshal([]byte(metaV.String()), &meta); err != nil {
		fail(http.StatusInternalServerError, "decoding response meta: %v", err)
		return
	}
	// A ReadableStream body (guest-constructed or a fetch() Response returned
	// straight through) is streamed chunk-by-chunk instead of buffered, so the
	// first byte reaches the client as soon as the function produces it.
	if v, serr := wk.needsStream.Call(); serr == nil && v.Bool() {
		wk.serveStreamingBody(ctx, rw, meta)
		return
	}

	var respBody []byte
	bodyV, err := wk.body.Call()
	if err != nil {
		fail(http.StatusInternalServerError, "reading response body: %v", err)
		return
	}
	if o := bodyV.Object(); o != nil {
		respBody, err = o.Bytes()
		o.Free()
		if err != nil {
			fail(http.StatusInternalServerError, "reading response body: %v", err)
			return
		}
	}

	h := rw.Header()
	for _, kv := range meta.Headers {
		h.Add(kv[0], kv[1])
	}
	// A function can set any status (Response.error() uses 0); an
	// out-of-range code panics net/http's WriteHeader, so clamp it.
	if meta.Status < 100 || meta.Status > 999 {
		meta.Status = http.StatusInternalServerError
	}
	rw.WriteHeader(meta.Status)
	if len(respBody) > 0 {
		rw.Write(respBody)
	}
}

// serveStreamingBody delivers a Response whose body is a ReadableStream:
// status and headers go out first, then every chunk is written and flushed as
// the function's stream produces it (chunked transfer encoding unless the
// function supplied a Content-Length). The pump runs on the instance's event
// loop; the write/done/fail callbacks below execute on this goroutine while
// RunUntil drives the loop, so the local state needs no locking.
func (wk *worker) serveStreamingBody(ctx context.Context, rw http.ResponseWriter, meta responseMeta) {
	h := rw.Header()
	for _, kv := range meta.Headers {
		h.Add(kv[0], kv[1])
	}
	if meta.Status < 100 || meta.Status > 999 {
		meta.Status = http.StatusInternalServerError
	}
	rw.WriteHeader(meta.Status)
	fl, _ := rw.(http.Flusher)

	// Arm the shared callbacks for this request; clear on every exit path
	// (including the abort panic) so the ResponseWriter is never pinned past
	// its request and a stale pump finds no sink.
	wk.streamGen++
	sink := &streamSink{rw: rw, fl: fl}
	wk.sink = sink
	defer func() { wk.sink = nil }()

	if _, cerr := wk.streamBody.Call(spidermonkey.ValueOf(wk.streamGen), wk.hostWrite, wk.hostDone, wk.hostFail); cerr != nil {
		sink.failed = true
	}
	if !sink.failed && !sink.pumpDone {
		wk.web.Loop().RunUntil(ctx, func() bool { return sink.pumpDone })
	}
	if !sink.pumpDone || sink.failed {
		// Status and headers (and possibly some bytes) are already on the wire;
		// the only honest failure signal left is aborting the connection so the
		// client sees truncation instead of a clean end. ErrAbortHandler is
		// re-panicked by serve's recover after the loop state is cleared.
		panic(http.ErrAbortHandler)
	}
}
