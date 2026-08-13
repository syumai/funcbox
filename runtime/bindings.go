package runtime

import (
	"context"
	"fmt"
	"sync"

	spidermonkey "github.com/goccy/go-spidermonkey"
	"github.com/goccy/go-spidermonkey/compat/cfworkers"
)

// StaticBinding exposes a plain Go value as an env binding (env.NAME reads
// v). It is a thin documented alias for cfworkers.Static: v materializes as
// a FRESH guest value every instance warm-up (anything encoding/json can
// marshal — see spidermonkey.ValueOf), so it carries data, not identity.
func StaticBinding(v any) cfworkers.Binding {
	return cfworkers.Static(v)
}

// FuncBinding exposes a synchronous Go function as a callable env binding:
// the guest calls env.NAME(...args) and gets fn's return value back
// immediately (a plain call, not a Promise). fn runs on the same goroutine
// and blocks the request for as long as fn takes — appropriate for fast,
// CPU-bound or already-blocking Go work (a cache lookup, a local
// computation).
//
// Built directly on JS.NewFunction (function.go): a Binding is called once
// per pooled instance at warm-up, and NewFunction's registration lives for
// the interpreter's lifetime — exactly matching one instance's lifetime, so
// nothing needs explicit cleanup beyond the instance's own Close.
func FuncBinding(name string, fn spidermonkey.Func) cfworkers.Binding {
	return func(js *spidermonkey.JS) (spidermonkey.Value, error) {
		obj, err := js.NewFunction(name, fn)
		if err != nil {
			return nil, fmt.Errorf("binding %q: %w", name, err)
		}
		return obj, nil
	}
}

// AsyncFuncBinding exposes fn as an env binding that returns a Promise:
// env.NAME(...args) returns immediately with a pending Promise, fn runs on
// its own goroutine, and its result resolves (a returned error rejects) the
// promise once fn finishes — the shape a dashboard internal-API binding (09)
// needs for a Go call that itself blocks on I/O (a DB query, another
// service).
//
// How this works, and why it went through two failed designs before landing
// here (found by reading hostenv.go and internal/spidermonkey.go, and then
// corrected twice by actually running it — see bindings_test.go and
// tmp/phase0-findings.md item 6 for the full account):
//
// cfworkers' Binding only ever hands a binding a *spidermonkey.JS, with no
// access to compat/web's event loop (that type lives in the library's
// compat/internal/eventloop, unexported outside the library), so a binding
// cannot drive the loop itself the way compat/web's own async ops do. Two
// more problems only surfaced by testing end to end:
//
//  1. A JS-visible property name built with a NUL prefix (mirroring
//     nextFnKey's "keep host dispatch keys out of guest namespace" trick in
//     function.go) breaks when actually used AS a property name: nextFnKey's
//     keys are Go-side map keys that never cross into JS, but a real
//     `globalThis[name]`/Object.Set(name, ...) property name crossing the
//     host/guest string bridge gets silently truncated at the embedded NUL,
//     so the property never round-trips and the lookup fails as "not a
//     function". Fixed by never naming the Go function at all: it is passed
//     directly as a call argument to a small JS factory closure instead (see
//     function_test.go's "Passable as a callback argument with identity
//     preserved" for the same pattern) — no name, no collision risk.
//  2. Settling the promise by calling resolve/reject DIRECTLY from the
//     background goroutine (a foreign *spidermonkey.Object.Call racing
//     against cfworkers' own `wk.web.Loop().RunUntil(ctx, stop)` on the
//     request-serving goroutine) is flaky: worker.serve reports "handler
//     never settled" often enough to be unusable. RunUntil declares the
//     request idle — and gives up — the moment its OWN bookkeeping (armed
//     timers, in-flight fetches, the microtask queue) looks empty; it has no
//     way to know a foreign goroutine intends to call resolve() imminently,
//     and depending on exactly when that foreign call wins the interpreter's
//     per-instance invoke lock relative to RunUntil's own idle check, the
//     loop can (and, empirically, sometimes does) declare idle first. Fixed
//     by never calling INTO the interpreter from the goroutine at all: the
//     goroutine only writes its result into a mutex-guarded Go-side map, and
//     a real `setInterval` — driven entirely by RunUntil's own normal timer
//     phase, on the SAME goroutine RunUntil itself runs on — polls that map
//     and calls resolve/reject itself once the result is ready. Every call
//     into the interpreter now happens from the loop's own turn, so there is
//     no cross-goroutine race on settlement, and the armed setInterval is
//     simultaneously the fix for finding 2 above: a real, loop-visible
//     pending timer that keeps RunUntil from declaring idle while the
//     goroutine is still working, cleared the instant the poll sees the
//     result.
//
// This pattern is exercised by TestAsyncFuncBindingResolvesFromGoroutine,
// TestAsyncFuncBindingRejectsOnError, and
// TestAsyncFuncBindingMultipleConcurrentCalls in bindings_test.go, run
// repeatedly (-count) while developing this to confirm the race is actually
// gone, not just usually-passing.
//
// Caveat: fn's arguments must be read as PRIMITIVES only (numbers, strings,
// booleans, null/undefined — matching what a JSON-shaped call typically
// passes). An object-typed argument that fn only reads inside the goroutine
// is unsafe: per Func's documented contract, an argument's handle is
// released "when the call returns" unless something inside the synchronous
// call took ownership of it (Value.Object/Export); kick's own call returns
// as soon as the goroutine is spawned, before fn runs, so an unretained
// object argument's handle may already be gone by the time fn reads it. A
// caller needing an object argument must extract what it needs from it (as
// primitives) before returning from a synchronous FuncBinding, not inside an
// AsyncFuncBinding's fn.
func AsyncFuncBinding(name string, fn spidermonkey.Func) cfworkers.Binding {
	return func(js *spidermonkey.JS) (spidermonkey.Value, error) {
		type asyncResult struct {
			value spidermonkey.Value
			err   error
		}
		var mu sync.Mutex
		results := make(map[int64]asyncResult)
		var nextID int64

		// kick starts fn on a goroutine and returns an opaque numeric handle
		// immediately — it never touches resolve/reject, so it has nothing
		// to race with RunUntil over.
		kick, err := js.NewFunction(name+":kick", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
			mu.Lock()
			nextID++
			id := nextID
			mu.Unlock()

			userArgs := append([]spidermonkey.Value(nil), args...)
			go func() {
				v, ferr := fn(cfg, userArgs)
				mu.Lock()
				results[id] = asyncResult{value: v, err: ferr}
				mu.Unlock()
			}()
			return spidermonkey.ValueOf(float64(id)), nil
		})
		if err != nil {
			return nil, fmt.Errorf("binding %q: registering kick: %w", name, err)
		}
		defer kick.Free()

		// poll is called repeatedly from a JS setInterval, always on the
		// loop's own goroutine: it just checks results for id and reports
		// {done:false} or {done:true, ok, value}. No blocking, no channel —
		// a plain mutex-guarded map read.
		poll, err := js.NewFunction(name+":poll", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("binding %q: internal error: poll called without an id", name)
			}
			id := int64(args[0].Float())
			mu.Lock()
			r, done := results[id]
			if done {
				delete(results, id)
			}
			mu.Unlock()

			out, oerr := js.NewObject()
			if oerr != nil {
				return nil, oerr
			}
			if !done {
				if serr := out.Set("done", spidermonkey.ValueOf(false)); serr != nil {
					return nil, serr
				}
				return out, nil
			}
			if serr := out.Set("done", spidermonkey.ValueOf(true)); serr != nil {
				return nil, serr
			}
			if r.err != nil {
				if serr := out.Set("ok", spidermonkey.ValueOf(false)); serr != nil {
					return nil, serr
				}
				if serr := out.Set("value", spidermonkey.ValueOf(r.err.Error())); serr != nil {
					return nil, serr
				}
				return out, nil
			}
			if serr := out.Set("ok", spidermonkey.ValueOf(true)); serr != nil {
				return nil, serr
			}
			v := r.value
			if v == nil {
				v = spidermonkey.Undefined()
			}
			if serr := out.Set("value", v); serr != nil {
				return nil, serr
			}
			return out, nil
		})
		if err != nil {
			return nil, fmt.Errorf("binding %q: registering poll: %w", name, err)
		}
		defer poll.Free()

		r, err := js.Eval(context.Background(), `(function(kick, poll) {
			return function(...args) {
				return new Promise((resolve, reject) => {
					const id = kick(...args);
					const iv = setInterval(() => {
						const r = poll(id);
						if (!r.done) return;
						clearInterval(iv);
						if (r.ok) resolve(r.value); else reject(r.value);
					}, 5);
				});
			};
		})`)
		if err != nil {
			return nil, fmt.Errorf("binding %q: building wrapper factory: %w", name, err)
		}
		if r.Error != nil {
			return nil, fmt.Errorf("binding %q: wrapper factory threw: %w", name, r.Error)
		}
		factory := r.Value.Object()
		if factory == nil {
			return nil, fmt.Errorf("binding %q: wrapper factory did not evaluate to a function", name)
		}
		defer factory.Free()

		wrapperVal, err := factory.Call(kick, poll)
		if err != nil {
			return nil, fmt.Errorf("binding %q: invoking wrapper factory: %w", name, err)
		}
		wrapperObj := wrapperVal.Object()
		if wrapperObj == nil {
			return nil, fmt.Errorf("binding %q: wrapper factory did not return a function", name)
		}
		return wrapperObj, nil
	}
}
