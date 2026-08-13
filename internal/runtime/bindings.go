package runtime

import (
	"context"
	"fmt"

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
// How this works, and why it's safe (found by reading hostenv.go and
// internal/spidermonkey.go, since cfworkers' Binding only ever hands out a
// *spidermonkey.JS with no access to compat/web's event loop — that type
// lives in the library's compat/internal/eventloop, unexported to
// consumers, so a binding cannot drive the loop itself the way compat/web's
// own async ops do):
//
//   - A tiny per-binding JS shim (built once at warm-up via Eval) wraps a
//     "starter" NewFunction in `new Promise((resolve, reject) => starter(
//     resolve, reject, ...args))`. The Promise constructor calls starter
//     synchronously but starter returns immediately, so `new Promise(...)`
//     — and therefore the exported env.NAME(...) call — returns a pending
//     Promise without blocking the guest.
//   - starter's Go closure takes args[0]/args[1] as *Object (resolve/
//     reject): per Func's documented contract, taking an argument AS an
//     object transfers the handle's GC pin to the callback, and "*Object
//     arguments also stay valid after the evaluation returns ... so
//     retaining them for later works too" (hostenv.go). So starter spawns a
//     goroutine holding those objects, returns undefined immediately (the
//     Promise is now pending on the guest side), and the goroutine runs fn.
//   - When fn finishes, the goroutine calls resolve.Call(result) or
//     reject.Call(errValue) directly — from a goroutine that is NOT the one
//     currently inside the interpreter. This is safe because
//     internal/spidermonkey.go documents a per-instance "invoke lock":
//     calls arrive serialized under it, and a host Func's own callback
//     window releases the lock for its duration precisely so re-entrant/
//     later calls (like this one) can proceed. Whichever goroutine is
//     inside the interpreter at that moment (typically cfworkers' own
//     RunUntil polling loop, driving the request to settle) simply
//     serializes with this call through that lock; there is no separate
//     synchronization to build.
//   - The resolve/reject call lands as an ordinary guest Promise
//     settlement, so it participates in the normal microtask queue the
//     request's RunUntil loop is already draining — no extra plumbing is
//     needed on the cfworkers side.
//
// This pattern is exercised by TestAsyncFuncBindingResolvesFromGoroutine and
// TestAsyncFuncBindingRejectsOnError in bindings_test.go, including a
// concurrency check that overlaps the goroutine's resolve call with the
// request loop's own polling.
//
// Caveat: fn's arguments must be read as PRIMITIVES only (numbers, strings,
// booleans, null/undefined — matching what a JSON-shaped call typically
// passes). An object-typed argument that fn only reads inside the goroutine
// is unsafe: per Func's documented contract, an argument's handle is
// released "when the call returns" unless something inside the synchronous
// call took ownership of it (Value.Object/Export); starter's own call
// returns as soon as the goroutine is spawned, before fn runs, so an
// unretained object argument's handle may already be gone by the time fn
// reads it. A caller needing an object argument must extract what it needs
// from it (as primitives) before returning from a synchronous FuncBinding,
// not inside an AsyncFuncBinding's fn.
func AsyncFuncBinding(name string, fn spidermonkey.Func) cfworkers.Binding {
	starterName := "\x00async_starter:" + name
	return func(js *spidermonkey.JS) (spidermonkey.Value, error) {
		starter, err := js.NewFunction(starterName, func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
			if len(args) < 2 {
				return nil, fmt.Errorf("binding %q: internal error: starter called without resolve/reject", name)
			}
			resolveObj := args[0].Object()
			rejectObj := args[1].Object()
			if resolveObj == nil || rejectObj == nil {
				return nil, fmt.Errorf("binding %q: internal error: resolve/reject not callable", name)
			}
			userArgs := append([]spidermonkey.Value(nil), args[2:]...)
			go func() {
				defer resolveObj.Free()
				defer rejectObj.Free()
				result, ferr := fn(cfg, userArgs)
				if ferr != nil {
					// A plain string is enough for a guest-visible rejection
					// reason; callers that need a real Error object can
					// still throw one from fn's Value on success paths.
					_, _ = rejectObj.Call(spidermonkey.ValueOf(ferr.Error()))
					return
				}
				_, _ = resolveObj.Call(result)
			}()
			return spidermonkey.Undefined(), nil
		})
		if err != nil {
			return nil, fmt.Errorf("binding %q: registering starter: %w", name, err)
		}

		if err := js.Global().Set(starterName, starter); err != nil {
			starter.Free()
			return nil, fmt.Errorf("binding %q: %w", name, err)
		}
		starter.Free()

		wrapperSrc := fmt.Sprintf(
			`(function(...args) { return new Promise((resolve, reject) => globalThis[%q](resolve, reject, ...args)); })`,
			starterName,
		)
		r, err := js.Eval(context.Background(), wrapperSrc)
		if err != nil {
			return nil, fmt.Errorf("binding %q: building wrapper: %w", name, err)
		}
		if r.Error != nil {
			return nil, fmt.Errorf("binding %q: wrapper threw: %w", name, r.Error)
		}
		wrapperObj := r.Value.Object()
		if wrapperObj == nil {
			return nil, fmt.Errorf("binding %q: wrapper did not evaluate to a function", name)
		}
		return wrapperObj, nil
	}
}
