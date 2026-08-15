package enginepool

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// InternalExport builds one named export's guest value, once per pooled
// instance at warm-up (mirroring the pre-migration env-binding shape, but
// for a funcbox:-namespaced module instead of a Cloudflare-Workers-style env
// binding).
type InternalExport func(js *spidermonkey.JS) (spidermonkey.Value, error)

// InternalModule maps export names to their constructors, for one
// funcbox:-namespaced module (e.g. Config.Internal["funcbox:internal"]).
// Only a pool actually constructed with a non-nil Config.Internal can ever
// import a "funcbox:" specifier — see internalModuleLoader.
type InternalModule map[string]InternalExport

// StaticExport is an InternalExport for plain data (anything encoding/json
// can marshal — it materializes guest-side as a fresh value per instance).
func StaticExport(v any) InternalExport {
	return func(*spidermonkey.JS) (spidermonkey.Value, error) { return spidermonkey.ValueOf(v), nil }
}

// FuncExport is an InternalExport exposing a synchronous Go function: the
// guest calls it and gets fn's return value back immediately (a plain call,
// not a Promise). fn runs on the same goroutine and blocks the request for
// as long as fn takes.
func FuncExport(name string, fn spidermonkey.Func) InternalExport {
	return func(js *spidermonkey.JS) (spidermonkey.Value, error) {
		obj, err := js.NewFunction(name, fn)
		if err != nil {
			return nil, fmt.Errorf("internal export %q: %w", name, err)
		}
		return obj, nil
	}
}

// AsyncExport is an InternalExport exposing fn as a Promise-returning guest
// function: the call returns immediately with a pending Promise, fn runs on
// its own goroutine, and its result resolves (a returned error rejects) the
// promise once fn finishes.
//
// This is the poll-based pattern (kick starts fn on a goroutine and returns
// an opaque handle; a guest-side setInterval polls a Go-side result map and
// settles the promise itself, always from the loop's own turn) verified
// against two failure modes during the pre-migration env-binding design:
//
//  1. Naming the Go function itself (rather than passing it as a bare call
//     argument) risks a NUL-prefixed or otherwise unusual property name
//     silently truncating at the host/guest string bridge — passing kick and
//     poll as arguments to a small JS wrapper factory sidesteps guest-visible
//     naming entirely.
//  2. Settling the promise by calling resolve/reject DIRECTLY from the
//     background goroutine races the serving goroutine's own
//     `wk.web.Loop().RunUntil(ctx, stop)`: RunUntil can declare the request
//     idle (and stop) the instant BEFORE a foreign resolve() call actually
//     lands, because RunUntil has no way to know a goroutine intends to call
//     it imminently. Never calling into the interpreter from the goroutine at
//     all — only writing into a mutex-guarded map, with the settlement call
//     itself made by a real setInterval on the SAME goroutine RunUntil
//     drives — removes the race, and the armed setInterval doubles as what
//     keeps RunUntil from declaring idle while the goroutine still works.
//
// Caveat: fn's arguments must be read as PRIMITIVES only (numbers, strings,
// booleans, null/undefined). An object-typed argument's handle is released
// when the synchronous kick call returns, before fn (on its own goroutine)
// gets a chance to read it — extract what's needed from an object argument
// before returning from a synchronous export, never inside fn here.
func AsyncExport(name string, fn spidermonkey.Func) InternalExport {
	return func(js *spidermonkey.JS) (spidermonkey.Value, error) {
		type asyncResult struct {
			value spidermonkey.Value
			err   error
		}
		var mu sync.Mutex
		results := make(map[int64]asyncResult)
		var nextID int64

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
			return nil, fmt.Errorf("internal export %q: registering kick: %w", name, err)
		}
		defer kick.Free()

		poll, err := js.NewFunction(name+":poll", func(cfg spidermonkey.Config, args []spidermonkey.Value) (spidermonkey.Value, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("internal export %q: internal error: poll called without an id", name)
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
			return nil, fmt.Errorf("internal export %q: registering poll: %w", name, err)
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
			return nil, fmt.Errorf("internal export %q: building wrapper factory: %w", name, err)
		}
		if r.Error != nil {
			return nil, fmt.Errorf("internal export %q: wrapper factory threw: %w", name, r.Error)
		}
		factory := r.Value.Object()
		if factory == nil {
			return nil, fmt.Errorf("internal export %q: wrapper factory did not evaluate to a function", name)
		}
		defer factory.Free()

		wrapperVal, err := factory.Call(kick, poll)
		if err != nil {
			return nil, fmt.Errorf("internal export %q: invoking wrapper factory: %w", name, err)
		}
		wrapperObj := wrapperVal.Object()
		if wrapperObj == nil {
			return nil, fmt.Errorf("internal export %q: wrapper factory did not return a function", name)
		}
		return wrapperObj, nil
	}
}

// internalGlobalName is the globalThis property one funcbox:-namespaced
// module's built export object is stashed under, keyed by its full
// specifier so distinct internal modules never collide.
func internalGlobalName(specifier string) string {
	return "__funcbox_internal__" + specifier
}

// installInternalModules builds every configured module's export object —
// calling each InternalExport, which may itself call js.NewFunction/
// js.NewObject/js.Eval/.Call() — and stashes each as a plain globalThis
// property, ALL BEFORE any module import happens (called from newWorker
// right after installEnv, before the glue eval / boot EvalModule).
//
// This timing matters and is NOT incidental: a ModuleLoader callback runs
// synchronously NESTED inside the engine's own EvalModule call (the engine
// calls back into Go mid-resolution), and an InternalExport like AsyncExport
// itself calls js.Eval/.Call() to build its Promise wrapper. Building
// exports from WITHIN the loader callback — i.e. reentrantly calling back
// into the interpreter while already inside a host callback the interpreter
// invoked — deadlocked in testing (confirmed empirically: the test process
// blocked with near-zero CPU, the signature of a self-deadlocked lock, not a
// slow computation). Building everything up front, exactly when cfworkers'
// original env-binding construction did (a plain top-level loop, no pending
// Eval/EvalModule call in progress), avoids the reentrancy entirely: the
// loader (below) then does nothing but synchronous string building.
func installInternalModules(js *spidermonkey.JS, modules map[string]InternalModule) error {
	for specifier, mod := range modules {
		obj, err := js.NewObject()
		if err != nil {
			return err
		}
		for _, name := range sortedExportNames(mod) {
			v, err := mod[name](js)
			if err != nil {
				obj.Free()
				return fmt.Errorf("building %q export %q: %w", specifier, name, err)
			}
			if err := obj.Set(name, v); err != nil {
				obj.Free()
				return fmt.Errorf("building %q export %q: %w", specifier, name, err)
			}
		}
		err = js.Global().Set(internalGlobalName(specifier), obj)
		obj.Free()
		if err != nil {
			return err
		}
	}
	return nil
}

// internalModuleLoader returns the spidermonkey.ModuleLoader registered for
// the "funcbox:" prefix (only when Config.Internal is non-nil — see
// newWorker, which calls installInternalModules first). It is a pure,
// synchronous string builder: every export object already exists on
// globalThis by the time any module import can reach this loader, so this
// never calls back into the interpreter itself (see installInternalModules'
// doc comment for why that distinction matters).
//
// A specifier is looked up by exact match against modules' keys; anything
// under the "funcbox:" prefix that isn't a configured key is "not found" —
// this is the only gate: a pool built with Config.Internal == nil never
// registers this resolver at all, so "funcbox:*" falls through to whatever
// the ordinary fallback loader reports (itself a "not found"-shaped error,
// since no real bundle ever contains a file named "funcbox:...").
func internalModuleLoader(modules map[string]InternalModule) spidermonkey.ModuleLoader {
	return func(_ spidermonkey.Config, specifier, referrer string) (string, error) {
		mod, ok := modules[specifier]
		if !ok {
			return "", fmt.Errorf("module %q not found", specifier)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "const __m = globalThis[%q];\n", internalGlobalName(specifier))
		for _, name := range sortedExportNames(mod) {
			fmt.Fprintf(&b, "export const %s = __m[%q];\n", name, name)
		}
		return b.String(), nil
	}
}

func sortedExportNames(mod InternalModule) []string {
	names := make([]string, 0, len(mod))
	for name := range mod {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
