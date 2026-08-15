package enginepool

import (
	"context"

	spidermonkey "github.com/goccy/go-spidermonkey"
)

// envGlobalName is the globalThis property envPreamble reads. It is set once
// per worker instance, before any function module (or its imports) load, and
// never mutated afterward — every module's import.meta.env preamble
// statement points at the SAME frozen object, so import.meta.env compares
// equal (by value, and by identity) across every module in the instance.
const envGlobalName = "__funcbox_env"

// envPreamble is prepended, verbatim, to every module's source text loaded
// through the wrapped loader (see wrapLoaderWithEnv). It does not rewrite or
// otherwise touch the rest of the module's source — it only defines one
// property on that module's own real import.meta object, using the
// language's actual per-module import.meta rather than a text substitution
// of every import.meta.env reference (which would be fragile: it would have
// to avoid false positives inside string/template literals and comments,
// survive minified single-line sources, and handle bracket-notation access).
// import.meta is a genuine, extensible, per-module ordinary object
// (confirmed empirically: it is NOT the same object across modules, and
// Object.defineProperty on it works with no engine-side "populate" hook
// needed — see the design note this package's tests pin down), so this is
// exactly what a HostPopulateImportMeta hook would do, just issued from
// JS instead of from a Go-side hook go-spidermonkey does not expose.
const envPreamble = `Object.defineProperty(import.meta, "env", ` +
	`{ value: globalThis["` + envGlobalName + `"], enumerable: true, writable: false, configurable: false });` +
	"\n"

// wrapLoaderWithEnv wraps inner so every module it resolves gets envPreamble
// prepended to its source. inner may be nil (e.g. a pool with nothing to
// load beyond funcbox:-namespaced modules, which never go through this
// loader — see loader.go's prefix-resolver split), in which case the wrapped
// loader is nil too.
func wrapLoaderWithEnv(inner spidermonkey.ModuleLoader) spidermonkey.ModuleLoader {
	if inner == nil {
		return nil
	}
	return func(cfg spidermonkey.Config, specifier, referrer string) (string, error) {
		src, err := inner(cfg, specifier, referrer)
		if err != nil {
			return "", err
		}
		return envPreamble + src, nil
	}
}

// installEnv defines globalThis.__funcbox_env as a frozen, string-only
// object built from env, before any module loads. env is assumed to already
// be exactly the declared (manifest `env:`) key set — this package does not
// filter or validate keys itself, matching the existing division of
// responsibility between the caller (which knows the declaration) and the
// engine layer (which just exposes what it's given).
func installEnv(js *spidermonkey.JS, env map[string]string) error {
	envObj, err := js.NewObject()
	if err != nil {
		return err
	}
	for k, v := range env {
		if err := envObj.Set(k, spidermonkey.ValueOf(v)); err != nil {
			envObj.Free()
			return err
		}
	}
	if err := js.Global().Set(envGlobalName, envObj); err != nil {
		envObj.Free()
		return err
	}
	envObj.Free()
	r, err := js.Eval(context.Background(), `Object.freeze(globalThis["`+envGlobalName+`"]);`)
	if err != nil {
		return err
	}
	if r.Error != nil {
		return r.Error
	}
	return nil
}
