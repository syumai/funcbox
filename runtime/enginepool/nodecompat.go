package enginepool

import (
	"bytes"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

// envInjectingFS wraps an fs.FS so first-party module files (see
// shouldInjectEnvPath) get envPreamble prepended to their content — the
// NodeCompat-mode equivalent of wrapLoaderWithEnv's loader wrap.
//
// Why an fs.FS wrap instead of wrapping the module loader itself (as
// non-NodeCompat mode does): compat/nodejs.Install installs its OWN fallback
// loader (an unexported *Runtime method — resolveModule/readModuleFile/
// cjsShim/coreShim all live inside compat/nodejs, unreachable from here) and
// there is no hook to layer another loader on top of or in front of it. The
// only thing this package can still observe and adjust before nodejs.Install
// even runs is Config.Engine.FS, which that installed loader reads every
// file through — so injection happens one layer lower, at the byte level,
// instead of at the module-source-string level.
//
// Injection is deliberately narrow: only files with a .js or .mjs extension,
// OUTSIDE any node_modules/ directory, are rewritten. This is a first-party
// vs. dependency split, not a real ESM/CommonJS classifier (this package
// does not duplicate compat/nodejs's module-kind detection) — funcbox's own
// convention is that a function's own files are ESM (the non-NodeCompat
// loader enforces exactly that), so this assumes the same of NodeCompat's
// first-party files. A first-party file that resolves as CommonJS (e.g. no
// "type": "module" anywhere in scope) would fail to parse with the
// import.meta preamble prepended — a known, narrow limitation, not silently
// corrupted data: the failure is a clear syntax/reference error at that
// file's own import, not a miscategorized dependency. node_modules content
// is never touched, so a vendored dependency's CJS/JSON files can never be
// corrupted by this wrap.
type envInjectingFS struct {
	inner fs.FS
}

// wrapFSWithEnv returns inner wrapped for NodeCompat-mode import.meta.env
// injection, or nil if inner is nil.
func wrapFSWithEnv(inner fs.FS) fs.FS {
	if inner == nil {
		return nil
	}
	return envInjectingFS{inner: inner}
}

// shouldInjectEnvPath reports whether name (a slash-separated fs.FS path) is
// a first-party ES module file eligible for the import.meta.env preamble.
func shouldInjectEnvPath(name string) bool {
	if strings.Contains(name, "node_modules/") {
		return false
	}
	switch path.Ext(name) {
	case ".js", ".mjs":
		return true
	default:
		return false
	}
}

func (e envInjectingFS) Open(name string) (fs.File, error) {
	f, err := e.inner.Open(name)
	if err != nil {
		return nil, err
	}
	if !shouldInjectEnvPath(name) {
		return f, nil
	}
	info, serr := f.Stat()
	if serr != nil {
		f.Close()
		return nil, serr
	}
	if info.IsDir() {
		// A directory named "*.js" is exotic but not impossible; leave
		// directory listing untouched.
		return f, nil
	}
	data, rerr := io.ReadAll(f)
	cerr := f.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	combined := append([]byte(envPreamble), data...)
	return &envInjectedFile{
		name:    name,
		size:    int64(len(combined)),
		mode:    info.Mode(),
		modTime: info.ModTime(),
		reader:  bytes.NewReader(combined),
	}, nil
}

// envInjectedFile is a synthetic fs.File serving the preamble-prepended
// content in place of the original, for exactly one Open call.
type envInjectedFile struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	reader  *bytes.Reader
}

func (f *envInjectedFile) Stat() (fs.FileInfo, error) { return envInjectedFileInfo{f}, nil }
func (f *envInjectedFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *envInjectedFile) Close() error               { return nil }

type envInjectedFileInfo struct{ f *envInjectedFile }

func (i envInjectedFileInfo) Name() string       { return path.Base(i.f.name) }
func (i envInjectedFileInfo) Size() int64        { return i.f.size }
func (i envInjectedFileInfo) Mode() fs.FileMode  { return i.f.mode }
func (i envInjectedFileInfo) ModTime() time.Time { return i.f.modTime }
func (i envInjectedFileInfo) IsDir() bool        { return false }
func (i envInjectedFileInfo) Sys() any           { return nil }
