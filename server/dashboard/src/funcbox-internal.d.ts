// Ambient module declaration for "funcbox:internal": a host-provided module
// funcbox's Go runtime resolves at request time (internal/dashboard's
// enginepool.Config.Internal -- see internalapi.go), not a real npm
// package or file on disk. esbuild is told to leave this import alone
// (build.ts's `external`); this declaration only exists so `tsc`/editors
// can typecheck against it.
declare module "funcbox:internal" {
	// internalAPI dispatches funcbox's management API in-process. callerToken
	// is an HMAC-signed identity claim internal/dashboard mints per request
	// and verifies on every call -- see api.ts's doc comment.
	export function internalAPI(method: string, path: string, body: string, callerToken: string): Promise<string>;
}
