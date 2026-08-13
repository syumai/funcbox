// funcbox entry point (funcbox.yaml's `main`). Runs inside funcbox's
// go-spidermonkey compat/cfworkers + compat/web runtime.
//
// vinext's Cloudflare Workers build (dist/server/index.js) is written
// against `env.ASSETS.fetch(...)` (the Workers static-assets binding) to
// serve dist/client's JS/CSS chunks — funcbox has no such binding. This
// module is the wrapper described in the example's README: it serves
// those assets itself from a build-time-generated map (dist/assets.js,
// see scripts/build-assets.mjs) and delegates everything else to vinext's
// own fetch handler.
//
// IMPORTANT — see README.md "Status: blocked" before assuming this works.
// dist/server/index.js (and several of the chunks it imports) contain a
// static `import { AsyncLocalStorage } from "node:async_hooks"`. funcbox
// does not provide node:* core modules in any mode (tmp/03-runtime.md
// §3.5), so that import fails at module-evaluation time — before this
// wrapper's fetch() ever runs, for *any* request, including asset
// requests, because ESM module graphs are evaluated eagerly as a whole.
// This file is shipped anyway, in that honest "does not currently boot on
// funcbox" state, as documentation of the intended architecture and so it
// is ready to work unmodified if/when the blocker is resolved upstream.
import { assets } from "./dist/assets.js";
import vinextHandler from "./dist/server/index.js";

const IMMUTABLE_PREFIX = "/_next/static/";

function decodeAsset(entry) {
  const binary = atob(entry.data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function assetResponse(pathname, entry) {
  const headers = { "content-type": entry.type, etag: `"${entry.hash}"` };
  if (pathname.startsWith(IMMUTABLE_PREFIX)) {
    headers["cache-control"] = "public, max-age=31536000, immutable";
  }
  return new Response(decodeAsset(entry), { headers });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const asset = assets[url.pathname];
    if (asset) {
      return assetResponse(url.pathname, asset);
    }
    return vinextHandler.fetch(request, env, ctx);
  },
};
