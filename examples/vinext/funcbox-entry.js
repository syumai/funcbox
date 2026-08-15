// funcbox entry point (funcbox.yaml's `main`). Runs inside funcbox's own
// runtime (runtime/enginepool), with compat.nodejs: true — required
// because dist/server/index.js (and a couple of the RSC chunks it
// imports) statically import `AsyncLocalStorage` from "node:async_hooks".
// See README.md for how this was verified (it used to be a hard blocker
// before funcbox brought its own execution pool in-house and could wire
// up nodejs.Install).
//
// vinext's Cloudflare Workers build (dist/server/index.js) is written
// against `env.ASSETS.fetch(...)` (the Workers static-assets binding) to
// serve dist/client's JS/CSS chunks — funcbox has no such binding. This
// module is the wrapper described in the example's README: it serves
// those assets itself from a build-time-generated map (dist/assets.js,
// see scripts/build-assets.mjs) and delegates everything else to vinext's
// own fetch handler. vinext's own handler still expects Workers-style
// `fetch(request, env, ctx)`; funcbox only ever calls `fetch(request)`, so
// this wrapper calls it with `undefined` for env/ctx — harmless for this
// app, which reads neither (see README's "Known limitations" for what
// that would mean for a vinext feature that DID use them, e.g. Cloudflare
// bindings via `cloudflare:workers`).
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
  async fetch(request) {
    const url = new URL(request.url);
    const asset = assets[url.pathname];
    if (asset) {
      return assetResponse(url.pathname, asset);
    }
    return vinextHandler.fetch(request, undefined, undefined);
  },
};
