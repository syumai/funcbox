// build.ts is funcbox dashboard's build script (tmp/09-dashboard.md §9.6),
// run with plain `node build.ts` (Node 24 strips TypeScript types natively,
// no separate transpile step needed) via the `build`/`watch` package.json
// scripts. It never runs at funcbox-server runtime -- only at development
// time and in `make server` (see the repo root Makefile) -- matching the
// "pnpm/Node are dev/build-time only" hosting requirement.
//
// Two esbuild passes, in order:
//   1. Client assets (src/client/main.ts, src/styles.css) -> dist/assets/,
//      with esbuild's own content-hashed filenames (entryNames:
//      "[name]-[hash]"), read back from the build result's metafile.
//   2. The SSR bundle (src/server.tsx) -> dist/server.js, a single
//      self-contained ESM module (platform: "neutral", conditions:
//      ["worker"], so it only ever resolves compat/web's WinterTC surface,
//      never a Node builtin) with the hashed asset URLs from step 1 baked in
//      via `define` -- so the running server never needs to read a manifest
//      file at request time, just the string constants esbuild inlined.
//
// Deviation from tmp/09-dashboard.md §9.2's tree diagram (dist/ nested
// under dashboard/): the build output actually lands in
// ../internal/dashboard/dist, not ./dist. go:embed cannot embed a path
// outside (or a parent-relative "../" from) the package directory it's
// declared in -- internal/dashboard/embed.go's `//go:embed all:dist`
// therefore REQUIRES dist/ to be internal/dashboard's own subdirectory, not
// dashboard's. This keeps the Go side's `//go:embed all:dist` directive
// exactly as simple as the design doc intends; only the physical location
// of the pnpm-managed output directory moves.
import * as esbuild from "esbuild";
import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dir = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(dir, "..", "internal", "dashboard", "dist");
const assetsDir = path.join(distDir, "assets");
const watch = process.argv.includes("--watch");

async function buildClientAssets(): Promise<{ scriptURL: string; styleURL: string }> {
	const result = await esbuild.build({
		entryPoints: {
			main: path.join(dir, "src/client/main.ts"),
			styles: path.join(dir, "src/styles.css"),
		},
		bundle: true,
		minify: true,
		sourcemap: false,
		outdir: assetsDir,
		entryNames: "[name]-[hash]",
		format: "iife",
		target: ["es2022"],
		metafile: true,
		logLevel: "info",
	});

	let scriptOut: string | undefined;
	let styleOut: string | undefined;
	for (const outFile of Object.keys(result.metafile.outputs)) {
		const rel = path.relative(distDir, path.join(dir, outFile));
		const base = path.basename(rel);
		if (base.startsWith("main-") && base.endsWith(".js")) scriptOut = rel;
		if (base.startsWith("styles-") && base.endsWith(".css")) styleOut = rel;
	}
	if (!scriptOut || !styleOut) {
		throw new Error(
			`build: could not find hashed client asset outputs in esbuild metafile (outputs: ${Object.keys(result.metafile.outputs).join(", ")})`,
		);
	}
	// scriptOut/styleOut are already "assets/<hashed-name>" (relative to
	// distDir), so the URL is just "/dashboard/" + that -- NOT
	// "/dashboard/assets/" + that, which would double the "assets" segment.
	return {
		scriptURL: `/dashboard/${scriptOut}`,
		styleURL: `/dashboard/${styleOut}`,
	};
}

async function buildServer(assetURLs: { scriptURL: string; styleURL: string }) {
	await esbuild.build({
		entryPoints: [path.join(dir, "src/server.tsx")],
		bundle: true,
		minify: true,
		sourcemap: false,
		outfile: path.join(distDir, "server.js"),
		format: "esm",
		platform: "neutral",
		conditions: ["worker"],
		target: ["es2022"],
		jsx: "automatic",
		jsxImportSource: "hono/jsx",
		define: {
			__ASSET_SCRIPT_URL__: JSON.stringify(assetURLs.scriptURL),
			__ASSET_STYLE_URL__: JSON.stringify(assetURLs.styleURL),
		},
		logLevel: "info",
	});
}

async function buildAll() {
	await rm(distDir, { recursive: true, force: true });
	await mkdir(assetsDir, { recursive: true });
	const assetURLs = await buildClientAssets();
	await buildServer(assetURLs);
	// Recreate the placeholder go:embed needs to see even in a pristine,
	// not-yet-built checkout (internal/dashboard/embed.go's doc comment);
	// this build just deleted it along with the rest of distDir above.
	await writeFile(path.join(distDir, ".gitkeep"), "");
	console.log("dashboard: build complete ->", distDir);
}

async function watchAll() {
	// esbuild's incremental watch mode doesn't fit this two-pass shape well
	// (the server bundle depends on the client pass's OUTPUT filenames, not
	// just its inputs), so `watch` here is a simple rebuild-on-change loop
	// rather than esbuild's own context.watch(). Good enough for local dev,
	// per tmp/09-dashboard.md §9.6: "dist 変更を検知して...Pool を
	// invalidate" is funcbox-server's job (internal/dashboard), not this
	// script's -- this script's only job is to keep dist/ up to date.
	const chokidarSrc = path.join(dir, "src");
	console.log("dashboard: watching", chokidarSrc, "for changes (Ctrl-C to stop)");
	await buildAll().catch((err) => console.error(err));
	const { watch: fsWatch } = await import("node:fs");
	let pending = false;
	let timer: NodeJS.Timeout | undefined;
	fsWatch(chokidarSrc, { recursive: true }, () => {
		if (timer) clearTimeout(timer);
		timer = setTimeout(async () => {
			if (pending) return;
			pending = true;
			try {
				await buildAll();
			} catch (err) {
				console.error(err);
			} finally {
				pending = false;
			}
		}, 100);
	});
	// Keep the process alive.
	await new Promise(() => {});
}

if (watch) {
	await watchAll();
} else {
	await buildAll();
}
