// client/main.ts is the dashboard's ONLY client-side JavaScript
// separately from the SSR app (see build.ts) and runs in the real browser,
// not funcbox's own runtime -- this is the one place in the dashboard that
// talks to /api/v1 over plain HTTP with the browser's own session cookie,
// because a multipart tar.gz upload has no sensible shape as an
// env.INTERNAL_API call (see api.ts's doc comment).
//
// Four independent behaviors, each scoped to its own DOM contract so they
// don't interfere with server-rendered markup that doesn't need them:
//   1. Confirm dialogs on any form carrying data-confirm="...".
//   2. Copy-to-clipboard buttons (data-copy-target="<id-of-text-to-copy>").
//   3. A client-side substring filter for the function list table.
//   4. The /functions/new upload flow: two file-picker modes, drag & drop,
//      a 5MB pre-check gauge, and nanotar-based tar.gz creation posted
//      directly to POST /api/v1/functions (dry-run and real deploy).
import { createTarGzip, type TarFileInput } from "nanotar";

const language = document.body.dataset.language === "ja" ? "ja" : "en";
const clientMessages = {
	en: {
		copied: "copied", unpacked: "Unpacked {current} / {max}", bundleTooLarge: "⚠ Total size exceeds the 5 MB limit. Did you select a folder containing node_modules? Exclude it with .funcboxignore or upload pre-bundled files.", dryRunWarnings: "Dry-run warnings", dryRunSucceeded: "Dry-run validation succeeded. manifest: {name}", deploymentSucceeded: "Deployment succeeded.", viewFunction: "View function details",
	},
	ja: {
		copied: "コピーしました", unpacked: "展開後 {current} / {max}", bundleTooLarge: "⚠ 合計サイズが5MBの上限を超えています。node_modules を含むフォルダを選択していませんか？ .funcboxignore で除外するか、事前バンドルしたファイルをアップロードしてください。", dryRunWarnings: "dry-run 警告", dryRunSucceeded: "dry-run 検証に成功しました。manifest: {name}", deploymentSucceeded: "デプロイに成功しました。", viewFunction: "関数の詳細を見る",
	},
};
const clientCopy = clientMessages[language];
function ct(key: keyof typeof clientMessages.en, values: Record<string, string> = {}) {
	return clientCopy[key].replace(/\{(\w+)\}/g, (_, name) => values[name] ?? `{${name}}`);
}

function csrfToken(): string {
	const m = document.cookie.match(/(?:^|; )fbx_csrf=([^;]+)/);
	return m ? decodeURIComponent(m[1]) : "";
}

// --- 1. confirm dialogs ---
document.addEventListener("submit", (e) => {
	const form = e.target as HTMLFormElement;
	const msg = form.getAttribute("data-confirm");
	if (msg && !window.confirm(msg)) {
		e.preventDefault();
	}
});

// --- 2. copy buttons ---
document.addEventListener("click", (e) => {
	const btn = (e.target as HTMLElement).closest<HTMLElement>("[data-copy-target]");
	if (!btn) return;
	const targetId = btn.getAttribute("data-copy-target");
	const target = targetId ? document.getElementById(targetId) : null;
	const text = target?.textContent?.trim();
	if (!text) return;
	navigator.clipboard?.writeText(text).then(() => {
		const original = btn.textContent;
		btn.textContent = ct("copied");
		setTimeout(() => {
			btn.textContent = original;
		}, 1200);
	});
});

// --- 3. function list filter ---
const filterInput = document.querySelector<HTMLInputElement>("[data-fn-filter]");
if (filterInput) {
	filterInput.addEventListener("input", () => {
		const q = filterInput.value.trim().toLowerCase();
		document.querySelectorAll<HTMLElement>("[data-fn-row]").forEach((row) => {
			const key = row.getAttribute("data-fn-key") ?? "";
			row.style.display = !q || key.includes(q) ? "" : "none";
		});
	});
}

// --- 4. upload flow ---
const MAX_UNPACKED_BYTES = 5 * 1024 * 1024;

interface CollectedFile {
	path: string;
	file: File;
}

function initDeployForm() {
	const root = document.querySelector<HTMLElement>("[data-deploy-root]");
	if (!root) return;

	const dropZone = root.querySelector<HTMLElement>("[data-drop-zone]")!;
	const inputFolder = root.querySelector<HTMLInputElement>("[data-input-folder]")!;
	const inputFiles = root.querySelector<HTMLInputElement>("[data-input-files]")!;
	const modeFolderBtn = root.querySelector<HTMLButtonElement>('[data-mode="folder"]')!;
	const modeFilesBtn = root.querySelector<HTMLButtonElement>('[data-mode="files"]')!;
	const filesList = root.querySelector<HTMLElement>("[data-files-list]")!;
	const gauge = root.querySelector<HTMLElement>("[data-gauge]")!;
	const gaugeBar = gauge.querySelector<HTMLElement>("i")!;
	const gnote = root.querySelector<HTMLElement>("[data-gnote]")!;
	const warnBox = root.querySelector<HTMLElement>("[data-warn]")!;
	const resultBox = root.querySelector<HTMLElement>("[data-result]")!;
	const deployBtn = root.querySelector<HTMLButtonElement>("[data-btn-deploy]")!;
	const dryrunBtn = root.querySelector<HTMLButtonElement>("[data-btn-dryrun]")!;
	const ownerSelect = root.querySelector<HTMLSelectElement>("[data-owner-select]")!;
	const nameInput = root.querySelector<HTMLInputElement>("[data-name-input]")!;
	const noteInput = root.querySelector<HTMLInputElement>("[data-note-input]")!;

	let mode: "folder" | "files" = "folder";
	let collected: CollectedFile[] = [];

	function setMode(next: "folder" | "files") {
		mode = next;
		modeFolderBtn.classList.toggle("on", mode === "folder");
		modeFilesBtn.classList.toggle("on", mode === "files");
	}
	modeFolderBtn.addEventListener("click", () => setMode("folder"));
	modeFilesBtn.addEventListener("click", () => setMode("files"));

	dropZone.addEventListener("click", () => {
		(mode === "folder" ? inputFolder : inputFiles).click();
	});
	dropZone.addEventListener("dragover", (e) => {
		e.preventDefault();
		dropZone.classList.add("dragover");
	});
	dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
	dropZone.addEventListener("drop", async (e) => {
		e.preventDefault();
		dropZone.classList.remove("dragover");
		if (!e.dataTransfer) return;
		const items = Array.from(e.dataTransfer.items);
		const entries = items.map((it) => it.webkitGetAsEntry?.()).filter((x): x is FileSystemEntry => !!x);
		if (entries.length > 0) {
			setCollected(await walkEntries(entries));
		} else if (e.dataTransfer.files.length > 0) {
			setCollected(Array.from(e.dataTransfer.files).map((file) => ({ path: file.name, file })));
		}
	});

	inputFolder.addEventListener("change", () => {
		const files = Array.from(inputFolder.files ?? []);
		setCollected(
			files.map((file) => {
				const rel = (file as any).webkitRelativePath as string | undefined;
				const path = rel ? stripTopSegment(rel) : file.name;
				return { path, file };
			}),
		);
	});
	inputFiles.addEventListener("change", () => {
		const files = Array.from(inputFiles.files ?? []);
		setCollected(files.map((file) => ({ path: file.name, file })));
	});

	function stripTopSegment(relPath: string): string {
		const idx = relPath.indexOf("/");
		return idx >= 0 ? relPath.slice(idx + 1) : relPath;
	}

	async function walkEntries(entries: FileSystemEntry[]): Promise<CollectedFile[]> {
		const out: CollectedFile[] = [];
		async function walk(entry: FileSystemEntry, prefix: string) {
			if (entry.isFile) {
				const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject));
				out.push({ path: prefix + entry.name, file });
			} else if (entry.isDirectory) {
				const reader = (entry as FileSystemDirectoryEntry).createReader();
				const children: FileSystemEntry[] = [];
				// readEntries must be called repeatedly until it returns an
				// empty array -- a single call is not guaranteed to return
				// every child (a documented quirk of the File System API).
				for (;;) {
					const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject));
					if (batch.length === 0) break;
					children.push(...batch);
				}
				for (const child of children) await walk(child, prefix + entry.name + "/");
			}
		}
		for (const entry of entries) await walk(entry, "");
		return out;
	}

	function setCollected(files: CollectedFile[]) {
		collected = files;
		renderFiles();
	}

	function renderFiles() {
		filesList.innerHTML = "";
		let total = 0;
		for (const f of collected) {
			total += f.file.size;
			const row = document.createElement("div");
			const nameSpan = document.createElement("span");
			nameSpan.textContent = f.path;
			const sizeSpan = document.createElement("span");
			sizeSpan.textContent = formatBytes(f.file.size);
			row.append(nameSpan, sizeSpan);
			filesList.append(row);
		}
		const pct = Math.min(100, Math.round((total / MAX_UNPACKED_BYTES) * 100));
		gaugeBar.style.width = pct + "%";
		gauge.classList.toggle("over", total > MAX_UNPACKED_BYTES);
		gnote.textContent = ct("unpacked", { current: formatBytes(total), max: formatBytes(MAX_UNPACKED_BYTES) });
		const over = total > MAX_UNPACKED_BYTES;
		deployBtn.disabled = over || collected.length === 0;
		dryrunBtn.disabled = over || collected.length === 0;
		if (over) {
			warnBox.innerHTML =
				ct("bundleTooLarge");
			warnBox.style.display = "";
		} else {
			warnBox.style.display = "none";
			warnBox.innerHTML = "";
		}
	}

	function formatBytes(n: number): string {
		if (n < 1024) return `${n} B`;
		if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
		return `${(n / (1024 * 1024)).toFixed(2)} MB`;
	}

	async function buildBundle(): Promise<Uint8Array> {
		const entries: TarFileInput[] = [];
		for (const f of collected) {
			const buf = new Uint8Array(await f.file.arrayBuffer());
			entries.push({ name: f.path, data: buf });
		}
		return createTarGzip(entries);
	}

	async function submit(dryRun: boolean) {
		if (collected.length === 0) return;
		deployBtn.disabled = true;
		dryrunBtn.disabled = true;
		resultBox.innerHTML = "";
		try {
			const bundle = await buildBundle();
			const form = new FormData();
			// The cast works around a DOM lib typing mismatch between
			// nanotar's Uint8Array<ArrayBufferLike> return type and
			// BlobPart's Uint8Array<ArrayBuffer> expectation -- Blob accepts
			// any ArrayBufferView at runtime regardless.
			form.set("bundle", new Blob([bundle as unknown as BlobPart], { type: "application/gzip" }), "bundle.tar.gz");
			form.set("owner", ownerSelect.value);
			if (nameInput.value) form.set("name", nameInput.value);
			if (noteInput.value) form.set("note", noteInput.value);

			const resp = await fetch(`/api/v1/functions${dryRun ? "?dry_run=true" : ""}`, {
				method: "POST",
				body: form,
				credentials: "same-origin",
				headers: { "X-CSRF-Token": csrfToken() },
			});
			const body = await resp.json();
			if (!resp.ok) {
				resultBox.innerHTML = `<div class="error-box">${escapeHTML(body?.error?.message ?? `deploy failed (status ${resp.status})`)}</div>`;
				return;
			}
			const warnings: string[] = body.warnings ?? [];
			let html = "";
			if (warnings.length > 0) {
				html += `<div class="warn"><b>${ct("dryRunWarnings")}</b><ul>${warnings.map((w) => `<li>${escapeHTML(w)}</li>`).join("")}</ul></div>`;
			}
			if (dryRun) {
				html += `<div class="notice-box">${ct("dryRunSucceeded", { name: escapeHTML(body.manifest?.name ?? "") })}</div>`;
			} else {
				const owner = ownerSelect.value;
				const fnName = body.function?.name ?? nameInput.value;
				html += `<div class="notice-box">${ct("deploymentSucceeded")} <a href="/dashboard/functions/${encodeURIComponent(owner)}/${encodeURIComponent(fnName)}">${ct("viewFunction")}</a></div>`;
			}
			resultBox.innerHTML = html;
			if (!dryRun && resp.ok) {
				const owner = ownerSelect.value;
				const fnName = body.function?.name ?? nameInput.value;
				window.location.href = `/dashboard/functions/${encodeURIComponent(owner)}/${encodeURIComponent(fnName)}`;
			}
		} catch (e) {
			resultBox.innerHTML = `<div class="error-box">${escapeHTML(String(e))}</div>`;
		} finally {
			deployBtn.disabled = collected.length === 0;
			dryrunBtn.disabled = collected.length === 0;
		}
	}

	function escapeHTML(s: string): string {
		return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
	}

	deployBtn.addEventListener("click", () => submit(false));
	dryrunBtn.addEventListener("click", () => submit(true));
	setMode("folder");
	renderFiles();
}

initDeployForm();
