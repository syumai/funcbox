// routes/deploy.tsx: /functions/new (tmp/09-dashboard.md §9.5 "アップロード
// UI"). This route only renders the page shell and the owner choices; the
// entire upload flow (file/folder picker, drag & drop, nanotar tar.gz
// creation, the 5MB pre-check gauge, and the dry-run/deploy POST itself)
// lives in src/client/main.ts, since it fundamentally has to run in the
// real browser (File/DataTransfer/CompressionStream APIs, a direct
// multipart POST with the browser's own session cookie) rather than as an
// env.INTERNAL_API call -- see api.ts's doc comment for why INTERNAL_API is
// SSR-data-access-only.
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page } from "../components/layout";
import { baseProps } from "../render";
import { APIError } from "../api";

export const deployApp = new Hono<AppEnv>();

deployApp.get("/functions/new", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "functions", "新規デプロイ");

	let owners: { value: string; label: string }[] = [];
	try {
		const me = await api.me();
		if (me.handle) owners.push({ value: me.handle, label: `${me.handle} (個人)` });
		for (const ws of me.workspaces) owners.push({ value: ws.handle, label: `${ws.handle} (ワークスペース)` });
	} catch (e) {
		return c.html(
			<Page {...props} crumb={<>関数 / <b>新規デプロイ</b></>}>
				<div class="error-box">オーナー一覧の取得に失敗しました: {e instanceof APIError ? e.message : String(e)}</div>
			</Page>,
		);
	}

	return c.html(
		<Page {...props} crumb={<>関数 / <b>新規デプロイ</b></>} maxWidth={640}>
			<div data-deploy-root class="stack">
				<div class="field">
					<label for="deploy-owner">デプロイ先オーナー</label>
					<select id="deploy-owner" data-owner-select>
						{owners.map((o) => (
							<option value={o.value}>{o.label}</option>
						))}
					</select>
				</div>
				<div class="field">
					<label for="deploy-name">関数名（省略時は funcbox.yaml の name）</label>
					<input id="deploy-name" type="text" data-name-input placeholder="例: report" />
				</div>
				<div class="field">
					<label for="deploy-note">デプロイメモ（任意）</label>
					<input id="deploy-note" type="text" data-note-input placeholder="例: fix warehouse timeout" />
				</div>

				<div class="mode">
					<button type="button" class="on" data-mode="folder">
						フォルダを選択
					</button>
					<button type="button" data-mode="files">
						複数ファイルを選択
					</button>
				</div>
				<div class="drop" data-drop-zone>
					プロジェクトフォルダをここにドロップ
					<br />
					<b>または クリックして選択</b>
					<br />
					<span style="font-size:11px">ブラウザ内で tar.gz 化して送信します（nanotar）。zip は非対応です</span>
				</div>
				{/* Hidden native pickers; main.ts drives both from the drop
				    zone's click handler and mode toggle. */}
				<input type="file" data-input-folder webkitdirectory multiple style="display:none" />
				<input type="file" data-input-files multiple style="display:none" />
				<div class="files" data-files-list></div>
				<div class="gauge" data-gauge>
					<i></i>
				</div>
				<div class="gnote" data-gnote>
					展開後 0 B / 5 MB
				</div>
				<div class="warn" data-warn style="display:none"></div>
				<div data-result></div>
				<div style="margin-top:16px;display:flex;gap:10px">
					<button class="btn" data-btn-deploy disabled>
						デプロイ
					</button>
					<button class="btn ghost" data-btn-dryrun disabled>
						dry-run を実行
					</button>
				</div>
			</div>
		</Page>,
	);
});
