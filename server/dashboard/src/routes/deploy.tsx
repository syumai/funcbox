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
	const props = await baseProps(api, c.var.caller, "functions", "New deployment");
	const t = props.t;

	let owners: { value: string; label: string }[] = [];
	try {
		const me = await api.me();
		if (me.handle) owners.push({ value: me.handle, label: `${me.handle} (${t("personal")})` });
		for (const ws of me.workspaces) owners.push({ value: ws.handle, label: `${ws.handle} (${t("workspace")})` });
	} catch (e) {
		return c.html(
			<Page {...props} crumb={<>{t("function")} / <b>{t("new_deploy")}</b></>}>
				<div class="error-box">{t("owners_failed", { error: e instanceof APIError ? e.message : String(e) })}</div>
			</Page>,
		);
	}

	return c.html(
		<Page {...props} crumb={<>{t("function")} / <b>{t("new_deploy")}</b></>} maxWidth={640}>
			<div data-deploy-root class="stack">
				<div class="field">
					<label for="deploy-owner">{t("deploy_owner")}</label>
					<select id="deploy-owner" data-owner-select>
						{owners.map((o) => (
							<option value={o.value}>{o.label}</option>
						))}
					</select>
				</div>
				<div class="field">
					<label for="deploy-name">{t("function_name")}</label>
					<input id="deploy-name" type="text" data-name-input placeholder={t("function_name_example")} />
				</div>
				<div class="field">
					<label for="deploy-note">{t("deployment_note")}</label>
					<input id="deploy-note" type="text" data-note-input placeholder={t("deployment_note_example")} />
				</div>

				<div class="mode">
					<button type="button" class="on" data-mode="folder">
						{t("select_folder")}
					</button>
					<button type="button" data-mode="files">
						{t("select_files")}
					</button>
				</div>
				<div class="drop" data-drop-zone>
					{t("drop_project")}
					<br />
					<b>{t("or_click")}</b>
					<br />
					<span style="font-size:11px">{t("browser_tar")}</span>
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
					{t("unpacked", { current: "0 B", max: "5 MB" })}
				</div>
				<div class="warn" data-warn style="display:none"></div>
				<div data-result></div>
				<div style="margin-top:16px;display:flex;gap:10px">
					<button class="btn" data-btn-deploy disabled>
						{t("deploy")}
					</button>
					<button class="btn ghost" data-btn-dryrun disabled>
						{t("run_dry_run")}
					</button>
				</div>
			</div>
		</Page>,
	);
});
