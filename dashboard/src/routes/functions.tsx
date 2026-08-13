// routes/functions.tsx: the function list (/), detail
// (/functions/{owner}/{name}), and every function-scoped mutation
// (rollback, delete, env set/delete) -- tmp/09-dashboard.md §9.5's first
// two screens. Mutations follow this app's uniform Post/Redirect/Get
// pattern: a plain HTML <form method="post"> to a route in this file, which
// calls env.INTERNAL_API (via c.var.api) and 303-redirects back with a
// flash message, so no client JS is needed for anything except copy
// buttons and confirm dialogs (see src/client/main.ts).
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Pill, Page, fmtBytes, fmtTime } from "../components/layout";
import { FetchPolicyGate, ExecutionLog, type PolicyLevel } from "../components/policy";
import { baseProps, flashFromQuery, redirectWithFlash } from "../render";
import { APIError } from "../api";
import type { FunctionDTO } from "../types";

export const functionsApp = new Hono<AppEnv>();

function CompatPill(props: { nodejs?: boolean }) {
	if (!props.nodejs) return null;
	return <Pill kind="node">nodejs</Pill>;
}

function OwnerTypePill(props: { ownerType: string }) {
	return props.ownerType === "workspace" ? <Pill kind="ws">workspace</Pill> : <Pill kind="pub">personal</Pill>;
}

// --- list ---
functionsApp.get("/", async (c) => {
	const api = c.var.api;
	let fns: FunctionDTO[] = [];
	let loadError = "";
	try {
		const res = await api.listFunctions();
		fns = res.functions;
	} catch (e) {
		loadError = e instanceof APIError ? e.message : String(e);
	}

	const props = await baseProps(api, c.var.caller, "functions", "関数");
	return c.html(
		<Page {...props} crumb={<>組織: <b>{props.orgName}</b></>} flash={flashFromQuery((k) => c.req.query(k))}>
			<div class="toolbar">
				<input class="search" type="text" placeholder="⌕ 名前・オーナーで検索…" data-fn-filter />
				<a class="btn" href="/dashboard/functions/new">
					＋ 新規デプロイ
				</a>
			</div>
			{loadError ? (
				<div class="error-box">関数一覧の取得に失敗しました: {loadError}</div>
			) : fns.length === 0 ? (
				<div class="empty">まだ関数がありません。「新規デプロイ」から最初の関数をデプロイしてください。</div>
			) : (
				<table class="fn" data-fn-table>
					<tr>
						<th>関数</th>
						<th>所有者種別</th>
						<th>更新</th>
						<th></th>
					</tr>
					{fns.map((fn) => (
						<tr data-fn-row data-fn-key={`${fn.owner ?? ""} ${fn.name}`.toLowerCase()}>
							<td>
								<span class="fname">{fn.name}</span> <span class="owner">/ {fn.owner ?? "?"}</span>
							</td>
							<td>
								<OwnerTypePill ownerType={fn.owner_type} />
							</td>
							<td class="owner">{fmtTime(fn.updated_at)}</td>
							<td>
								<a class="link" href={`/dashboard/functions/${encodeURIComponent(fn.owner ?? "")}/${encodeURIComponent(fn.name)}`}>
									詳細
								</a>
							</td>
						</tr>
					))}
				</table>
			)}
		</Page>,
	);
});

// --- detail ---
functionsApp.get("/functions/:owner/:name", async (c) => {
	const { owner, name } = c.req.param();
	const api = c.var.api;
	let fn: FunctionDTO;
	try {
		fn = await api.getFunction(owner, name);
	} catch (e) {
		const props = await baseProps(api, c.var.caller, "functions", "関数が見つかりません");
		const message = e instanceof APIError ? e.message : String(e);
		return c.html(
			<Page {...props} crumb={<>関数 / {owner} / {name}</>}>
				<div class="error-box">{message}</div>
			</Page>,
			e instanceof APIError ? (e.status as any) : 500,
		);
	}

	let versions: Awaited<ReturnType<typeof api.listVersions>>["versions"] = [];
	try {
		versions = (await api.listVersions(owner, name)).versions;
	} catch {
		// Non-fatal: the version table just renders empty.
	}

	const manifest = fn.active_version?.manifest;
	const levels: PolicyLevel[] = [];
	if (fn.fetch_policy_levels) {
		levels.push({ label: "組織", sub: c.var.caller.role === "admin" ? "" : "", policy: fn.fetch_policy_levels.organization });
		if (fn.fetch_policy_levels.workspace) {
			levels.push({ label: "ワークスペース", sub: fn.owner ?? "", policy: fn.fetch_policy_levels.workspace });
		}
	}
	levels.push({ label: "manifest", sub: "funcbox.yaml", policy: manifest?.permissions.fetch ?? { mode: "deny" } });

	const invokeURL = `${new URL(c.req.url).origin}/${owner}/${name}`;
	const props = await baseProps(api, c.var.caller, "functions", fn.name);

	return c.html(
		<Page
			{...props}
			crumb={
				<>
					関数 / {owner} / <b>{fn.name}</b>
				</>
			}
			flash={flashFromQuery((k) => c.req.query(k))}
		>
			<h4>
				{fn.name} <OwnerTypePill ownerType={fn.owner_type} /> <CompatPill nodejs={manifest?.compat.nodejs} />
			</h4>
			<div class="urlrow">
				<span class="urlbox mono" id="fn-invoke-url">
					{invokeURL}
				</span>
				<button class="copy" type="button" data-copy-target="fn-invoke-url">
					copy
				</button>
				{fn.active_version ? (
					<span class="owner" style="font-size:11.5px">
						{fn.active_version.id.slice(0, 8)}… がアクティブ
					</span>
				) : (
					<span class="owner" style="font-size:11.5px">
						アクティブなバージョンがありません
					</span>
				)}
			</div>

			<div class="cols">
				<div>
					<FetchPolicyGate levels={levels} />
					<div class="card" style="margin-top:14px">
						<h5>実行ログ</h5>
						<ExecutionLog />
					</div>
				</div>
				<div>
					<div class="card">
						<h5>バージョン</h5>
						{versions.length === 0 ? (
							<div class="empty">バージョンがありません</div>
						) : (
							<table class="vers">
								{versions.map((v) => (
									<tr>
										<td class="vtag">{v.id.slice(0, 8)}…</td>
										<td class="mono owner">{fmtBytes(v.unpacked_size)}</td>
										<td>{fn.active_version_id === v.id ? <span class="active-b">ACTIVE</span> : null}</td>
										<td class="owner">{fmtTime(v.created_at)}</td>
										<td>
											{fn.active_version_id !== v.id ? (
												<form method="post" action={`/dashboard/functions/${owner}/${name}/versions/${v.id}/activate`} data-confirm="このバージョンをアクティブにしますか?（ロールバック）">
													<button class="link" type="submit">
														rollback
													</button>
												</form>
											) : null}
										</td>
									</tr>
								))}
							</table>
						)}
					</div>
					<div class="card">
						<h5>環境変数</h5>
						{!manifest?.env || manifest.env.length === 0 ? (
							<div class="empty">manifest で env が宣言されていません</div>
						) : (
							<table class="vers">
								{manifest.env.map((key) => (
									<tr>
										<td class="mono">{key}</td>
										<td>
											<form method="post" action={`/dashboard/functions/${owner}/${name}/env/${encodeURIComponent(key)}`} class="row">
												<input type="text" name="value" placeholder="新しい値" style="width:140px" />
												<button class="link" type="submit">
													更新
												</button>
											</form>
										</td>
										<td>
											<form method="post" action={`/dashboard/functions/${owner}/${name}/env/${encodeURIComponent(key)}/delete`} data-confirm={`env ${key} を削除しますか?`}>
												<button class="link danger" type="submit">
													削除
												</button>
											</form>
										</td>
									</tr>
								))}
							</table>
						)}
						<div style="font-size:11px;margin-top:8px" class="owner">
							manifest で宣言されたキーのみ実行時に渡されます。値は暗号化されて保存され、一覧表示はできません。
						</div>
					</div>
					<div class="card" style="margin-top:14px">
						<h5>危険な操作</h5>
						<form method="post" action={`/dashboard/functions/${owner}/${name}/delete`} data-confirm={`関数 ${name} を削除しますか? この操作は取り消せません。`}>
							<button class="btn danger" type="submit">
								この関数を削除
							</button>
						</form>
					</div>
				</div>
			</div>
		</Page>,
	);
});

// --- mutations (Post/Redirect/Get) ---
functionsApp.post("/functions/:owner/:name/versions/:id/activate", async (c) => {
	const { owner, name, id } = c.req.param();
	const back = `/dashboard/functions/${owner}/${name}`;
	try {
		await c.var.api.activateVersion(owner, name, id);
		return c.redirect(redirectWithFlash(back, "notice", "ロールバックしました"), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

functionsApp.post("/functions/:owner/:name/env/:key", async (c) => {
	const { owner, name, key } = c.req.param();
	const back = `/dashboard/functions/${owner}/${name}`;
	const body = await c.req.parseBody();
	const value = typeof body.value === "string" ? body.value : "";
	if (!value) {
		return c.redirect(redirectWithFlash(back, "error", "空の値は設定できません（削除するには「削除」ボタンを使用してください）"), 303);
	}
	try {
		await c.var.api.setEnv(owner, name, key, value);
		return c.redirect(redirectWithFlash(back, "notice", `${key} を更新しました`), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

functionsApp.post("/functions/:owner/:name/env/:key/delete", async (c) => {
	const { owner, name, key } = c.req.param();
	const back = `/dashboard/functions/${owner}/${name}`;
	try {
		await c.var.api.deleteEnv(owner, name, key);
		return c.redirect(redirectWithFlash(back, "notice", `${key} を削除しました`), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

functionsApp.post("/functions/:owner/:name/delete", async (c) => {
	const { owner, name } = c.req.param();
	try {
		await c.var.api.deleteFunction(owner, name);
		return c.redirect(redirectWithFlash("/dashboard", "notice", `${name} を削除しました`), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(`/dashboard/functions/${owner}/${name}`, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
