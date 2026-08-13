// routes/workspaces.tsx: /workspaces (list + create) and
// /workspaces/{handle} (detail: members, fetch policy, visibility ceiling,
// member_can_deploy -- tmp/09-dashboard.md §9.5).
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page } from "../components/layout";
import { baseProps, flashFromQuery, redirectWithFlash } from "../render";
import { APIError } from "../api";

export const workspacesApp = new Hono<AppEnv>();

workspacesApp.get("/workspaces", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "workspaces", "ワークスペース");
	let workspaces: Awaited<ReturnType<typeof api.listWorkspaces>>["workspaces"] = [];
	let loadError = "";
	try {
		workspaces = (await api.listWorkspaces()).workspaces;
	} catch (e) {
		loadError = e instanceof APIError ? e.message : String(e);
	}

	return c.html(
		<Page {...props} crumb={<>組織: <b>{props.orgName}</b></>} flash={flashFromQuery((k) => c.req.query(k))}>
			<form method="post" action="/dashboard/workspaces" class="toolbar">
				<input type="text" name="handle" placeholder="handle（例: data）" required style="width:160px" />
				<input type="text" name="name" placeholder="表示名（省略時は handle）" style="width:200px" />
				<button class="btn" type="submit">
					＋ ワークスペース作成
				</button>
			</form>
			{loadError ? (
				<div class="error-box">{loadError}</div>
			) : workspaces.length === 0 ? (
				<div class="empty">ワークスペースがありません</div>
			) : (
				<table class="fn">
					<tr>
						<th>ワークスペース</th>
						<th>fetch ポリシー</th>
						<th>作成</th>
						<th></th>
					</tr>
					{workspaces.map((ws) => (
						<tr>
							<td>
								<span class="fname">{ws.handle}</span> <span class="owner">{ws.name}</span>
							</td>
							<td class="owner mono">{ws.settings.fetch_policy.mode}</td>
							<td class="owner">{new Date(ws.created_at).toLocaleDateString()}</td>
							<td>
								<a class="link" href={`/dashboard/workspaces/${encodeURIComponent(ws.handle)}`}>
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

workspacesApp.post("/workspaces", async (c) => {
	const body = await c.req.parseBody();
	const handle = typeof body.handle === "string" ? body.handle : "";
	const name = typeof body.name === "string" ? body.name : "";
	try {
		await c.var.api.createWorkspace(handle, name);
		return c.redirect(redirectWithFlash("/dashboard/workspaces", "notice", `${handle} を作成しました`), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/workspaces", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

workspacesApp.get("/workspaces/:handle", async (c) => {
	const { handle } = c.req.param();
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "workspaces", handle);
	try {
		const ws = await api.getWorkspace(handle);
		return c.html(
			<Page {...props} crumb={<>ワークスペース / <b>{handle}</b></>} flash={flashFromQuery((k) => c.req.query(k))}>
				<div class="cols">
					<div class="card">
						<h5>設定</h5>
						<form method="post" action={`/dashboard/workspaces/${handle}/settings`} class="stack">
							<div class="field">
								<label>fetch ポリシー mode</label>
								<select name="fetch_mode">
									{["deny", "allowlist", "allow-all"].map((m) => (
										<option value={m} selected={m === ws.settings.fetch_policy.mode}>
											{m}
										</option>
									))}
								</select>
							</div>
							<div class="field">
								<label>allowlist（カンマ区切り、mode=allowlist の時のみ有効）</label>
								<input type="text" name="fetch_allow" value={(ws.settings.fetch_policy.allow ?? []).join(", ")} style="width:100%" />
							</div>
							<div class="field">
								<label>max_visibility（空欄 = 組織の上限をそのまま使う）</label>
								<select name="max_visibility">
									<option value="" selected={!ws.settings.max_visibility}>
										（未設定）
									</option>
									{["private", "workspace", "org", "public"].map((v) => (
										<option value={v} selected={v === ws.settings.max_visibility}>
											{v}
										</option>
									))}
								</select>
							</div>
							<div class="field">
								<label>
									<input type="checkbox" name="member_can_deploy" checked={ws.settings.member_can_deploy} /> メンバーがデプロイ可能
								</label>
							</div>
							<button class="btn" type="submit">
								保存
							</button>
						</form>
					</div>
					<div class="card">
						<h5>メンバー ({(ws.members ?? []).length})</h5>
						<table class="vers">
							{(ws.members ?? []).map((m) => (
								<tr>
									<td class="mono owner">{m.user_id}</td>
									<td>
										<span class={m.role === "admin" ? "pill admin" : "pill member"}>{m.role}</span>
									</td>
									<td>
										<form method="post" action={`/dashboard/workspaces/${handle}/members/${m.user_id}/delete`} data-confirm={`このメンバーを削除しますか?`}>
											<button class="link danger" type="submit">
												削除
											</button>
										</form>
									</td>
								</tr>
							))}
						</table>
						<form method="post" action={`/dashboard/workspaces/${handle}/members`} class="row" style="margin-top:10px">
							<input type="text" name="user_id" placeholder="ユーザーID" style="width:140px" required />
							<select name="role">
								<option value="member">member</option>
								<option value="admin">admin</option>
							</select>
							<button class="btn ghost" type="submit">
								追加/更新
							</button>
						</form>
						<div class="hint">
							ユーザーID は「組織設定 &gt; ユーザー」画面（admin のみ）で確認できます。
						</div>
					</div>
				</div>
			</Page>,
		);
	} catch (e) {
		return c.html(
			<Page {...props} crumb={<>ワークスペース / {handle}</>}>
				<div class="error-box">{e instanceof APIError ? e.message : String(e)}</div>
			</Page>,
			e instanceof APIError ? (e.status as any) : 500,
		);
	}
});

workspacesApp.post("/workspaces/:handle/settings", async (c) => {
	const { handle } = c.req.param();
	const back = `/dashboard/workspaces/${handle}`;
	const body = await c.req.parseBody();
	const allowRaw = typeof body.fetch_allow === "string" ? body.fetch_allow : "";
	const allow = allowRaw
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
	try {
		await c.var.api.patchWorkspace(handle, {
			fetch_policy: { mode: String(body.fetch_mode ?? "deny"), allow },
			max_visibility: typeof body.max_visibility === "string" ? body.max_visibility : "",
			member_can_deploy: body.member_can_deploy === "on" || body.member_can_deploy === "true",
		});
		return c.redirect(redirectWithFlash(back, "notice", "設定を更新しました"), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

workspacesApp.post("/workspaces/:handle/members", async (c) => {
	const { handle } = c.req.param();
	const back = `/dashboard/workspaces/${handle}`;
	const body = await c.req.parseBody();
	const userID = typeof body.user_id === "string" ? body.user_id : "";
	const role = typeof body.role === "string" ? body.role : "member";
	try {
		await c.var.api.putWorkspaceMember(handle, userID, role);
		return c.redirect(redirectWithFlash(back, "notice", "メンバーを更新しました"), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

workspacesApp.post("/workspaces/:handle/members/:userID/delete", async (c) => {
	const { handle, userID } = c.req.param();
	const back = `/dashboard/workspaces/${handle}`;
	try {
		await c.var.api.deleteWorkspaceMember(handle, userID);
		return c.redirect(redirectWithFlash(back, "notice", "メンバーを削除しました"), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
