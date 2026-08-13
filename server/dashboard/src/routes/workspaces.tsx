// routes/workspaces.tsx: /workspaces (list + create) and
// /workspaces/{id} (detail: members, fetch policy, visibility ceiling,
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Page } from "../components/layout";
import { baseProps, flashFromQuery, localizedMessage, redirectWithFlash } from "../render";
import { APIError } from "../api";

export const workspacesApp = new Hono<AppEnv>();

workspacesApp.get("/workspaces", async (c) => {
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "workspaces", "Workspaces");
	const t = props.t;
	let workspaces: Awaited<ReturnType<typeof api.listWorkspaces>>["workspaces"] = [];
	let loadError = "";
	try {
		workspaces = (await api.listWorkspaces()).workspaces;
	} catch (e) {
		loadError = e instanceof APIError ? e.message : String(e);
	}

	return c.html(
		<Page {...props} crumb={<>{t("organization_colon")} <b>{props.orgName}</b></>} flash={flashFromQuery((k) => c.req.query(k), props.language)}>
			<form method="post" action="/dashboard/workspaces" class="toolbar">
				<input type="text" name="name" placeholder={t("workspace_name_required")} required style="width:240px" />
				<button class="btn" type="submit">
					＋ {t("create_workspace")}
				</button>
			</form>
			{loadError ? (
				<div class="error-box">{loadError}</div>
			) : workspaces.length === 0 ? (
				<div class="empty">{t("workspaces_empty")}</div>
			) : (
				<table class="fn">
					<tr>
						<th>{t("workspace")}</th>
						<th>{t("fetch_policy_mode")}</th>
						<th>{t("created")}</th>
						<th></th>
					</tr>
					{workspaces.map((ws) => (
						<tr>
							<td>
								<span class="fname">{ws.name}</span>
							</td>
							<td class="owner mono">{ws.settings.fetch_policy.mode}</td>
							<td class="owner">{new Date(ws.created_at).toLocaleDateString()}</td>
							<td>
								<a class="link" href={`/dashboard/workspaces/${encodeURIComponent(ws.id)}`}>
									{t("details")}
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
	const name = typeof body.name === "string" ? body.name : "";
	try {
		const workspace = await c.var.api.createWorkspace(name);
		return c.redirect(redirectWithFlash("/dashboard/workspaces", "notice", await localizedMessage(c.var.api, "workspace_created_name", { name: workspace.name })), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash("/dashboard/workspaces", "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

workspacesApp.get("/workspaces/:workspaceID", async (c) => {
	const { workspaceID } = c.req.param();
	const api = c.var.api;
	const props = await baseProps(api, c.var.caller, "workspaces", workspaceID);
	const t = props.t;
	try {
		const ws = await api.getWorkspace(workspaceID);
		return c.html(
			<Page {...props} crumb={<>{t("workspace")} / <b>{ws.name}</b></>} flash={flashFromQuery((k) => c.req.query(k), props.language)}>
				<div class="cols">
					<div class="card">
						<h5>{t("workspace_settings")}</h5>
						<form method="post" action={`/dashboard/workspaces/${workspaceID}/settings`} class="stack">
							<div class="field">
								<label>{t("fetch_policy_mode")}</label>
								<select name="fetch_mode">
									{["deny", "allowlist", "allow-all"].map((m) => (
										<option value={m} selected={m === ws.settings.fetch_policy.mode}>
											{m}
										</option>
									))}
								</select>
							</div>
							<div class="field">
								<label>{t("allowlist_help")}</label>
								<input type="text" name="fetch_allow" value={(ws.settings.fetch_policy.allow ?? []).join(", ")} style="width:100%" />
							</div>
							<div class="field">
								<label>{t("max_visibility_help")}</label>
								<select name="max_visibility">
									<option value="" selected={!ws.settings.max_visibility}>
										{t("inherit_org_limit")}
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
									<input type="checkbox" name="member_can_deploy" checked={ws.settings.member_can_deploy} /> {t("members_can_deploy")}
								</label>
							</div>
							<button class="btn" type="submit">
								{t("save")}
							</button>
						</form>
					</div>
					<div class="card">
						<h5>{t("members", { count: (ws.members ?? []).length })}</h5>
						<table class="vers">
							{(ws.members ?? []).map((m) => (
								<tr>
									<td class="mono owner">{m.user_id}</td>
									<td>
										<span class={m.role === "admin" ? "pill admin" : "pill member"}>{m.role}</span>
									</td>
									<td>
										<form method="post" action={`/dashboard/workspaces/${workspaceID}/members/${m.user_id}/delete`} data-confirm={t("remove_member_confirm")}>
											<button class="link danger" type="submit">
												{t("delete")}
											</button>
										</form>
									</td>
								</tr>
							))}
						</table>
						<form method="post" action={`/dashboard/workspaces/${workspaceID}/members`} class="row" style="margin-top:10px">
							<input type="text" name="user_id" placeholder={t("user_id")} style="width:140px" required />
							<select name="role">
								<option value="member">member</option>
								<option value="admin">admin</option>
							</select>
							<button class="btn ghost" type="submit">
								{t("add_update")}
							</button>
						</form>
						<div class="hint">
							{t("user_id_help")}
						</div>
					</div>
				</div>
			</Page>,
		);
	} catch (e) {
		return c.html(
			<Page {...props} crumb={<>{t("workspace")} / {workspaceID}</>}>
				<div class="error-box">{e instanceof APIError ? e.message : String(e)}</div>
			</Page>,
			e instanceof APIError ? (e.status as any) : 500,
		);
	}
});

workspacesApp.post("/workspaces/:workspaceID/settings", async (c) => {
	const { workspaceID } = c.req.param();
	const back = `/dashboard/workspaces/${workspaceID}`;
	const body = await c.req.parseBody();
	const allowRaw = typeof body.fetch_allow === "string" ? body.fetch_allow : "";
	const allow = allowRaw
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
	try {
		await c.var.api.patchWorkspace(workspaceID, {
			fetch_policy: { mode: String(body.fetch_mode ?? "deny"), allow },
			max_visibility: typeof body.max_visibility === "string" ? body.max_visibility : "",
			member_can_deploy: body.member_can_deploy === "on" || body.member_can_deploy === "true",
		});
		return c.redirect(redirectWithFlash(back, "notice", await localizedMessage(c.var.api, "settings_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

workspacesApp.post("/workspaces/:workspaceID/members", async (c) => {
	const { workspaceID } = c.req.param();
	const back = `/dashboard/workspaces/${workspaceID}`;
	const body = await c.req.parseBody();
	const userID = typeof body.user_id === "string" ? body.user_id : "";
	const role = typeof body.role === "string" ? body.role : "member";
	try {
		await c.var.api.putWorkspaceMember(workspaceID, userID, role);
		return c.redirect(redirectWithFlash(back, "notice", await localizedMessage(c.var.api, "member_updated")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

workspacesApp.post("/workspaces/:workspaceID/members/:userID/delete", async (c) => {
	const { workspaceID, userID } = c.req.param();
	const back = `/dashboard/workspaces/${workspaceID}`;
	try {
		await c.var.api.deleteWorkspaceMember(workspaceID, userID);
		return c.redirect(redirectWithFlash(back, "notice", await localizedMessage(c.var.api, "member_deleted")), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
