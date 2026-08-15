// routes/functions.tsx: the function list (/), detail
// (/functions/{owner}/{name}), and every function-scoped mutation
// two screens. Mutations follow this app's uniform Post/Redirect/Get
// pattern: a plain HTML <form method="post"> to a route in this file, which
// calls internalAPI (via c.var.api) and 303-redirects back with a
// flash message, so no client JS is needed for anything except copy
// buttons and confirm dialogs (see src/client/main.ts).
import { Hono } from "hono";
import type { AppEnv } from "../appenv";
import { Pill, Page, fmtBytes, fmtTime } from "../components/layout";
import { FetchPolicyGate, ExecutionLog, type PolicyLevel } from "../components/policy";
import { baseProps, flashFromQuery, localizedMessage, redirectWithFlash } from "../render";
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

	const props = await baseProps(api, c.var.caller, "functions", "Functions");
	const t = props.t;
	return c.html(
		<Page {...props} crumb={<>{t("organization_colon")} <b>{props.orgName}</b></>} flash={flashFromQuery((k) => c.req.query(k), props.language)}>
			<div class="toolbar">
				<input class="search" type="text" placeholder={t("search_functions")} data-fn-filter />
				<a class="btn" href="/dashboard/functions/new">
					＋ {t("new_deploy")}
				</a>
			</div>
			{loadError ? (
				<div class="error-box">{t("function_list_failed", { error: loadError })}</div>
			) : fns.length === 0 ? (
				<div class="empty">{t("no_functions")}</div>
			) : (
				<table class="fn" data-fn-table>
					<tr>
						<th>{t("function")}</th>
						<th>{t("owner_type")}</th>
						<th>{t("endpoint")}</th>
						<th>{t("updated")}</th>
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
							<td class="mono owner">
								{fn.url ? <a class="link" href={fn.url}>{fn.url}</a> : "-"}
							</td>
							<td class="owner">{fmtTime(fn.updated_at)}</td>
							<td>
								<a class="link" href={`/dashboard/functions/${encodeURIComponent(fn.owner ?? "")}/${encodeURIComponent(fn.name)}`}>
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

// --- detail ---
functionsApp.get("/functions/:owner/:name", async (c) => {
	const { owner, name } = c.req.param();
	const api = c.var.api;
	let fn: FunctionDTO;
	try {
		fn = await api.getFunction(owner, name);
	} catch (e) {
		const props = await baseProps(api, c.var.caller, "functions", "Function not found");
		const t = props.t;
		const message = e instanceof APIError ? e.message : String(e);
		return c.html(
			<Page {...props} crumb={<>{t("function")} / {owner} / {name}</>}>
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

	let logs: Awaited<ReturnType<typeof api.listLogs>>["logs"] = [];
	try {
		logs = (await api.listLogs(owner, name, 20)).logs;
	} catch {
		// Non-fatal: the execution-log panel just renders empty.
	}

	const manifest = fn.active_version?.manifest;
	const levels: PolicyLevel[] = [];
	if (fn.fetch_policy_levels) {
		levels.push({ label: "Organization", sub: c.var.caller.role === "admin" ? "" : "", policy: fn.fetch_policy_levels.organization });
		if (fn.fetch_policy_levels.workspace) {
			levels.push({ label: "Workspace", sub: fn.owner ?? "", policy: fn.fetch_policy_levels.workspace });
		}
	}
	levels.push({ label: "manifest", sub: "funcbox.yaml", policy: manifest?.permissions.fetch ?? { mode: "deny" } });

	const invokeURL = fn.url;
	const props = await baseProps(api, c.var.caller, "functions", fn.name);
	const t = props.t;

	return c.html(
		<Page
			{...props}
			crumb={
				<>
					{t("function")} / {owner} / <b>{fn.name}</b>
				</>
			}
			titleExtra={
				<>
					<OwnerTypePill ownerType={fn.owner_type} /> <CompatPill nodejs={manifest?.compat.nodejs} />
				</>
			}
			flash={flashFromQuery((k) => c.req.query(k), props.language)}
		>
			{invokeURL ? <div class="urlrow">
				<span class="urlbox mono" id="fn-invoke-url">
					{invokeURL}
				</span>
				<button class="copy" type="button" data-copy-target="fn-invoke-url">
					copy
				</button>
				{fn.active_version ? (
					<span class="owner" style="font-size:11.5px">
						{t("active_version", { id: fn.active_version.id.slice(0, 8) })}
					</span>
				) : (
					<span class="owner" style="font-size:11.5px">
						{t("no_active_version")}
					</span>
				)}
			</div> : null}

			<div class="cols">
				<div>
					<FetchPolicyGate levels={levels} t={t} />
					<div class="card" style="margin-top:14px">
						<h5>{t("execution_logs")}</h5>
						<ExecutionLog logs={logs} t={t} />
					</div>
				</div>
				<div>
					<div class="card">
						<h5>{t("versions")}</h5>
						{versions.length === 0 ? (
							<div class="empty">{t("no_versions")}</div>
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
												<form method="post" action={`/dashboard/functions/${owner}/${name}/versions/${v.id}/activate`} data-confirm={t("rollback_confirm")}>
													<button class="link" type="submit">
														{t("rollback")}
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
						<h5>{t("environment_variables")}</h5>
						{!manifest?.env || manifest.env.length === 0 ? (
							<div class="empty">{t("no_env")}</div>
						) : (
							<table class="vers">
								{manifest.env.map((key) => (
									<tr>
										<td class="mono">{key}</td>
										<td>
											<form method="post" action={`/dashboard/functions/${owner}/${name}/env/${encodeURIComponent(key)}`} class="row">
												<input type="text" name="value" placeholder={t("new_value")} style="width:140px" />
												<button class="link" type="submit">
													{t("update")}
												</button>
											</form>
										</td>
										<td>
											<form method="post" action={`/dashboard/functions/${owner}/${name}/env/${encodeURIComponent(key)}/delete`} data-confirm={t("delete_function_confirm", { name: `env ${key}` })}>
												<button class="link danger" type="submit">
													{t("delete")}
												</button>
											</form>
										</td>
									</tr>
								))}
							</table>
						)}
						<div style="font-size:11px;margin-top:8px" class="owner">
							{t("env_note")}
						</div>
					</div>
					<div class="card" style="margin-top:14px">
						<h5>{t("danger_zone")}</h5>
						<form method="post" action={`/dashboard/functions/${owner}/${name}/delete`} data-confirm={t("delete_function_confirm", { name })}>
							<button class="btn danger" type="submit">
								{t("delete_function")}
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
		return c.redirect(redirectWithFlash(back, "notice", await localizedMessage(c.var.api, "rollback_done")), 303);
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
		return c.redirect(redirectWithFlash(back, "error", await localizedMessage(c.var.api, "empty_value")), 303);
	}
	try {
		await c.var.api.setEnv(owner, name, key, value);
		return c.redirect(redirectWithFlash(back, "notice", await localizedMessage(c.var.api, "updated_key", { key })), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

functionsApp.post("/functions/:owner/:name/env/:key/delete", async (c) => {
	const { owner, name, key } = c.req.param();
	const back = `/dashboard/functions/${owner}/${name}`;
	try {
		await c.var.api.deleteEnv(owner, name, key);
		return c.redirect(redirectWithFlash(back, "notice", await localizedMessage(c.var.api, "deleted_key", { key })), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(back, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});

functionsApp.post("/functions/:owner/:name/delete", async (c) => {
	const { owner, name } = c.req.param();
	try {
		await c.var.api.deleteFunction(owner, name);
		return c.redirect(redirectWithFlash("/dashboard", "notice", await localizedMessage(c.var.api, "deleted_name", { name })), 303);
	} catch (e) {
		return c.redirect(redirectWithFlash(`/dashboard/functions/${owner}/${name}`, "error", e instanceof APIError ? e.message : String(e)), 303);
	}
});
