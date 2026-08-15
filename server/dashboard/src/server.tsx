// §9.2): a Hono app, `export default app`, run inside funcbox's OWN
// runtime (internal/dashboard hosts it exactly like an enginepool.Pool
// would host a user function -- see that package's doc comment) rather
// than Node. Every route reads/writes the management API exclusively
// through internalAPI, imported from "funcbox:internal" (api.ts) -- there
// is no other privileged capability available to this app.
import { Hono } from "hono";
import type { AppEnv } from "./appenv";
import { API } from "./api";
import { decodeCallerToken } from "./identity";
import { functionsApp } from "./routes/functions";
import { deployApp } from "./routes/deploy";
import { workspacesApp } from "./routes/workspaces";
import { orgApp } from "./routes/org";
import { orgUsersApp } from "./routes/orgUsers";
import { orgAuditApp } from "./routes/orgAudit";
import { settingsApp } from "./routes/settings";
import { cliAuthApp } from "./routes/cliAuth";

const app = new Hono<AppEnv>().basePath("/dashboard");

// Every request arrives already authenticated: internal/dashboard's Go
// hosting layer checks the session cookie and redirects to /auth/login
// sets X-Funcbox-Caller-Token itself (stripping any client-supplied value
// first, mirroring internal/invoke's X-Funcbox-* handling) -- so this
// middleware only ever decodes a token this app's own host produced.
app.use("*", async (c, next) => {
	const token = c.req.header("X-Funcbox-Caller-Token") ?? "";
	const caller = decodeCallerToken(token);
	c.set("callerToken", token);
	c.set("caller", caller);
	c.set("api", new API(token));
	await next();
});

app.route("/", functionsApp);
app.route("/", deployApp);
app.route("/", workspacesApp);
app.route("/", orgApp);
app.route("/", orgUsersApp);
app.route("/", orgAuditApp);
app.route("/", settingsApp);
app.route("/", cliAuthApp);

app.notFound((c) => c.text("funcbox dashboard: not found", 404));
app.onError((err, c) => {
	console.error("dashboard: unhandled error", err);
	return c.text(`funcbox dashboard: internal error (${err instanceof Error ? err.message : String(err)})`, 500);
});

export default app;
