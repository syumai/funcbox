// appenv.ts: the Hono generic env shape shared by server.tsx and every
// route module -- c.var carries the per-request API client and decoded
// caller identity that server.tsx's top-level middleware sets up once.
// There are no Bindings anymore: the one privileged capability this app
// gets (internalAPI) is a plain top-level import from "funcbox:internal",
// not a per-request env binding -- see api.ts.
import type { API } from "./api";
import type { CallerClaims } from "./identity";

export interface AppVariables {
	api: API;
	caller: CallerClaims;
	callerToken: string;
}

export interface AppEnv {
	Variables: AppVariables;
}
