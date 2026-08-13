// appenv.ts: the Hono generic env shape shared by server.tsx and every
// route module -- c.env is the cfworkers binding object (just
// INTERNAL_API), c.var carries the per-request API client and decoded
// caller identity that server.tsx's top-level middleware sets up once.
import type { Env, API } from "./api";
import type { CallerClaims } from "./identity";

export interface AppVariables {
	api: API;
	caller: CallerClaims;
	callerToken: string;
}

export interface AppEnv {
	Bindings: Env;
	Variables: AppVariables;
}
