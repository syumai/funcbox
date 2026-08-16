-- server/internal/oauth's OAuth 2.1 authorization server (MCP
-- Authorization spec): three new tables, one per entity that flow needs
-- beyond the pre-existing users/sessions.
--
--   oauth_clients: dynamically registered public clients (RFC 7591 DCR,
--   POST /oauth/register). No secret column -- MCP clients authenticate
--   via PKCE only (RFC 7636), never a client_secret. redirect_uris is a
--   JSON array; GET /oauth/authorize's redirect_uri must match one entry
--   EXACTLY.
--
--   oauth_auth_codes: the short-lived, single-use PKCE authorization code
--   the consent decision issues and POST /oauth/token's authorization_code
--   grant consumes. Same shape as cli_auth_codes (0010_cli_auth.sql) plus
--   the client_id/redirect_uri/resource bindings a standards-compliant
--   authorization code needs.
--
--   oauth_grants: long-lived refresh-token grants, minted alongside every
--   access token and renewed (never rotated) by the refresh_token grant.
--   Same sliding-expiry shape as cli_credentials: last_used_at is null
--   until first use.
CREATE TABLE oauth_clients (
	id            TEXT PRIMARY KEY,
	name          TEXT NOT NULL,
	redirect_uris TEXT NOT NULL, -- JSON array of strings
	created_at    INTEGER NOT NULL,
	updated_at    INTEGER NOT NULL
);

CREATE TABLE oauth_auth_codes (
	id           TEXT PRIMARY KEY, -- sha256 hex of the raw one-time code
	user_id      TEXT NOT NULL REFERENCES users(id),
	client_id    TEXT NOT NULL REFERENCES oauth_clients(id),
	redirect_uri TEXT NOT NULL,
	challenge    TEXT NOT NULL,
	resource     TEXT NOT NULL DEFAULT '',
	expires_at   INTEGER NOT NULL,
	created_at   INTEGER NOT NULL
);

CREATE TABLE oauth_grants (
	id           TEXT PRIMARY KEY,
	user_id      TEXT NOT NULL REFERENCES users(id),
	client_id    TEXT NOT NULL REFERENCES oauth_clients(id),
	secret_hash  TEXT NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL,
	last_used_at INTEGER
);

CREATE INDEX idx_oauth_grants_user_id ON oauth_grants(user_id);
