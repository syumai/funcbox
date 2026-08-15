-- API keys are abolished: api_tokens (fbx_ tokens) is dropped entirely,
-- and replaced by two new tables backing the loopback+PKCE
-- `funcbox login` flow:
--
--   cli_credentials: the long-lived "fbxc_..." credential a device saves
--   after completing browser login. It carries no direct API access; it
--   only mints short-lived access tokens. last_used_at is null
--   until first use, giving the sliding 90-day expiry window a starting
--   point of created_at before that.
--
--   cli_auth_codes: the short-lived, single-use PKCE authorization code
--   the dashboard's approval page issues and POST /api/v1/cli/token
--   consumes to mint a cli_credentials row.
DROP TABLE api_tokens;

CREATE TABLE cli_credentials (
	id           TEXT PRIMARY KEY,
	user_id      TEXT NOT NULL REFERENCES users(id),
	name         TEXT NOT NULL,
	secret_hash  TEXT NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL,
	last_used_at INTEGER
);

CREATE INDEX idx_cli_credentials_user_id ON cli_credentials(user_id);

CREATE TABLE cli_auth_codes (
	id         TEXT PRIMARY KEY, -- sha256 hex of the raw one-time code
	user_id    TEXT NOT NULL REFERENCES users(id),
	name       TEXT NOT NULL,
	challenge  TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
