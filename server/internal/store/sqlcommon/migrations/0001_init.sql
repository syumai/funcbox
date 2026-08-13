-- (Unix seconds, UTC) added to every table.

CREATE TABLE organizations (
  id           TEXT PRIMARY KEY,          -- always 'org'
  name         TEXT NOT NULL,
  settings     TEXT NOT NULL DEFAULT '{}', -- JSON
  settings_gen INTEGER NOT NULL DEFAULT 1,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

CREATE TABLE login_rules (
  id         TEXT PRIMARY KEY,
  ord        INTEGER NOT NULL,
  rule_type  TEXT NOT NULL,               -- email_domain | email_exact | email_glob | default
  value      TEXT NOT NULL DEFAULT '',
  action     TEXT NOT NULL,               -- allow | deny
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE users (
  id         TEXT PRIMARY KEY,
  google_sub TEXT NOT NULL UNIQUE,
  email      TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'member', -- admin | member
  disabled   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Public User IDs. Legacy databases may contain workspace rows; current
-- code ignores them and uses immutable workspace IDs instead.
CREATE TABLE handles (
  handle     TEXT PRIMARY KEY,            -- lowercase DNS-label form
  owner_type TEXT NOT NULL,               -- user | workspace
  owner_id   TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE workspaces (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,             -- display name, distinct from handle
  settings     TEXT NOT NULL DEFAULT '{}', -- JSON
  settings_gen INTEGER NOT NULL DEFAULT 1,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

CREATE TABLE workspace_members (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  user_id      TEXT NOT NULL REFERENCES users(id),
  role         TEXT NOT NULL,             -- admin | member
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
);

CREATE INDEX idx_workspace_members_user_id ON workspace_members(user_id);

CREATE TABLE functions (
  id                TEXT PRIMARY KEY,
  owner_type        TEXT NOT NULL,        -- user | workspace
  owner_id          TEXT NOT NULL,
  name              TEXT NOT NULL,        -- DNS-label form
  description       TEXT NOT NULL DEFAULT '',
  active_version_id TEXT,                 -- NULL = not yet deployed
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL,
  UNIQUE (owner_type, owner_id, name)
);

CREATE INDEX idx_functions_owner ON functions(owner_type, owner_id);

CREATE TABLE function_versions (
  id            TEXT PRIMARY KEY,
  function_id   TEXT NOT NULL REFERENCES functions(id),
  manifest      TEXT NOT NULL,            -- normalized manifest JSON
  main_path     TEXT NOT NULL,
  bundle_hash   TEXT NOT NULL,            -- sha256 hex of canonical tar.gz (blob store key)
  bundle_size   INTEGER NOT NULL,         -- compressed size in bytes
  unpacked_size INTEGER NOT NULL,         -- unpacked size in bytes
  files         TEXT NOT NULL,            -- JSON: [{path, size}, ...]
  created_by    TEXT NOT NULL REFERENCES users(id),
  note          TEXT NOT NULL DEFAULT '', -- deploy comment
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE INDEX idx_function_versions_function_id ON function_versions(function_id, created_at DESC);

-- Environment variables are bound to a function (not a version) so secret
-- rotation doesn't require a redeploy. Values are stored encrypted.
CREATE TABLE env_vars (
  function_id TEXT NOT NULL REFERENCES functions(id),
  key         TEXT NOT NULL,
  value_enc   BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (function_id, key)
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,            -- hash of the session token
  user_id    TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);

CREATE TABLE api_tokens (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL UNIQUE,        -- sha256 hex
  name       TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX idx_api_tokens_user_id ON api_tokens(user_id);

CREATE TABLE audit_logs (
  id         TEXT PRIMARY KEY,            -- ULID; also the sort key / pagination cursor
  actor_id   TEXT NOT NULL,
  action     TEXT NOT NULL,               -- e.g. 'function.deploy', 'org.settings.update'
  target     TEXT NOT NULL,               -- e.g. 'function:01H...'
  detail     TEXT NOT NULL DEFAULT '{}',  -- JSON
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
