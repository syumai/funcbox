CREATE TABLE invoke_auth_codes (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  function_id TEXT NOT NULL REFERENCES functions(id) ON DELETE CASCADE,
  host        TEXT NOT NULL,
  return_to   TEXT NOT NULL,
  expires_at  BIGINT NOT NULL,
  created_at  BIGINT NOT NULL
);

CREATE INDEX idx_invoke_auth_codes_expires_at ON invoke_auth_codes(expires_at);
