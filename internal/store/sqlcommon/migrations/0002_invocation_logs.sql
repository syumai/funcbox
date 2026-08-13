-- Per-invocation execution log (tmp/10-roadmap.md Phase 4). One row per
-- request; retention is enforced by a periodic DELETE sweep driven by the
-- organization's log_retention_days setting (see cmd/funcbox-server's gc /
-- cleanup goroutine), not by a ring buffer.
CREATE TABLE invocation_logs (
  id              TEXT PRIMARY KEY,       -- ULID; also the pagination cursor
  function_id     TEXT NOT NULL REFERENCES functions(id),
  version_id      TEXT NOT NULL,
  method          TEXT NOT NULL,
  path            TEXT NOT NULL,
  status          INTEGER NOT NULL,
  duration_ms     INTEGER NOT NULL,
  stdout          TEXT NOT NULL DEFAULT '',
  stderr          TEXT NOT NULL DEFAULT '',
  fetch_decisions TEXT NOT NULL DEFAULT '[]', -- JSON: [{host,port,allowed,stage}, ...]
  created_at      INTEGER NOT NULL
);

CREATE INDEX idx_invocation_logs_function_id ON invocation_logs(function_id, id DESC);
CREATE INDEX idx_invocation_logs_created_at ON invocation_logs(created_at);
