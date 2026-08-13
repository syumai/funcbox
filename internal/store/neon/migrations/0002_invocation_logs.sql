-- PostgreSQL counterpart of store/sqlcommon's invocation_logs migration.
CREATE TABLE invocation_logs (
  id              TEXT PRIMARY KEY,
  function_id     TEXT NOT NULL REFERENCES functions(id),
  version_id      TEXT NOT NULL,
  method          TEXT NOT NULL,
  path            TEXT NOT NULL,
  status          BIGINT NOT NULL,
  duration_ms     BIGINT NOT NULL,
  stdout          TEXT NOT NULL DEFAULT '',
  stderr          TEXT NOT NULL DEFAULT '',
  fetch_decisions TEXT NOT NULL DEFAULT '[]',
  created_at      BIGINT NOT NULL
);

CREATE INDEX idx_invocation_logs_function_id ON invocation_logs(function_id, id DESC);
CREATE INDEX idx_invocation_logs_created_at ON invocation_logs(created_at);
