-- Generalizes users.disabled (bool) into a three-state users.status, adding
-- room for a "pending" (awaiting Org Admin approval) state alongside the
-- existing active/disabled distinction (tmp/13-public-mode.md §13.3).
-- Approval itself isn't implemented yet -- no row is created as "pending"
-- today -- this migration only carries forward the existing active/disabled
-- split under the new column.
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';

UPDATE users SET status = CASE WHEN disabled != 0 THEN 'disabled' ELSE 'active' END;

ALTER TABLE users DROP COLUMN disabled;
