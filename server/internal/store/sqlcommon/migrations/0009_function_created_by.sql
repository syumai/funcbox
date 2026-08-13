-- Tracks which user created a function (tmp/13-public-mode.md §13.4), needed
-- for workspace-scoped "max_functions_per_member" limits: a workspace's
-- functions are shared, but that limit is per creating member, which the
-- previous schema had no way to answer. For a personal-scope function,
-- owner == creator already (no transfer feature exists), so counting logic
-- there uses owner instead and doesn't depend on this column.
--
-- Existing rows are backfilled from their oldest function_versions.created_by
-- (versions are immutable and already carry a creator). A function with no
-- versions yet (reserved-but-undeployed) has nothing to backfill from and is
-- left NULL; NULL functions are excluded from creator-scoped counts (see
-- FunctionRepo.CountByWorkspaceAndCreator).
ALTER TABLE functions ADD COLUMN created_by TEXT REFERENCES users(id);

UPDATE functions SET created_by = (
  SELECT fv.created_by
  FROM function_versions fv
  WHERE fv.function_id = functions.id
  ORDER BY fv.created_at ASC, fv.id ASC
  LIMIT 1
);
