-- Installation-global function-name claims. Existing owner-scoped duplicates
-- are preserved in functions; the oldest function (then lowest immutable ID)
-- deterministically receives the active global claim.
CREATE TABLE function_names (
  name               TEXT PRIMARY KEY,
  function_id        TEXT NOT NULL UNIQUE,
  state              TEXT NOT NULL DEFAULT 'active',
  claimed_at         INTEGER NOT NULL,
  claimed_by_user_id TEXT,
  released_at        INTEGER,
  tombstone_until    INTEGER
);

INSERT INTO function_names (name, function_id, state, claimed_at)
SELECT f.name, f.id, 'active', f.created_at
FROM functions f
WHERE NOT EXISTS (
  SELECT 1
  FROM functions earlier
  WHERE earlier.name = f.name
    AND (earlier.created_at < f.created_at
      OR (earlier.created_at = f.created_at AND earlier.id < f.id))
);
