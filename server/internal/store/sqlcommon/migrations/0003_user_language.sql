-- A user-level dashboard language preference. Empty means inherit the
-- organization's settings.language; this lets users opt back into future
-- organization-wide language changes.
ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT '';
