-- Generalizes users.google_sub (a Google-only column) into provider +
-- provider_subject, so a second identity provider (GitHub) can share the
-- same shape. Every pre-existing row is a
-- Google account, so it is migrated as such; UNIQUE moves from google_sub
-- alone to the (provider, provider_subject) pair.
--
-- google_sub carries an inline UNIQUE constraint, and SQLite's
-- ALTER TABLE ... DROP COLUMN refuses to drop a column with a UNIQUE
-- constraint (see https://www.sqlite.org/lang_altertable.html, "column may
-- not have a UNIQUE or PRIMARY KEY constraint"), so this rebuilds the table
-- instead of dropping the column in place -- SQLite's standard technique for
-- schema changes ALTER TABLE can't express directly.
CREATE TABLE users_new (
  id               TEXT PRIMARY KEY,
  provider         TEXT NOT NULL,
  provider_subject TEXT NOT NULL,
  email            TEXT NOT NULL UNIQUE,
  name             TEXT NOT NULL,
  role             TEXT NOT NULL DEFAULT 'member',
  disabled         INTEGER NOT NULL DEFAULT 0,
  language         TEXT NOT NULL DEFAULT '',
  created_at       INTEGER NOT NULL,
  updated_at       INTEGER NOT NULL,
  UNIQUE (provider, provider_subject)
);

INSERT INTO users_new (id, provider, provider_subject, email, name, role, disabled, language, created_at, updated_at)
SELECT id, 'google', google_sub, email, name, role, disabled, language, created_at, updated_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
