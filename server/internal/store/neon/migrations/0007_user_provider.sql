-- Generalizes users.google_sub (a Google-only column) into provider +
-- provider_subject, so a second identity provider (GitHub) can share the
-- same shape. Every pre-existing row is a
-- Google account, so it is migrated as such; UNIQUE moves from
-- google_sub alone to the (provider, provider_subject) pair.
ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'google';
ALTER TABLE users ADD COLUMN provider_subject TEXT NOT NULL DEFAULT '';

UPDATE users SET provider = 'google', provider_subject = google_sub;

CREATE UNIQUE INDEX idx_users_provider_subject ON users(provider, provider_subject);

ALTER TABLE users DROP COLUMN google_sub;
