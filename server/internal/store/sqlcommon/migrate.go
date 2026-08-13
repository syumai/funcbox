package sqlcommon

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var sqliteMigrationsFS embed.FS

// SQLiteMigrations returns the SQLite-family schema migrations (used
// as-is, with no dialect differences, by both store/sqlite and
// store/turso — libsql is a SQLite-wire-compatible fork; see
// store/neon embeds its own PostgreSQL-dialect migrations instead (BLOB ->
// BYTEA; see store/neon/migrations).
func SQLiteMigrations() fs.FS {
	sub, err := fs.Sub(sqliteMigrationsFS, "migrations")
	if err != nil {
		// Unreachable: "migrations" is a literal directory embedded above.
		panic(err)
	}
	return sub
}
