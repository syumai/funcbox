// Package sqlite implements store.Store on top of modernc.org/sqlite (a
// pure-Go, CGo-free SQLite driver). It is the v1 reference backend for
// local development and small deployments; see
//
// The actual query/row-mapping logic lives in internal/store/sqlcommon,
// shared with store/turso and store/neon (see that package's doc comment);
// this package only supplies the SQLite-specific pieces: opening the
// *sql.DB with the right pragmas, a Dialect with an identity Rebind (both
// SQLite and libsql accept "?" placeholders natively) and a text-matching
// MapErr, and this backend's own embedded migrations (reused as-is by
// store/turso, since libsql is SQLite-wire-compatible with no dialect
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlcommon"
)

// Store implements store.Store.
type Store struct {
	*sqlcommon.Store
}

var _ store.Store = (*Store)(nil)

// Open opens (creating if necessary) a SQLite database at dsn and returns a
// ready-to-use Store. Call Migrate before using it against a fresh
// database. dsn is passed straight through to modernc.org/sqlite, so both
// ":memory:" and file paths work.
//
// The connection pool is capped at a single connection. This serves two
// purposes:
//
//  1. It enforces the "single writer is fine" design from
//     connection.
//  2. It is what makes ":memory:" DSNs usable at all through database/sql.
//     modernc.org/sqlite does not implicitly share an in-memory database
//     across connections: each new physical connection to ":memory:" gets
//     its own empty database. database/sql's pool may otherwise open
//     several connections concurrently, which would make queries
//     non-deterministically see an empty database. Capping the pool at
//     one connection guarantees every query goes through the same
//     physical connection, so ":memory:" behaves as a single shared
//     database for the lifetime of the Store.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: enable foreign_keys: %w", err)
	}
	// WAL has no effect on ":memory:" databases (SQLite keeps those in
	// "memory" journal mode regardless); harmless to request unconditionally.
	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: enable WAL: %w", err)
	}

	return &Store{Store: sqlcommon.Open(db, Dialect())}, nil
}

// Dialect is store/sqlite's (and store/turso's) sqlcommon.Dialect: an
// identity Rebind and text-matching MapErr, both exported so store/turso
// can reuse them verbatim (its wire protocol is SQLite's, so its driver
// surfaces the same error text).
func Dialect() sqlcommon.Dialect {
	return sqlcommon.Dialect{Name: "sqlite", Rebind: nil, MapErr: MapErr}
}

// Migrate applies internal/store/sqlcommon's SQLite-family schema
// migrations. It is idempotent and safe to call on every process start.
func (s *Store) Migrate(ctx context.Context) error {
	return s.ApplyMigrations(ctx, sqlcommon.SQLiteMigrations())
}

// MapErr normalizes a raw database/sql or modernc.org/sqlite error into a
// store sentinel error where applicable, leaving other errors (I/O
// failures, context cancellation, ...) unwrapped. Exported so store/turso
// can reuse it verbatim (see Dialect's doc comment).
func MapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if isConstraintErr(err) {
		return store.ErrConflict
	}
	return err
}

// isConstraintErr reports whether err is a SQLite UNIQUE/PRIMARY KEY/
// FOREIGN KEY constraint violation. modernc.org/sqlite surfaces these as
// *sqlite.Error, but rather than depend on that package's exported error
// codes (which vary between the extended result codes used in messages),
// we match on the stable, human-readable message SQLite itself produces --
// the same approach commonly used with the CGo sqlite3 driver. libsql (the
// driver store/turso uses) speaks the same SQLite wire protocol and
// produces the same constraint-violation message text, so this also backs
// store/turso's MapErr.
func isConstraintErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "PRIMARY KEY constraint failed") ||
		strings.Contains(msg, "FOREIGN KEY constraint failed") ||
		strings.Contains(msg, "constraint failed")
}
