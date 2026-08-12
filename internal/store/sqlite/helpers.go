package sqlite

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/syumai/funcbox/internal/store"
)

// nowUnix returns the current time as Unix seconds (UTC), the storage
// representation used for every timestamp column.
func nowUnix() int64 { return time.Now().UTC().Unix() }

// toUnix converts a time.Time to its storage representation.
func toUnix(t time.Time) int64 { return t.UTC().Unix() }

// fromUnix converts a storage timestamp back to a time.Time in UTC.
func fromUnix(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

// mapErr normalizes a raw database/sql or modernc.org/sqlite error into a
// store sentinel error where applicable, leaving other errors (I/O
// failures, context cancellation, ...) unwrapped.
func mapErr(err error) error {
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
// we match on the stable, human-readable message SQLite itself produces —
// the same approach commonly used with the CGo sqlite3 driver.
func isConstraintErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "PRIMARY KEY constraint failed") ||
		strings.Contains(msg, "FOREIGN KEY constraint failed") ||
		strings.Contains(msg, "constraint failed")
}
