// Package neon implements store.Store on top of PostgreSQL (Neon or any
// other PostgreSQL-compatible server -- Neon itself is just speaks the wire
// protocol, so this package has nothing Neon-specific in it beyond the
// name), using github.com/jackc/pgx/v5 in database/sql stdlib-driver mode
// (registered as "pgx"; see tmp/08-storage-and-db.md §8.3).
//
// The query/row-mapping logic is entirely shared with store/sqlite and
// store/turso via internal/store/sqlcommon; this package supplies only the
// PostgreSQL-specific Dialect (rewriting "?" placeholders to "$1, $2, ..."
// via sqlcommon.PositionalRebind, and mapping pgconn error codes to store
// sentinel errors) and its own migrations (internal/store/neon/migrations),
// which differ from the SQLite family only in BLOB -> BYTEA (see that
// directory).
package neon

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlcommon"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store implements store.Store.
type Store struct {
	*sqlcommon.Store
}

var _ store.Store = (*Store)(nil)

// Open connects to a PostgreSQL database at dsn, a standard
// "postgres://user:pass@host:port/dbname?sslmode=..." (or equivalent
// keyword/value) connection string -- passed straight through to pgx's
// database/sql driver. Call Migrate before using it against a fresh
// database.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("neon: open: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("neon: ping: %w", err)
	}
	return &Store{Store: sqlcommon.Open(db, Dialect())}, nil
}

// Dialect is store/neon's sqlcommon.Dialect: PostgreSQL positional
// placeholders and pgconn-error-code-based MapErr.
func Dialect() sqlcommon.Dialect {
	return sqlcommon.Dialect{Name: "postgres", Rebind: sqlcommon.PositionalRebind, MapErr: MapErr}
}

// Migrate applies this package's own PostgreSQL-dialect schema migrations
// (internal/store/neon/migrations), embedded and applied via
// sqlcommon.Store.ApplyMigrations exactly like every other backend. It is
// idempotent and safe to call on every process start.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err // unreachable: "migrations" is a literal embedded directory
	}
	return s.ApplyMigrations(ctx, sub)
}

// MapErr normalizes a raw database/sql or pgx error into a store sentinel
// error where applicable, leaving other errors (I/O failures, context
// cancellation, ...) unwrapped.
func MapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		// unique_violation, foreign_key_violation, exclusion_violation,
		// not_null_violation, check_violation -- see
		// https://www.postgresql.org/docs/current/errcodes-appendix.html
		// class 23 ("Integrity Constraint Violation"), the same family
		// store/sqlite's text-matching MapErr covers.
		case "23505", "23503", "23514", "23502", "23P01":
			return store.ErrConflict
		}
	}
	return err
}
