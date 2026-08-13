// Package turso implements store.Store on top of Turso/libsql, using the
// pure-Go github.com/tursodatabase/libsql-client-go/libsql database/sql
// driver (NOT go-libsql, which requires CGo -- funcbox's binary must stay
// CGo-free; see tmp/08-storage-and-db.md §8.3).
//
// libsql speaks SQLite's SQL dialect (and, over the wire, is a SQLite
// fork), so there are no dialect differences from store/sqlite at all: this
// package reuses store/sqlite's Dialect (identity Rebind, the same
// text-matching MapErr) and store/sqlcommon's SQLite-family migrations
// unchanged. The only thing this package supplies is connection setup: DSN
// parsing (splitting the auth token out of the URL, since the libsql
// driver forbids passing it as a raw query parameter -- see Open's doc
// comment) and Migrate.
package turso

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/tursodatabase/libsql-client-go/libsql"

	"github.com/syumai/funcbox/server/internal/store"
	"github.com/syumai/funcbox/server/internal/store/sqlcommon"
	"github.com/syumai/funcbox/server/internal/store/sqlite"
)

// Store implements store.Store.
type Store struct {
	*sqlcommon.Store
}

var _ store.Store = (*Store)(nil)

// Open connects to a Turso/libsql database at dsn. dsn is a libsql/https/
// wss/http/ws URL (e.g. "libsql://mydb-org.turso.io" or, for a local
// sqld/embedded-replica dev server, "http://127.0.0.1:8080"), optionally
// carrying an "authToken" query parameter (matching this project's
// FUNCBOX_DB scheme convention, "turso:URL?authToken=..."; see
// internal/config's doc comment). The libsql driver itself forbids an
// "authToken"/"auth_token"/"jwt" query parameter reaching it directly (it
// wants that passed via libsql.WithAuthToken instead, presumably so it
// never accidentally ends up logged as part of a connection string), so
// Open extracts it here and strips it from the URL handed to the driver.
func Open(dsn string) (*Store, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("turso: parse DSN: %w", err)
	}
	q := u.Query()
	authToken := q.Get("authToken")
	q.Del("authToken")
	u.RawQuery = q.Encode()

	var opts []libsql.Option
	if authToken != "" {
		opts = append(opts, libsql.WithAuthToken(authToken))
	}
	connector, err := libsql.NewConnector(u.String(), opts...)
	if err != nil {
		return nil, fmt.Errorf("turso: create connector: %w", err)
	}

	db := sql.OpenDB(connector)
	// Unlike store/sqlite's ":memory:" case, a Turso/libsql connection is
	// always a real remote (or local-server) database that already handles
	// concurrent connections/transactions correctly, so the pool is left
	// at database/sql's default sizing rather than capped at one
	// connection. BootstrapFirstUser's concurrency safety therefore rests
	// on its UNIQUE-constraint backstop (see sqlcommon/aggregate.go's doc
	// comment), exactly as it would for any other real connection pool.

	return &Store{Store: sqlcommon.Open(db, sqlite.Dialect())}, nil
}

// Migrate applies internal/store/sqlcommon's SQLite-family schema
// migrations -- the same ones store/sqlite uses, with no dialect
// differences (see this package's doc comment).
func (s *Store) Migrate(ctx context.Context) error {
	return s.ApplyMigrations(ctx, sqlcommon.SQLiteMigrations())
}
