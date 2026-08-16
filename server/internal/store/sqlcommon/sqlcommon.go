// Package sqlcommon implements store.Store's queries and row-mapping once,
// shared by every backend built on database/sql (store/sqlite, store/turso,
// SQL がほぼ共通なので、共通の SQL ビルダ層... を store/sqlcommon に置き、3
// 実装で共有する").
//
// Every query in this package is written with "?" placeholders, exactly as
// database/sql's own convention (and as SQLite/libsql expect natively).
// PostgreSQL's "$1, $2, ..." placeholder style is the only real dialect
// difference repositories need to handle (see this package's doc comment
// on Dialect) — UPSERT syntax ("ON CONFLICT ... DO UPDATE SET x =
// excluded.x") and Unix-seconds timestamp storage are identical across all
// three engines, so no other hook is needed. A Dialect rewrites "?" to the
// target engine's placeholder style and normalizes driver-specific errors
// (constraint violations, no-rows) into the store package's sentinel
// errors.
package sqlcommon

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/syumai/funcbox/server/internal/store"
)

// Dialect captures the handful of ways a database/sql driver differs for
// this package's purposes: placeholder syntax and error normalization.
type Dialect struct {
	// Name identifies the dialect for error messages (e.g. "sqlite",
	// "postgres").
	Name string

	// Rebind rewrites a query written with "?" placeholders into the
	// target driver's placeholder syntax. A nil Rebind is the identity
	// function, correct for SQLite and libsql (both accept "?" natively).
	Rebind func(query string) string

	// MapErr normalizes a raw database/sql or driver error into a store
	// sentinel error (store.ErrNotFound, store.ErrConflict) where
	// applicable, leaving other errors (I/O failures, context
	// cancellation, ...) unwrapped. Must handle sql.ErrNoRows itself (it is
	// not special-cased by sqlcommon). Required (a nil MapErr panics on
	// first use).
	MapErr func(err error) error
}

func (d Dialect) rebind(query string) string {
	if d.Rebind == nil {
		return query
	}
	return d.Rebind(query)
}

// PositionalRebind rewrites "?" placeholders into "$1", "$2", ... in
// left-to-right order, for PostgreSQL-family drivers (used by
// store/neon's Dialect). It does not attempt to skip "?" inside string
// literals: none of this package's queries embed a literal "?" in SQL
// text, only as a bind-parameter marker, so a straightforward scan is
// sufficient.
func PositionalRebind(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// execer is satisfied by both *sql.DB and *sql.Tx, letting conn's helpers
// work uniformly whether or not a caller has opened a transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// conn bundles the *sql.DB and Dialect every repository needs, plus the
// rebind-then-delegate helpers repositories call instead of touching
// database/sql directly.
type conn struct {
	db      *sql.DB
	dialect Dialect
}

func (c *conn) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.execOn(ctx, c.db, query, args...)
}

func (c *conn) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return c.queryOn(ctx, c.db, query, args...)
}

func (c *conn) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return c.queryRowOn(ctx, c.db, query, args...)
}

// execOn/queryOn/queryRowOn take an explicit execer so aggregate.go's
// cross-entity transactions can reuse the same rebind logic against a
// *sql.Tx instead of c.db.
func (c *conn) execOn(ctx context.Context, e execer, query string, args ...any) (sql.Result, error) {
	return e.ExecContext(ctx, c.dialect.rebind(query), args...)
}

func (c *conn) queryOn(ctx context.Context, e execer, query string, args ...any) (*sql.Rows, error) {
	return e.QueryContext(ctx, c.dialect.rebind(query), args...)
}

func (c *conn) queryRowOn(ctx context.Context, e execer, query string, args ...any) *sql.Row {
	return e.QueryRowContext(ctx, c.dialect.rebind(query), args...)
}

func (c *conn) mapErr(err error) error {
	if err == nil {
		return nil
	}
	return c.dialect.MapErr(err)
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// Store implements store.Store on top of a *sql.DB and a Dialect. Backend
// packages (store/sqlite, store/turso, store/neon) construct one with Open,
// wrap it in their own Store type (typically by embedding *sqlcommon.Store)
// to add a backend-specific Migrate method that supplies their own
// migrations filesystem via ApplyMigrations, and open the *sql.DB
// themselves (connection string parsing, pragmas, pool sizing are all
// backend-specific).
type Store struct {
	c *conn

	organizations   *organizationRepo
	users           *userRepo
	handles         *handleRepo
	workspaces      *workspaceRepo
	functions       *functionRepo
	sessions        *sessionRepo
	invokeAuthCodes *invokeAuthCodeRepo
	cliCredentials  *cliCredentialRepo
	cliAuthCodes    *cliAuthCodeRepo
	oauthClients    *oauthClientRepo
	oauthAuthCodes  *oauthAuthCodeRepo
	oauthGrants     *oauthGrantRepo
	audit           *auditRepo
	invocationLogs  *invocationLogRepo
}

// Store deliberately does NOT assert store.Store conformance here: it is
// missing Migrate (each backend supplies its own migrations filesystem via
// ApplyMigrations; see this type's doc comment). Backend packages assert
// their own wrapper type against store.Store instead.

// Open wraps an already-opened *sql.DB as a Store using dialect. It does
// not run migrations; call ApplyMigrations (typically via a backend's own
// Migrate wrapper) before using a fresh database.
func Open(db *sql.DB, dialect Dialect) *Store {
	c := &conn{db: db, dialect: dialect}
	return &Store{
		c:               c,
		organizations:   &organizationRepo{c: c},
		users:           &userRepo{c: c},
		handles:         &handleRepo{c: c},
		workspaces:      &workspaceRepo{c: c},
		functions:       &functionRepo{c: c},
		sessions:        &sessionRepo{c: c},
		invokeAuthCodes: &invokeAuthCodeRepo{c: c},
		cliCredentials:  &cliCredentialRepo{c: c},
		cliAuthCodes:    &cliAuthCodeRepo{c: c},
		oauthClients:    &oauthClientRepo{c: c},
		oauthAuthCodes:  &oauthAuthCodeRepo{c: c},
		oauthGrants:     &oauthGrantRepo{c: c},
		audit:           &auditRepo{c: c},
		invocationLogs:  &invocationLogRepo{c: c},
	}
}

func (s *Store) Organizations() store.OrganizationRepo     { return s.organizations }
func (s *Store) Users() store.UserRepo                     { return s.users }
func (s *Store) PublicUserIDs() store.PublicUserIDRepo     { return s.handles }
func (s *Store) Workspaces() store.WorkspaceRepo           { return s.workspaces }
func (s *Store) Functions() store.FunctionRepo             { return s.functions }
func (s *Store) Sessions() store.SessionRepo               { return s.sessions }
func (s *Store) InvokeAuthCodes() store.InvokeAuthCodeRepo { return s.invokeAuthCodes }
func (s *Store) CLICredentials() store.CLICredentialRepo   { return s.cliCredentials }
func (s *Store) CLIAuthCodes() store.CLIAuthCodeRepo       { return s.cliAuthCodes }
func (s *Store) OAuthClients() store.OAuthClientRepo       { return s.oauthClients }
func (s *Store) OAuthAuthCodes() store.OAuthAuthCodeRepo   { return s.oauthAuthCodes }
func (s *Store) OAuthGrants() store.OAuthGrantRepo         { return s.oauthGrants }
func (s *Store) Audit() store.AuditRepo                    { return s.audit }
func (s *Store) InvocationLogs() store.InvocationLogRepo   { return s.invocationLogs }

// Close closes the underlying *sql.DB.
func (s *Store) Close() error { return s.c.db.Close() }

// DB returns the underlying *sql.DB, for backends that need it for
// migrations, health checks, or shutdown beyond what Store itself exposes.
func (s *Store) DB() *sql.DB { return s.c.db }

// ApplyMigrations applies every "NNNN_description.sql" file under
// migrations (matched at its root, i.e. callers pass an already-rooted
// fs.FS, e.g. via fs.Sub on an embed.FS) that hasn't yet been recorded in
// schema_migrations, in ascending numeric order. It is idempotent and safe
// to call on every process start. The schema_migrations bootstrap
// statement and each migration's own bookkeeping insert use the standard
// "INTEGER PRIMARY KEY" / "?" forms, which every dialect this package
// supports (SQLite, libsql, PostgreSQL) accepts identically after rebind.
func (s *Store) ApplyMigrations(ctx context.Context, migrations fs.FS) error {
	// SQLite's ALTER TABLE ... DROP COLUMN refuses to drop a column with a
	// UNIQUE or PRIMARY KEY constraint (see e.g. migration 0007's users
	// table rebuild), so a migration needing that has no choice but to
	// rebuild the table (DROP TABLE + CREATE + copy + rename). With
	// PRAGMA foreign_keys=ON (store/sqlite's Open enables it; store/turso's
	// libsql connection leaves it at SQLite's own default of off, so this
	// is a no-op there), dropping a table other tables reference via
	// FOREIGN KEY fails the implicit existence check DROP TABLE performs.
	// SQLite's own docs prescribe disabling the pragma for the whole
	// migration -- and only outside of any transaction, since "this pragma
	// is a no-op within a transaction" -- so that's done here, once, around
	// every pending migration in this call, and restored before returning.
	// PRAGMA is a plain statement (no rebind/placeholders needed) that only
	// SQLite-family dialects define; postgres has no such pragma, so this
	// is skipped there.
	if s.c.dialect.Name == "sqlite" {
		if _, err := s.c.exec(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return fmt.Errorf("sqlcommon: disable foreign_keys for migration: %w", err)
		}
		defer s.c.exec(ctx, `PRAGMA foreign_keys = ON`) //nolint:errcheck
	}

	if _, err := s.c.exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("sqlcommon: create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		return fmt.Errorf("sqlcommon: read migrations dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // "0001_init.sql" < "0002_....sql" lexically == numerically

	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}

		var applied int
		if err := s.c.queryRow(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("sqlcommon: check migration %d: %w", version, err)
		}
		if applied > 0 {
			continue
		}

		body, err := fs.ReadFile(migrations, name)
		if err != nil {
			return fmt.Errorf("sqlcommon: read migration %s: %w", name, err)
		}

		if err := s.applyMigration(ctx, version, string(body)); err != nil {
			return fmt.Errorf("sqlcommon: apply migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, version int, sqlText string) error {
	tx, err := s.c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	// The migration body itself contains no "?" placeholders (it's raw
	// DDL), so it's executed as-is with no rebind.
	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		return err
	}
	if _, err := s.c.execOn(ctx, tx,
		`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, version, nowUnix(),
	); err != nil {
		return err
	}
	return tx.Commit()
}

// migrationVersion extracts the numeric prefix from a migration filename
// such as "0001_init.sql" -> 1.
func migrationVersion(name string) (int, error) {
	i := strings.IndexByte(name, '_')
	if i < 0 {
		return 0, fmt.Errorf("sqlcommon: malformed migration filename %q (want \"NNNN_description.sql\")", name)
	}
	v, err := strconv.Atoi(name[:i])
	if err != nil {
		return 0, fmt.Errorf("sqlcommon: malformed migration filename %q: %w", name, err)
	}
	return v, nil
}
