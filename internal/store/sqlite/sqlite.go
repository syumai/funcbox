// Package sqlite implements store.Store on top of modernc.org/sqlite (a
// pure-Go, CGo-free SQLite driver). It is the v1 reference backend for
// local development and small deployments; see
// tmp/08-storage-and-db.md §8.3.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/syumai/funcbox/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store implements store.Store.
type Store struct {
	db *sql.DB

	organizations *organizationRepo
	users         *userRepo
	handles       *handleRepo
	workspaces    *workspaceRepo
	functions     *functionRepo
	sessions      *sessionRepo
	tokens        *tokenRepo
	audit         *auditRepo
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
//     tmp/08-storage-and-db.md §8.3 by serializing all access through one
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

	s := &Store{db: db}
	s.organizations = &organizationRepo{db: db}
	s.users = &userRepo{db: db}
	s.handles = &handleRepo{db: db}
	s.workspaces = &workspaceRepo{db: db}
	s.functions = &functionRepo{db: db}
	s.sessions = &sessionRepo{db: db}
	s.tokens = &tokenRepo{db: db}
	s.audit = &auditRepo{db: db}
	return s, nil
}

func (s *Store) Organizations() store.OrganizationRepo { return s.organizations }
func (s *Store) Users() store.UserRepo                 { return s.users }
func (s *Store) Handles() store.HandleRepo             { return s.handles }
func (s *Store) Workspaces() store.WorkspaceRepo       { return s.workspaces }
func (s *Store) Functions() store.FunctionRepo         { return s.functions }
func (s *Store) Sessions() store.SessionRepo           { return s.sessions }
func (s *Store) Tokens() store.TokenRepo               { return s.tokens }
func (s *Store) Audit() store.AuditRepo                { return s.audit }

// Close closes the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

// Migrate applies any schema migrations embedded under migrations/ that
// haven't been recorded in schema_migrations yet. It is idempotent and
// safe to call on every process start.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("sqlite: create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("sqlite: read migrations dir: %w", err)
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
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("sqlite: check migration %d: %w", version, err)
		}
		if applied > 0 {
			continue
		}

		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("sqlite: read migration %s: %w", name, err)
		}

		if err := s.applyMigration(ctx, version, string(body)); err != nil {
			return fmt.Errorf("sqlite: apply migration %s: %w", name, err)
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, version int, sqlText string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	if _, err := tx.ExecContext(ctx, sqlText); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
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
		return 0, fmt.Errorf("sqlite: malformed migration filename %q (want \"NNNN_description.sql\")", name)
	}
	v, err := strconv.Atoi(name[:i])
	if err != nil {
		return 0, fmt.Errorf("sqlite: malformed migration filename %q: %w", name, err)
	}
	return v, nil
}
