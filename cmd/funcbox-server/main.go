// Command funcbox-server runs the funcbox server: it hosts the dashboard,
// the management API, auth, and function invocation behind a single HTTP
// listener (see tmp/02-architecture.md).
//
// Configuration is entirely via environment variables (internal/config);
// there are no command-line flags. See tmp/02-architecture.md
// "設定（環境変数）" for the full list.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/syumai/funcbox/internal/api"
	blobfs "github.com/syumai/funcbox/internal/blob/fs"
	"github.com/syumai/funcbox/internal/config"
	"github.com/syumai/funcbox/internal/invoke"
	"github.com/syumai/funcbox/internal/runtime"
	"github.com/syumai/funcbox/internal/server"
	"github.com/syumai/funcbox/internal/service"
	"github.com/syumai/funcbox/internal/store"
	"github.com/syumai/funcbox/internal/store/sqlite"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(logger); err != nil {
		logger.Error("funcbox-server exited with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	st, err := openStore(cfg.DB)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}

	blobStore, err := openBlob(cfg.Blob)
	if err != nil {
		return err
	}

	manager := runtime.NewManager()
	defer manager.Close()

	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	functions := &service.Functions{Store: st, Runtime: manager}
	apiHandler := api.New(deployer, functions, logger)

	invoker := &invoke.Invoker{
		Store:   st,
		Blob:    blobStore,
		Manager: manager,
		Logger:  logger,
		Timeout: cfg.InvokeTimeout,
	}

	handler := server.New(server.Deps{
		Logger:  logger,
		API:     apiHandler,
		Invoker: invoker,
	})
	httpServer := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("funcbox-server listening", "addr", cfg.Addr)
		serveErr <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-sigCtx.Done():
		logger.Info("shutdown signal received, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	logger.Info("funcbox-server shut down cleanly")
	return nil
}

// openStore parses FUNCBOX_DB (a "scheme:rest" connection string, e.g.
// "sqlite:./funcbox.db" or "sqlite::memory:"; see
// tmp/02-architecture.md's config table) and opens the matching store.Store
// backend. Only "sqlite" is implemented this phase; other schemes
// (turso/neon/dynamodb) are named in the design doc as future backends.
func openStore(dbConn string) (store.Store, error) {
	if dbConn == "" {
		dbConn = "sqlite:funcbox.db"
	}
	scheme, rest, ok := strings.Cut(dbConn, ":")
	if !ok {
		return nil, fmt.Errorf("invalid FUNCBOX_DB %q: expected \"scheme:connection\"", dbConn)
	}
	switch scheme {
	case "sqlite":
		return sqlite.Open(rest)
	default:
		return nil, fmt.Errorf("unsupported FUNCBOX_DB scheme %q (only \"sqlite\" is implemented this phase)", scheme)
	}
}

// openBlob parses FUNCBOX_BLOB the same way as openStore, for the blob
// backend. Only "fs" is implemented this phase; s3/gcs are future backends.
func openBlob(blobConn string) (*blobfs.Store, error) {
	if blobConn == "" {
		blobConn = "fs:./data/blobs"
	}
	scheme, rest, ok := strings.Cut(blobConn, ":")
	if !ok {
		return nil, fmt.Errorf("invalid FUNCBOX_BLOB %q: expected \"scheme:connection\"", blobConn)
	}
	switch scheme {
	case "fs":
		return blobfs.New(rest)
	default:
		return nil, fmt.Errorf("unsupported FUNCBOX_BLOB scheme %q (only \"fs\" is implemented this phase)", scheme)
	}
}
