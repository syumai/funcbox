// Command funcbox-server runs the funcbox server: it hosts the
// dashboard, the management API, auth, and function invocation behind
// a single HTTP listener (see tmp/02-architecture.md).
//
// Configuration is entirely via environment variables (internal/
// config); there are no command-line flags. See tmp/02-architecture.md
// "設定（環境変数）" for the full list.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/syumai/funcbox/internal/config"
	"github.com/syumai/funcbox/internal/server"
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

	handler := server.New(logger)
	httpServer := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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
	case <-ctx.Done():
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
