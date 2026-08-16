// Command funcbox-server runs the funcbox server: it hosts the dashboard,
// the management API, auth, and function invocation behind a single HTTP
//
// Configuration is entirely via environment variables (internal/config);
// there are no command-line flags for the server itself. The one
// which still reads FUNCBOX_DB/FUNCBOX_BLOB from the environment but takes
// for the full env var list.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/syumai/funcbox/runtime"
	"github.com/syumai/funcbox/server/internal/api"
	"github.com/syumai/funcbox/server/internal/auth"
	"github.com/syumai/funcbox/server/internal/config"
	fcrypto "github.com/syumai/funcbox/server/internal/crypto"
	"github.com/syumai/funcbox/server/internal/dashboard"
	"github.com/syumai/funcbox/server/internal/invoke"
	"github.com/syumai/funcbox/server/internal/mcpserver"
	"github.com/syumai/funcbox/server/internal/metrics"
	"github.com/syumai/funcbox/server/internal/oauth"
	"github.com/syumai/funcbox/server/internal/server"
	"github.com/syumai/funcbox/server/internal/service"
)

// envVarEncryptionInfo is the HKDF "info" label used to derive the env-var
// AES-GCM key from FUNCBOX_SESSION_SECRET (see internal/crypto's package
// doc for the key-rotation implications of changing the secret).
const envVarEncryptionInfo = "funcbox:env-vars"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// "gc" is the one subcommand this binary has (gc.go); anything else
	// (including no arguments at all) starts the server, matching this
	// binary's historical flag-free invocation.
	if len(os.Args) > 1 && os.Args[1] == "gc" {
		if err := runGC(os.Args[2:], logger, os.Stdout); err != nil {
			logger.Error("funcbox-server gc failed", "error", err)
			os.Exit(1)
		}
		return
	}

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
	// blob/gcs.Store holds a client with connections to release on
	// shutdown; blob/fs and blob/s3 have nothing to close and don't
	// implement io.Closer, so this is a no-op for them.
	if closer, ok := blobStore.(io.Closer); ok {
		defer closer.Close()
	}

	// FUNCBOX_METRICS=1 gates Prometheus instrumentation entirely
	// when disabled, so every call site below stays unconditional.
	mtr := metrics.New(os.Getenv("FUNCBOX_METRICS") == "1")

	// WithMaxPools is the invoke path's LRU cap on warm function-version
	// pools (FUNCBOX_POOL_MAX_FUNCTIONS, default 10, 0 = unlimited; see
	// internal/config). WithEvictHook feeds every LRU eviction into
	// funcbox_pool_evictions_total without runtime importing prometheus
	// itself. This manager is NOT used for the dashboard's own pool
	// (internal/dashboard builds and owns that one directly), so the
	// dashboard is never subject to this cap.
	manager := runtime.NewManager(
		runtime.WithMaxPools(cfg.PoolMaxFunctions),
		runtime.WithEvictHook(mtr.IncPoolEviction),
	)
	defer manager.Close()

	// Dev mode wins outright when set (provider-independent); otherwise
	// FUNCBOX_AUTH_PROVIDER selects between Google (the default) and
	// GitHub. Exactly one of these is
	// ever active.
	authMode := auth.ModeGoogle
	switch {
	case cfg.AuthMode == string(auth.ModeDev):
		authMode = auth.ModeDev
	case cfg.AuthProvider == string(auth.ModeGitHub):
		authMode = auth.ModeGitHub
	}
	authSvc, err := auth.New(auth.Config{
		Mode:               authMode,
		BaseURL:            cfg.BaseURL,
		ControlOrigin:      cfg.ControlURL,
		FunctionDomain:     cfg.FunctionDomain,
		ListenAddr:         cfg.Addr,
		ClientID:           cfg.GoogleClientID,
		ClientSecret:       cfg.GoogleClientSecret,
		GitHubClientID:     cfg.GitHubClientID,
		GitHubClientSecret: cfg.GitHubClientSecret,
		SessionSecret:      cfg.SessionSecret,
		OpenMode:           cfg.OpenMode,
	}, st)
	if err != nil {
		return fmt.Errorf("configure auth: %w", err)
	}

	// auth.New (above) already required cfg.SessionSecret to be non-empty,
	// so this derivation can't hit crypto.DeriveKey's empty-secret error.
	envKey, err := fcrypto.DeriveKey(cfg.SessionSecret, envVarEncryptionInfo)
	if err != nil {
		return fmt.Errorf("derive env var encryption key: %w", err)
	}

	deployer := &service.Deployer{Store: st, Blob: blobStore, Runtime: manager}
	functions := &service.Functions{Store: st, Runtime: manager, EnvKey: envKey}
	// WithManagedFunctionURL is only wired when FUNCBOX_FUNCTION_DOMAIN is
	// actually configured -- cfg.ManagedFunctionURL unconditionally errors
	// otherwise (config.Config.ManagedFunctionURL's own guard), which would
	// make every function DTO log a spurious ERROR line and fall back to no
	// "url" at all. WithBaseURL is always wired: it's functionDTO's
	// path-based "<BaseURL>/<owner>/<name>" URL fallback for exactly that
	// case (the README quick-start's path-based deployment shape).
	apiOpts := []api.Option{api.WithBaseURL(cfg.BaseURL)}
	if cfg.FunctionDomain != "" {
		apiOpts = append(apiOpts, api.WithManagedFunctionURL(cfg.ManagedFunctionURL))
	}
	apiHandler := api.New(deployer, functions, st, authSvc, logger, apiOpts...)

	invoker := &invoke.Invoker{
		Store:   st,
		Blob:    blobStore,
		Manager: manager,
		Logger:  logger,
		Timeout: cfg.InvokeTimeout,
		Auth:    authSvc,
		EnvKey:  envKey,
		Metrics: mtr,
	}

	// The MCP/OAuth control origin: FUNCBOX_CONTROL_URL when host-based
	// routing is configured, falling back to FUNCBOX_BASE_URL for the
	// common single-origin, path-routed deployment -- mirrors
	// auth.Config.ControlOrigin's own fallback (internal/auth/config.go),
	// duplicated here since neither oauth.New nor mcpserver.New defaults an
	// empty ControlOrigin the way auth.New does.
	controlOrigin := cfg.ControlURL
	if controlOrigin == "" {
		controlOrigin = cfg.BaseURL
	}
	oauthSvc, err := oauth.New(oauth.Config{
		ControlOrigin: controlOrigin,
		SessionSecret: cfg.SessionSecret,
	}, st, authSvc)
	if err != nil {
		return fmt.Errorf("configure oauth: %w", err)
	}
	mcpSvc, err := mcpserver.New(mcpserver.Config{
		ControlOrigin: controlOrigin,
	}, st, authSvc, apiHandler)
	if err != nil {
		return fmt.Errorf("configure mcpserver: %w", err)
	}

	dashboardSrv, err := dashboard.New(dashboard.Config{
		Auth:          authSvc,
		API:           apiHandler,
		SessionSecret: cfg.SessionSecret,
		Logger:        logger,
		DistDir:       cfg.DashboardDistDir,
	})
	if err != nil {
		return fmt.Errorf("configure dashboard: %w", err)
	}
	defer dashboardSrv.Close()
	if err := dashboardSrv.Ready(); err != nil {
		// management API have nothing to do with whether `pnpm build` has
		// been run. Every dashboard request gets the same clear message
		// via Server.ServeHTTP's writeNotBuiltPage in the meantime.
		logger.Warn("funcbox-server: dashboard assets not built", "error", err, "hint", "run `make server`")
	}

	handler := server.New(server.Deps{
		Logger:         logger,
		API:            apiHandler,
		Invoker:        invoker,
		Auth:           authSvc.Routes(),
		DevOIDC:        authSvc.DevRoutes(),
		Dashboard:      dashboardSrv,
		Metrics:        mtr, // gates its own /metrics mount + request instrumentation; see internal/metrics
		ControlURL:     cfg.ControlURL,
		FunctionDomain: cfg.FunctionDomain,
		LandingURL:     cfg.LandingURL,
		BaseURL:        cfg.BaseURL,
		MCP:            mcpSvc,
		OAuth:          oauthSvc.Routes(),
		MCPGate:        func(r *http.Request) bool { return mcpserver.Enabled(r.Context(), st) },
	})
	httpServer := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// delete rows older than the organization's log_retention_days
	// setting. Runs for the process lifetime; stopped via sigCtx the same
	// way the HTTP server itself is.
	go runLogRetention(sigCtx, st, logger)

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
