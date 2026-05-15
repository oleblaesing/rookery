// rookery-server is the single binary that runs the HTTP server, SMTP listeners,
// and background workers for a rookery instance.
//
// Subcommands:
//   - (no args)   start the server (default)
//   - healthcheck probe the local /healthz endpoint and exit; used by the
//                 container HEALTHCHECK because the distroless runtime image
//                 has no shell or wget/curl.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"rookery/internal/config"
	"rookery/internal/smtp"
	"rookery/internal/store"
	"rookery/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}

	if code := runServer(); code != 0 {
		os.Exit(code)
	}
}

func runServer() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfgPath := os.Getenv("ROOKERY_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/rookery/rookery.toml"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", cfgPath, "err", err)
		return 1
	}

	if lvl := cfg.Log.Level; lvl != "" {
		var l slog.Level
		if err := l.UnmarshalText([]byte(lvl)); err != nil {
			slog.Warn("invalid log.level in config; keeping info", "value", lvl, "err", err)
		} else {
			logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
			slog.SetDefault(logger)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ---- Open DB + run migrations ----
	st, err := store.Open(ctx, cfg.DBUrl(), cfg.Storage.MessageDir)
	if err != nil {
		slog.Error("failed to open store", "err", err)
		return 1
	}
	defer st.Close()

	// ---- First-run bootstrap ----
	// Seed the primary domain row if it doesn't exist yet.
	if err := bootstrapPrimaryDomain(ctx, st, cfg); err != nil {
		slog.Error("bootstrap: failed to seed primary domain", "err", err)
		return 1
	}

	// ---- HTTP server ----
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	web.RegisterRoutes(r, cfg, st.DB, st)

	httpAddr := fmt.Sprintf("%s:%d", cfg.HTTP.Host, cfg.HTTP.Port)
	srv := &http.Server{
		Addr:         httpAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	slog.Info("rookery starting", "http_addr", httpAddr, "domain", cfg.Domain)

	// ---- SMTP inbound listener ----
	// TLS config is nil in Phase 1 (no cert provisioning yet). Phase 4 wires
	// certmagic and passes a *tls.Config here.
	smtpServer := smtp.NewServer(cfg, st.DB, st, nil)

	serverErr := make(chan error, 2)

	go func() {
		// Phase 0/1 serves plaintext HTTP. TLS termination via ACME (certmagic)
		// lands in Phase 4 (§11.7 of PLAN.md).
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("http: %w", err)
		}
	}()

	go func() {
		if err := smtpServer.ListenAndServe(ctx); err != nil {
			serverErr <- fmt.Errorf("smtp: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-serverErr:
		slog.Error("server error", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful HTTP shutdown failed", "err", err)
	}

	slog.Info("rookery stopped")
	return 0
}

// bootstrapPrimaryDomain inserts the primary domain row on first run if it
// does not already exist. This is the only server-managed row that must exist
// before any user can register. §11.8 / ADR-0008: no interactive setup wizard.
func bootstrapPrimaryDomain(ctx context.Context, st *store.Store, cfg *config.Config) error {
	_, err := st.DB.Exec(ctx, `
		INSERT INTO domains (domain, is_primary, verified_at, wkd_active)
		VALUES ($1, TRUE, now(), TRUE)
		ON CONFLICT (domain) DO NOTHING
	`, cfg.Domain)
	if err != nil {
		return fmt.Errorf("bootstrap primary domain: %w", err)
	}
	slog.Info("bootstrap: primary domain ready", "domain", cfg.Domain)
	return nil
}

// runHealthcheck is invoked as `rookery-server healthcheck` from the container
// HEALTHCHECK. It probes the locally bound HTTP listener and exits 0 on
// success, non-zero on failure.
func runHealthcheck() int {
	port := os.Getenv("ROOKERY_HEALTHCHECK_PORT")
	if port == "" {
		port = "80"
	}
	url := fmt.Sprintf("http://127.0.0.1:%s/healthz", port)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
