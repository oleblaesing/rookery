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
	"crypto/rand"
	"encoding/base64"
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
	"rookery/internal/dkim"
	"rookery/internal/domains"
	"rookery/internal/queue"
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

	// ---- DKIM key management ----
	dk := dkim.NewManager(st.DB, cfg.Secrets.MasterKey)
	if err := bootstrapDKIM(ctx, st, cfg, dk); err != nil {
		slog.Error("bootstrap: DKIM key generation failed", "err", err)
		return 1
	}

	// ---- Domain manager (custom domains, MTA-STS, DNS checks) ----
	domMgr := domains.NewManager(st.DB, cfg.Domain, cfg.DNS.Resolver)

	// ---- Outbound delivery worker ----
	qWorker := queue.NewWorker(st.DB, st, dk, cfg, smtp.Deliver)

	// ---- HTTP server ----
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	web.RegisterRoutes(r, cfg, st.DB, st, dk, domMgr)

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
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("http: %w", err)
		}
	}()

	go func() {
		if err := smtpServer.ListenAndServe(ctx); err != nil {
			serverErr <- fmt.Errorf("smtp: %w", err)
		}
	}()

	go qWorker.Run(ctx)

	// ---- Domain background workers ----
	go runHourlyWorker(ctx, "mta-sts-upgrade", func(ctx context.Context) error {
		return domMgr.UpgradeMTASTSModes(ctx)
	})
	go runHourlyWorker(ctx, "dns-drift", func(ctx context.Context) error {
		return domMgr.DNSCheckAll(ctx)
	})
	go runDailyWorker(ctx, "cert-expiry", func(ctx context.Context) error {
		return domMgr.CheckCertExpiry(ctx)
	})

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

// runHourlyWorker runs fn once per hour until ctx is cancelled. Errors are
// logged and do not stop the loop.
func runHourlyWorker(ctx context.Context, name string, fn func(context.Context) error) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	// Run once at startup.
	if err := fn(ctx); err != nil {
		slog.Error("worker: startup run failed", "worker", name, "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fn(ctx); err != nil {
				slog.Error("worker: run failed", "worker", name, "err", err)
			}
		}
	}
}

// runDailyWorker runs fn once per day until ctx is cancelled.
func runDailyWorker(ctx context.Context, name string, fn func(context.Context) error) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	if err := fn(ctx); err != nil {
		slog.Error("worker: startup run failed", "worker", name, "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fn(ctx); err != nil {
				slog.Error("worker: run failed", "worker", name, "err", err)
			}
		}
	}
}

// bootstrapDKIM fetches the primary domain ID and calls dkim.Manager.EnsureKeys.
// It generates ed25519 + RSA-2048 DKIM keypairs on first run and logs the DNS
// TXT records the operator must publish.
func bootstrapDKIM(ctx context.Context, st *store.Store, cfg *config.Config, dk *dkim.Manager) error {
	var domainID string
	if err := st.DB.QueryRow(ctx,
		`SELECT id FROM domains WHERE domain = $1`, cfg.Domain,
	).Scan(&domainID); err != nil {
		return fmt.Errorf("bootstrap dkim: lookup domain id: %w", err)
	}
	return dk.EnsureKeys(ctx, domainID, cfg.Domain)
}

// bootstrapPrimaryDomain inserts the primary domain row on first run if it
// does not already exist. This is the only server-managed row that must exist
// before any user can register. §11.8 / ADR-0008: no interactive setup wizard.
//
// The mta_sts_id is generated here (mirroring what Register does for custom
// domains); ON CONFLICT backfills it for instances bootstrapped before this
// fix landed.
func bootstrapPrimaryDomain(ctx context.Context, st *store.Store, cfg *config.Config) error {
	mtsID, err := generateMTASTSID()
	if err != nil {
		return fmt.Errorf("bootstrap primary domain: generate mta-sts id: %w", err)
	}
	_, err = st.DB.Exec(ctx, `
		INSERT INTO domains (domain, is_primary, verified_at, wkd_active, mta_sts_id)
		VALUES ($1, TRUE, now(), TRUE, $2)
		ON CONFLICT (domain) DO UPDATE
		  SET mta_sts_id = COALESCE(domains.mta_sts_id, EXCLUDED.mta_sts_id)
	`, cfg.Domain, mtsID)
	if err != nil {
		return fmt.Errorf("bootstrap primary domain: %w", err)
	}
	slog.Info("bootstrap: primary domain ready", "domain", cfg.Domain)
	return nil
}

// generateMTASTSID returns a 16-char URL-safe base64 string suitable for use
// as an MTA-STS policy id. Matches the format used by domains.Register.
func generateMTASTSID() (string, error) {
	b := make([]byte, 12) // 12 bytes → 16 base64url chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// runHealthcheck is invoked as `rookery-server healthcheck` from the container
// HEALTHCHECK. It probes the locally bound HTTP listener and exits 0 on
// success, non-zero on failure.
func runHealthcheck() int {
	port := os.Getenv("ROOKERY_HEALTHCHECK_PORT")
	if port == "" {
		port = "8080"
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
