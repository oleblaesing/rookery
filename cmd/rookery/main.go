// rookery is the single binary for a rookery instance. It has explicit
// subcommands so each invocation is unambiguous:
//
//	rookery serve                              — start the HTTP + SMTP server
//	rookery healthcheck                        — probe the local /healthz endpoint (container use)
//	rookery delete-user <address>              — permanently delete a user account
//	rookery rotate-master-key ...              — re-encrypt DKIM keys under a new master key
//	rookery relay-client <create|list|revoke>  — manage relay-rookery client credentials
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"rookery/internal/config"
	"rookery/internal/dkim"
	"rookery/internal/domains"
	"rookery/internal/lifecycle"
	"rookery/internal/queue"
	"rookery/internal/smtp"
	"rookery/internal/store"
	"rookery/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		os.Exit(runServer())
	case "healthcheck":
		os.Exit(runHealthcheck())
	case "delete-user":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: rookery delete-user <address>")
			os.Exit(1)
		}
		os.Exit(runDeleteUser(os.Args[2]))
	case "rotate-master-key":
		os.Exit(runRotateMasterKey(os.Args[2:]))
	case "relay-client":
		os.Exit(runRelayClient(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "rookery: unknown subcommand %q\n\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Fprint(os.Stderr, `rookery — mail server binary

Usage:
  rookery serve
      Start the HTTP and SMTP server.

  rookery healthcheck
      Probe the local /healthz endpoint and exit 0 on success.
      Used by the container HEALTHCHECK; not intended for direct operator use.

  rookery delete-user <address>
      Permanently delete a user account and all exclusively-owned data.
      The rookery dispatcher (./rookery user delete) is the operator-facing
      interface; this subcommand is the implementation it delegates to.

  rookery rotate-master-key --old-key=<hex> --new-key=<hex>
      Re-encrypt all DKIM private keys from the old master key to a new one.
      The rookery dispatcher (./rookery master-key rotate) generates the new
      key and invokes this subcommand; do not call it directly.

  rookery relay-client <create|list|revoke> ...
      Manage downstream relay-client credentials for the relay-rookery
      submission listener (ADR-0030). The rookery dispatcher
      (./rookery relay-client ...) is the operator-facing interface.

`)
}

// -------------------------------------------------------------------------
// serve
// -------------------------------------------------------------------------

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

	st, err := store.Open(ctx, cfg.DBUrl(), cfg.Storage.MessageDir)
	if err != nil {
		slog.Error("failed to open store", "err", err)
		return 1
	}
	defer st.Close()

	if err := bootstrapPrimaryDomain(ctx, st, cfg); err != nil {
		slog.Error("bootstrap: failed to seed primary domain", "err", err)
		return 1
	}

	dk := dkim.NewManager(st.DB, cfg.Secrets.MasterKey)
	if err := bootstrapDKIM(ctx, st, cfg, dk); err != nil {
		slog.Error("bootstrap: DKIM key generation failed", "err", err)
		return 1
	}

	domMgr := domains.NewManager(st.DB, cfg.Domain, cfg.DNS.Resolver)
	domMgr.SetLocalDelivery(func(ctx context.Context, from, to string, rawMsg []byte) error {
		return smtp.DeliverLocal(ctx, st.DB, st, cfg, from, to, rawMsg)
	})
	if err := domMgr.BackfillOwnerAddresses(ctx); err != nil {
		slog.Error("bootstrap: backfill owner addresses failed", "err", err)
	}

	qWorker := queue.NewWorker(st.DB, st, dk, cfg, smtp.Deliver)

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

	smtpServer := smtp.NewServer(cfg, st.DB, st, nil)

	serverErr := make(chan error, 3)

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

	// Relay-rookery submission listener (ports 465/587), opt-in. Reuses the TLS
	// certificate Caddy provisions for the instance domain (ADR-0030 §3/§4).
	if cfg.SMTP.SubmissionEnabled {
		tlsCfg, err := smtp.LoadSubmissionTLS(cfg.SMTP.SubmissionCertsDir, cfg.Domain,
			cfg.SMTP.SubmissionCertFile, cfg.SMTP.SubmissionKeyFile)
		if err != nil {
			slog.Error("submission: TLS setup failed; listener not started", "err", err)
			return 1
		}
		submissionServer := smtp.NewSubmissionServer(cfg, st.DB, st, tlsCfg)
		go func() {
			if err := submissionServer.ListenAndServe(ctx); err != nil {
				serverErr <- fmt.Errorf("submission: %w", err)
			}
		}()
	}
	go qWorker.Run(ctx)
	go runHourlyWorker(ctx, "mta-sts-upgrade", func(ctx context.Context) error {
		return domMgr.UpgradeMTASTSModes(ctx)
	})
	go runHourlyWorker(ctx, "dns-drift", func(ctx context.Context) error {
		return domMgr.DNSCheckAll(ctx)
	})
	go runDailyWorker(ctx, "cert-expiry", func(ctx context.Context) error {
		return domMgr.CheckCertExpiry(ctx)
	})
	go runHourlyWorker(ctx, "export-cleanup", func(ctx context.Context) error {
		return web.CleanupExpiredExports(ctx, st.DB, st.ExportDir)
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

// -------------------------------------------------------------------------
// healthcheck
// -------------------------------------------------------------------------

func runHealthcheck() int {
	port := os.Getenv("ROOKERY_HEALTHCHECK_PORT")
	if port == "" {
		port = "8080"
	}
	target := fmt.Sprintf("http://127.0.0.1:%s/healthz", port)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(target)
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

// -------------------------------------------------------------------------
// delete-user
// -------------------------------------------------------------------------

func runDeleteUser(address string) int {
	ctx := context.Background()

	cfgPath := os.Getenv("ROOKERY_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/rookery/rookery.toml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "delete-user: load config: %v\n", err)
		return 1
	}

	st, err := store.Open(ctx, cfg.DBUrl(), cfg.Storage.MessageDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "delete-user: open store: %v\n", err)
		return 1
	}
	defer st.Close()

	var userID string
	err = st.DB.QueryRow(ctx,
		`SELECT user_id FROM addresses WHERE lower(address) = lower($1) LIMIT 1`,
		address,
	).Scan(&userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			fmt.Fprintf(os.Stderr, "delete-user: no user found for %q\n", address)
		} else {
			fmt.Fprintf(os.Stderr, "delete-user: lookup: %v\n", err)
		}
		return 1
	}

	if err := lifecycle.DeleteUser(ctx, st.DB, st, userID); err != nil {
		fmt.Fprintf(os.Stderr, "delete-user: %v\n", err)
		return 1
	}

	fmt.Printf("delete-user: deleted %s\n", address)
	return 0
}

// -------------------------------------------------------------------------
// rotate-master-key
// -------------------------------------------------------------------------

func runRotateMasterKey(args []string) int {
	var oldKey, newKey string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--old-key="):
			oldKey = strings.TrimPrefix(a, "--old-key=")
		case strings.HasPrefix(a, "--new-key="):
			newKey = strings.TrimPrefix(a, "--new-key=")
		}
	}
	if oldKey == "" || newKey == "" {
		fmt.Fprintln(os.Stderr, "usage: rookery rotate-master-key --old-key=<hex> --new-key=<hex>")
		return 1
	}

	ctx := context.Background()

	dbPass := os.Getenv("ROOKERY_DB_PASSWORD")
	if dbPass == "" {
		fmt.Fprintln(os.Stderr, "rotate-master-key: ROOKERY_DB_PASSWORD not set")
		return 1
	}
	dbURL := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("rookery", dbPass),
		Host:     "postgres:5432",
		Path:     "/rookery",
		RawQuery: "sslmode=disable",
	}).String()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rotate-master-key: connect: %v\n", err)
		return 1
	}
	defer pool.Close()

	oldMgr := dkim.NewManager(pool, oldKey)
	newMgr := dkim.NewManager(pool, newKey)

	n, err := oldMgr.ReEncryptKeys(ctx, newMgr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rotate-master-key: %v\n", err)
		return 1
	}

	fmt.Printf("rotate-master-key: re-encrypted %d DKIM key(s) successfully\n", n)
	return 0
}

// -------------------------------------------------------------------------
// relay-client
// -------------------------------------------------------------------------

// runRelayClient implements `rookery relay-client {create,list,revoke}` — the
// lifecycle for downstream relay-client credentials (ADR-0030 §3, Phase B).
// The rookery dispatcher (./rookery relay-client ...) execs this in the running
// container; it is not intended for direct invocation.
func runRelayClient(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: rookery relay-client <create|list|revoke> ...")
		return 1
	}

	cfg, err := loadConfigForCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay-client: %v\n", err)
		return 1
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DBUrl())
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay-client: connect: %v\n", err)
		return 1
	}
	defer pool.Close()

	switch args[0] {
	case "create":
		return relayClientCreate(ctx, pool, cfg, args[1:])
	case "list":
		return relayClientList(ctx, pool)
	case "revoke":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: rookery relay-client revoke <username>")
			return 1
		}
		return relayClientRevoke(ctx, pool, args[1])
	default:
		fmt.Fprintf(os.Stderr, "relay-client: unknown subcommand %q\n", args[0])
		return 1
	}
}

func relayClientCreate(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, args []string) int {
	var label string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--label" && i+1 < len(args):
			label = args[i+1]
			i++
		case len(args[i]) > 8 && args[i][:8] == "--label=":
			label = args[i][8:]
		}
	}

	username := "relay-" + randHex(6)
	secret := randHex(24)
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay-client: hash secret: %v\n", err)
		return 1
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO relay_clients (username, secret_hash, label)
		VALUES ($1, $2, $3)
	`, username, string(hash), label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay-client: insert: %v\n", err)
		return 1
	}

	fmt.Printf(`Relay client created.

  username: %s
  secret:   %s
  label:    %q

This secret is shown ONCE and is not recoverable — only its hash is stored.
Hand the username + secret to the downstream operator out of band, along with
the config block below for their rookery.toml:

[smtp.smarthost]
enabled     = true
host        = %q
port        = 587
username    = %q
require_tls = true
auth        = true

And in their .env:

  ROOKERY_SMTP_RELAY_PASSWORD=%s

Revoke any time with: rookery relay-client revoke %s
`, username, secret, label, cfg.Domain, username, secret, username)
	return 0
}

func relayClientList(ctx context.Context, pool *pgxpool.Pool) int {
	rows, err := pool.Query(ctx, `
		SELECT username, label, enabled, rate_per_hour, created_at, last_used_at
		FROM   relay_clients
		ORDER  BY created_at
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay-client: query: %v\n", err)
		return 1
	}
	defer rows.Close()

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "USERNAME\tENABLED\tRATE/H\tLABEL\tCREATED\tLAST USED")
	for rows.Next() {
		var username, label string
		var enabled bool
		var ratePerHour int
		var createdAt time.Time
		var lastUsed *time.Time
		if err := rows.Scan(&username, &label, &enabled, &ratePerHour, &createdAt, &lastUsed); err != nil {
			fmt.Fprintf(os.Stderr, "relay-client: scan: %v\n", err)
			return 1
		}
		last := "never"
		if lastUsed != nil {
			last = lastUsed.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%t\t%d\t%s\t%s\t%s\n",
			username, enabled, ratePerHour, label, createdAt.Format("2006-01-02"), last)
	}
	if err := rows.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "relay-client: rows: %v\n", err)
		return 1
	}
	tw.Flush()
	return 0
}

func relayClientRevoke(ctx context.Context, pool *pgxpool.Pool, username string) int {
	tag, err := pool.Exec(ctx,
		`UPDATE relay_clients SET enabled = FALSE WHERE username = $1`, username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "relay-client: revoke: %v\n", err)
		return 1
	}
	if tag.RowsAffected() == 0 {
		fmt.Fprintf(os.Stderr, "relay-client: no client named %q\n", username)
		return 1
	}
	fmt.Printf("relay-client: revoked %s (existing sessions are unaffected until they re-authenticate)\n", username)
	return 0
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return hex.EncodeToString(b)
}

// loadConfigForCLI loads the instance config the same way the server does,
// honoring ROOKERY_CONFIG. Used by CLI subcommands that need the DB URL/domain.
func loadConfigForCLI() (*config.Config, error) {
	cfgPath := os.Getenv("ROOKERY_CONFIG")
	if cfgPath == "" {
		cfgPath = "/etc/rookery/rookery.toml"
	}
	return config.Load(cfgPath)
}

// -------------------------------------------------------------------------
// Server bootstrap helpers
// -------------------------------------------------------------------------

func bootstrapDKIM(ctx context.Context, st *store.Store, cfg *config.Config, dk *dkim.Manager) error {
	var domainID string
	if err := st.DB.QueryRow(ctx,
		`SELECT id FROM domains WHERE domain = $1`, cfg.Domain,
	).Scan(&domainID); err != nil {
		return fmt.Errorf("bootstrap dkim: lookup domain id: %w", err)
	}
	return dk.EnsureKeys(ctx, domainID, cfg.Domain)
}

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

func generateMTASTSID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func runHourlyWorker(ctx context.Context, name string, fn func(context.Context) error) {
	ticker := time.NewTicker(time.Hour)
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
