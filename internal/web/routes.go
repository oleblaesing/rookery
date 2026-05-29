// Package web registers HTTP routes and renders server-side HTML for the
// rookery web interface. All user-facing pages use Go html/template. The
// HTTP API lives under /api/v1/ and is the same interface the web UI consumes;
// it is documented as a stable public contract from Phase 0 onward (see
// docs/api-sketch.md and ADR-0006).
package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
	"rookery/internal/dkim"
	"rookery/internal/domains"
	"rookery/internal/store"
)

// RegisterRoutes mounts all HTTP routes onto r.
func RegisterRoutes(r chi.Router, cfg *config.Config, db *pgxpool.Pool, st *store.Store, dk *dkim.Manager, domMgr *domains.Manager) {
	ss := auth.NewSessionStore(db, cfg)

	// ---- Unauthenticated public endpoints ----
	r.Get("/healthz", handleHealthz(cfg))
	r.Get("/api/v1/status", handleAPIStatus(cfg))

	// Invite landing page (HTML, unauthenticated).
	r.Get("/invite/{token}", handleInvitePage(db, ss, cfg))

	// Login / logout.
	r.Get("/login", handleLoginPage(ss, cfg))
	r.Get("/logout", handleLogoutPage(ss, cfg))

	// ---- API v1 — invite validation (unauthenticated) ----
	r.Get("/api/v1/invites/{token}", handleAPIGetInvite(db, cfg))

	// ---- API v1 — registration (unauthenticated) ----
	r.Post("/api/v1/users/register", handleAPIRegister(db, ss, cfg))

	// ---- API v1 — auth ----
	// Login and logout sit outside the authenticated /api/v1 group: login by
	// definition has no session yet, and logout must work even after the
	// session has expired. CSRF still protects logout — it is mounted with
	// the CSRF middleware so cross-site forms cannot forcibly log a user
	// out.
	csrfAPI := auth.CSRFMiddleware(csrfFailAPI)
	// Challenge endpoint: unauthenticated, no CSRF (GET, no state mutation).
	r.Get("/api/v1/auth/challenge", handleAPILoginChallenge(db, cfg))
	r.Post("/api/v1/auth/login", handleAPILogin(db, ss, cfg))
	r.With(csrfAPI).Post("/api/v1/auth/logout", handleAPILogout(ss))

	// ---- WKD Advanced Method ----
	// Requests arrive at openpgpkey.<domain> via CNAME. We distinguish them
	// by inspecting the Host header. The router below matches both:
	//   - openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>
	//   - <domain>/.well-known/openpgpkey/<domain>/hu/<hash>   (fallback)
	r.Get("/.well-known/openpgpkey/{domain}/hu/{hash}", handleWKDKey(db))
	r.Get("/.well-known/openpgpkey/{domain}/policy", handleWKDPolicy)

	// ---- MTA-STS policy (ADR-0037) ----
	// mta-sts.<domain> CNAMEs to this server; Caddy terminates TLS.
	// Rookery dispatches by Host header inside this handler.
	r.Get("/.well-known/mta-sts.txt", handleMTASTS(domMgr))

	// ---- Caddy on-demand TLS ask endpoint (ADR-0035) ----
	// Called by Caddy before issuing a certificate for any hostname.
	// Not authenticated — Caddy calls it from the same host.
	r.Get("/internal/tls-ask", handleTLSAsk(domMgr))

	// /api/v1/export/{token} — unauthenticated binary download (bearer token auth).
	// Used by curl, the import proxy on instance B, and the download button.
	r.Get("/api/v1/export/{token}", handleAPIExportDownload(db, cfg))

	// ---- Authenticated middleware group ----
	authAPI := auth.Middleware(ss, unauthAPI)
	authHTML := auth.Middleware(ss, unauthHTML)

	// HTML pages (require session cookie; CSRF checked on mutating form POSTs
	// via separate middleware on the POST routes).
	r.Group(func(r chi.Router) {
		r.Use(authHTML)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		})
		r.Get("/settings", handleSettingsPage(db, cfg, domMgr))
		// /export/{token} — session-authenticated; only the owning user can view.
		r.Get("/export/{token}", handleExportPage(db, cfg))
		r.Get("/inbox", handleInboxPage(db, cfg))
		r.Get("/compose", handleComposePage(db, cfg))
		r.Get("/partials/key-status", handleKeyStatusFragment(db))
		r.Get("/messages/{id}", handleReadPage(db, cfg))

		// Form POSTs from HTML pages — these run CSRF middleware inline.
		csrfHTML := auth.CSRFMiddleware(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
		})
		r.With(csrfHTML).Post("/messages/{id}/trash", handleTrashPost(db))
		r.With(csrfHTML).Post("/messages/{id}/delete", handleDeletePermanentPost(db, st))

		// Domain verification status fragment (GET = read-only, no CSRF needed).
		r.Get("/partials/domains/{id}/verify-status", handleDomainVerifyStatusFragment(domMgr))
	})

	// API v1 — authenticated endpoints.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authAPI)
		r.Use(csrfAPI)

		// Users.
		r.Get("/users/me", handleAPIGetMe(db))
		r.Get("/users/me/sessions", handleAPIListSessions(ss))
		r.Delete("/users/me/sessions/{id}", handleAPIDeleteSession(db, ss))

		// Account deletion (challenge/response, then irreversible delete).
		r.Post("/users/me/deletion/challenge", handleAPIDeletionChallenge(db))
		r.Post("/users/me/deletion", handleAPIDeletion(db, ss, st))

		// Keys.
		r.Get("/keys/me", handleAPIGetMyKey(db))
		r.Put("/keys/me", handleAPIPutMyKey(db))
		r.Get("/keys/lookup", handleAPIKeyLookup(db))

		// Messages.
		r.Get("/messages", handleAPIListMessages(db))
		r.Get("/messages/{id}", handleAPIGetMessage(db))
		r.Get("/messages/{id}/raw", handleAPIGetMessageRaw(db, st))
		r.Get("/messages/{id}/attachments/{index}", handleAPIGetAttachment(db, st))
		r.Patch("/messages/{id}", handleAPIPatchMessage(db))
		r.Delete("/messages/{id}", handleAPIDeleteMessage(db, st))

		// Outbound mail and drafts (Phase 2).
		r.Post("/messages", handleAPISendMessage(db, st, dk, cfg))
		r.Post("/messages/drafts", handleAPICreateDraft(db))
		r.Get("/messages/drafts/{id}", handleAPIGetDraftByID(db))
		r.Put("/messages/drafts/{id}", handleAPIUpdateDraft(db))
		r.Delete("/messages/drafts/{id}", handleAPIDeleteDraftByID(db))

		// Custom domains (Phase 4).
		r.Post("/domains", handleAPIRegisterDomain(domMgr))
		r.Get("/domains", handleAPIListDomains(domMgr))
		r.Get("/domains/{id}", handleAPIGetDomain(domMgr))
		r.Patch("/domains/{id}", handleAPIPatchDomain(domMgr))
		r.Delete("/domains/{id}", handleAPIDeleteDomain(domMgr))
		r.Post("/domains/{id}/verify", handleAPIVerifyDomain(domMgr))

		// Export / import (per-user data portability, ADR-0039).
		r.Post("/users/me/export", handleAPIExport(db, st, cfg))
		r.Get("/users/me/export/status", handleAPIExportStatus(db))
		r.Get("/users/me/import/fetch", handleAPIImportFetch())
		r.Post("/users/me/import", handleAPIImport(db, st))
	})

	// Static assets. The path is tried in order:
	//   1. /opt/rookery/web/static  — container image layout (production)
	//   2. web/static               — repo layout (local dev with `go run`)
	staticDir := "/opt/rookery/web/static"
	if _, err := os.Stat(staticDir); err != nil {
		staticDir = "web/static"
	}
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
}

// -------------------------------------------------------------------------
// Phase 0 handlers (unchanged, kept here for reference)
// -------------------------------------------------------------------------

type healthzResponse struct {
	Status    string    `json:"status"`
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
}

func handleHealthz(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(healthzResponse{
			Status:    "ok",
			Domain:    cfg.Domain,
			Timestamp: time.Now().UTC(),
		}); err != nil {
			slog.Error("healthz: encode response", "err", err)
		}
	}
}

type apiStatusResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Domain  string `json:"domain"`
}

func handleAPIStatus(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(apiStatusResponse{
			Status:  "ok",
			Version: "0.1.0-phase1",
			Domain:  cfg.Domain,
		}); err != nil {
			slog.Error("api/v1/status: encode response", "err", err)
		}
	}
}
