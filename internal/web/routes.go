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

func RegisterRoutes(r chi.Router, cfg *config.Config, db *pgxpool.Pool, st *store.Store, dk *dkim.Manager, domMgr *domains.Manager) {
	ss := auth.NewSessionStore(db, cfg)

	if cfg.OnionAddress != "" {
		r.Use(onionLocation(cfg.OnionAddress))
	}

	r.Get("/healthz", handleHealthz(cfg))
	r.Get("/api/v1/status", handleAPIStatus(cfg))

	r.Get("/invite/{token}", handleInvitePage(db, ss, cfg))

	r.Get("/login", handleLoginPage(ss, cfg))
	r.Get("/logout", handleLogoutPage(ss, cfg))

	r.Get("/migrate", handleMigratePage(ss, cfg))
	r.Get("/jslicense", handleJSLicensePage(cfg))

	r.Get("/api/v1/invites/{token}", handleAPIGetInvite(db, cfg))
	r.Post("/api/v1/users/register", handleAPIRegister(db, ss, cfg))

	// Login/logout live outside the authenticated group: login has no session
	// yet, and logout must work after a session has expired. CSRF still guards
	// logout so a cross-site form can't forcibly log a user out.
	csrfAPI := auth.CSRFMiddleware(csrfFailAPI)
	r.Get("/api/v1/auth/challenge", handleAPILoginChallenge(db, cfg)) // GET, no CSRF
	r.Post("/api/v1/auth/login", handleAPILogin(db, ss, cfg))
	r.With(csrfAPI).Post("/api/v1/auth/logout", handleAPILogout(ss))

	// WKD requests reach openpgpkey.<domain> via CNAME; this matches both that
	// host and the bare <domain> fallback, dispatching on the Host header.
	r.Get("/.well-known/openpgpkey/{domain}/hu/{hash}", handleWKDKey(db))
	r.Get("/.well-known/openpgpkey/{domain}/policy", handleWKDPolicy)

	// mta-sts.<domain> CNAMEs here; the handler dispatches on Host.
	r.Get("/.well-known/mta-sts.txt", handleMTASTS(domMgr))

	// Caddy calls this from the same host before issuing a cert.
	r.Get("/internal/tls-ask", handleTLSAsk(domMgr))

	// Unauthenticated bearer-token download, used by curl, the import proxy, and
	// the download button.
	r.Get("/api/v1/export/{token}", handleAPIExportDownload(db, cfg))

	// Unauthenticated SSRF-safe proxy: the migration page fetches the encrypted
	// archive before any account exists. Security is in handleAPIImportFetch.
	r.Get("/api/v1/import/fetch", handleAPIImportFetch())

	authAPI := auth.Middleware(ss, unauthAPI)
	authHTML := auth.Middleware(ss, unauthHTML)

	r.Group(func(r chi.Router) {
		r.Use(authHTML)

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/inbox", http.StatusSeeOther)
		})
		r.Get("/settings", handleSettingsPage(db, cfg, domMgr))
		r.Get("/export/{token}", handleExportPage(db, cfg)) // owning user only
		r.Get("/inbox", handleInboxPage(db, cfg))
		r.Get("/compose", handleComposePage(db, cfg))
		r.Get("/partials/key-status", handleKeyStatusFragment(db))
		r.Get("/messages/{id}", handleReadPage(db, cfg))

		// Mutating form POSTs run CSRF inline; GET fragments below don't need it.
		csrfHTML := auth.CSRFMiddleware(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
		})
		r.With(csrfHTML).Post("/messages/{id}/trash", handleTrashPost(db))
		r.With(csrfHTML).Post("/messages/{id}/delete", handleDeletePermanentPost(db, st))

		r.Get("/partials/domains/{id}/verify-status", handleDomainVerifyStatusFragment(domMgr))
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authAPI)
		r.Use(csrfAPI)

		r.Get("/users/me", handleAPIGetMe(db))
		r.Get("/users/me/sessions", handleAPIListSessions(ss))
		r.Delete("/users/me/sessions/{id}", handleAPIDeleteSession(db, ss))

		r.Post("/users/me/deletion/challenge", handleAPIDeletionChallenge(db))
		r.Post("/users/me/deletion", handleAPIDeletion(db, ss, st))

		r.Get("/keys/me", handleAPIGetMyKey(db))
		r.Put("/keys/me", handleAPIPutMyKey(db))
		r.Post("/keys/me/rotation/challenge", handleAPIRotationChallenge(db))
		r.Post("/keys/me/rotation", handleAPIRotateKey(db))
		r.Get("/keys/lookup", handleAPIKeyLookup(db))

		r.Get("/messages", handleAPIListMessages(db))
		r.Get("/messages/{id}", handleAPIGetMessage(db))
		r.Get("/messages/{id}/raw", handleAPIGetMessageRaw(db, st))
		r.Get("/messages/{id}/attachments/{index}", handleAPIGetAttachment(db, st))
		r.Patch("/messages/{id}", handleAPIPatchMessage(db))
		r.Delete("/messages/{id}", handleAPIDeleteMessage(db, st))

		r.Post("/messages", handleAPISendMessage(db, st, dk, cfg))
		r.Post("/messages/drafts", handleAPICreateDraft(db))
		r.Get("/messages/drafts/{id}", handleAPIGetDraftByID(db))
		r.Put("/messages/drafts/{id}", handleAPIUpdateDraft(db))
		r.Delete("/messages/drafts/{id}", handleAPIDeleteDraftByID(db))

		r.Post("/domains", handleAPIRegisterDomain(domMgr))
		r.Get("/domains", handleAPIListDomains(domMgr))
		r.Get("/domains/{id}", handleAPIGetDomain(domMgr))
		r.Patch("/domains/{id}", handleAPIPatchDomain(domMgr))
		r.Delete("/domains/{id}", handleAPIDeleteDomain(domMgr))
		r.Post("/domains/{id}/verify", handleAPIVerifyDomain(domMgr))

		r.Post("/users/me/export", handleAPIExport(db, st, cfg))
		r.Get("/users/me/export/status", handleAPIExportStatus(db))
		r.Post("/users/me/import", handleAPIImport(db, st))
	})

	// Container image layout first, repo layout for local `go run`.
	staticDir := "/opt/rookery/web/static"
	if _, err := os.Stat(staticDir); err != nil {
		staticDir = "static"
	}
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
}

// Skips requests that already arrive over the onion so we don't advertise it to
// itself. The scheme is http:// because Tor provides the transport encryption;
// Tor Browser only acts on it for HTTPS document loads, so it's inert on
// plain-HTTP localhost and on API/asset responses.
func onionLocation(onion string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != onion {
				w.Header().Set("Onion-Location", "http://"+onion+r.URL.RequestURI())
			}
			next.ServeHTTP(w, r)
		})
	}
}

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
			Version: "0.1.0",
			Domain:  cfg.Domain,
		}); err != nil {
			slog.Error("api/v1/status: encode response", "err", err)
		}
	}
}
