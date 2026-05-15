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
	"time"

	"github.com/go-chi/chi/v5"

	"rookery/internal/config"
)

// RegisterRoutes mounts all HTTP routes onto r.
func RegisterRoutes(r chi.Router, cfg *config.Config) {
	r.Get("/healthz", handleHealthz(cfg))

	// API v1 stub — handlers will be fleshed out in Phase 1 and beyond.
	// The resource model is documented in docs/api-sketch.md.
	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/status", handleAPIStatus(cfg))
	})
}

// healthzResponse is returned by /healthz.
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

// apiStatusResponse is returned by GET /api/v1/status.
// This is the Phase 0 "is the server up" endpoint; it will be extended in
// Phase 1 to include database connectivity and queue health.
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
			Version: "0.0.0-phase0",
			Domain:  cfg.Domain,
		}); err != nil {
			slog.Error("api/v1/status: encode response", "err", err)
		}
	}
}
