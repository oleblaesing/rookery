package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
)

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type apiErrorWrapper struct {
	Error apiError `json:"error"`
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("respondJSON encode", "err", err)
	}
}

func respondError(w http.ResponseWriter, status int, code, message string) {
	respondJSON(w, status, apiErrorWrapper{
		Error: apiError{Code: code, Message: message},
	})
}

func respondErrorDetail(w http.ResponseWriter, status int, code, message string, details any) {
	respondJSON(w, status, apiErrorWrapper{
		Error: apiError{Code: code, Message: message, Details: details},
	})
}

func unauthAPI(w http.ResponseWriter, _ *http.Request) {
	respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required.")
}

func csrfFailAPI(w http.ResponseWriter, _ *http.Request) {
	respondError(w, http.StatusForbidden, "CSRF_INVALID", "CSRF token missing or invalid.")
}

// unauthHTML routes through /logout (which clears localStorage key material)
// rather than straight to /login, preserving the original URL in next=.
func unauthHTML(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/logout?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
}
