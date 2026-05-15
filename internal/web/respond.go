package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
)

// apiError is the stable JSON error envelope described in docs/api-sketch.md.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type apiErrorWrapper struct {
	Error apiError `json:"error"`
}

// respondJSON encodes v as JSON with status code.
func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("respondJSON encode", "err", err)
	}
}

// respondError writes a JSON error envelope.
func respondError(w http.ResponseWriter, status int, code, message string) {
	respondJSON(w, status, apiErrorWrapper{
		Error: apiError{Code: code, Message: message},
	})
}

// respondErrorDetail writes a JSON error envelope with a details object.
func respondErrorDetail(w http.ResponseWriter, status int, code, message string, details any) {
	respondJSON(w, status, apiErrorWrapper{
		Error: apiError{Code: code, Message: message, Details: details},
	})
}

// unauthAPI is the onUnauth callback for API routes — returns 401 JSON.
func unauthAPI(w http.ResponseWriter, _ *http.Request) {
	respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required.")
}

// csrfFailAPI is the onFail callback for API CSRF middleware — returns 403 JSON.
func csrfFailAPI(w http.ResponseWriter, _ *http.Request) {
	respondError(w, http.StatusForbidden, "CSRF_INVALID", "CSRF token missing or invalid.")
}

// unauthHTML redirects to the logout page, which clears localStorage key
// material before forwarding to /login. The original URL is preserved as the
// next= query parameter so the user lands back where they were after
// re-authenticating.
func unauthHTML(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/logout?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
}
