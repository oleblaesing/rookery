package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
)

// contextKey is a private type for context values to avoid collisions.
type contextKey int

const (
	ctxKeySession contextKey = iota
	ctxKeyUserID
)

// Middleware returns an HTTP middleware that validates the session cookie.
// On success, it injects the Session and UserID into the request context,
// and re-emits the CSRF cookie with the session's stable CSRF token (so the
// cookie value never drifts away from the synchronizer token embedded in
// rendered forms, regardless of how many tabs the user has open).
// On failure (no cookie, unknown token, expired), it calls onUnauth — which
// for API endpoints returns 401 JSON, and for HTML pages redirects to login.
func Middleware(ss *SessionStore, onUnauth func(w http.ResponseWriter, r *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken, ok := TokenFromRequest(r)
			if !ok {
				onUnauth(w, r)
				return
			}
			session, err := ss.Get(r.Context(), rawToken)
			if err != nil {
				ClearCookie(w, r)
				onUnauth(w, r)
				return
			}

			// Keep the rookery_csrf cookie in sync with the session's stable
			// CSRF token. We only write the cookie if it is missing or wrong;
			// otherwise repeated requests during one page load would generate
			// duplicate Set-Cookie headers for no benefit.
			if c, err := r.Cookie(CSRFCookieName); err != nil || c.Value != session.CSRFToken {
				SetCSRFCookie(w, r, session.CSRFToken)
			}

			ctx := context.WithValue(r.Context(), ctxKeySession, session)
			ctx = context.WithValue(ctx, ctxKeyUserID, session.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionFromContext retrieves the Session injected by Middleware.
// Returns nil if not present (should not happen inside authenticated routes).
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(ctxKeySession).(*Session)
	return s
}

// UserIDFromContext retrieves the authenticated user's UUID from context.
// Returns "" if not present.
func UserIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyUserID).(string)
	return id
}

// CSRFTokenFromContext returns the session's stable CSRF token, suitable
// for embedding in rendered forms. Returns "" outside of an authenticated
// request (i.e. when no Session is in context).
func CSRFTokenFromContext(ctx context.Context) string {
	s := SessionFromContext(ctx)
	if s == nil {
		return ""
	}
	return s.CSRFToken
}

// CSRFMiddleware verifies the synchronizer CSRF token on state-changing
// requests (POST, PUT, PATCH, DELETE). It checks:
//
//  1. The X-CSRF-Token request header, OR
//  2. A _csrf field in application/x-www-form-urlencoded bodies.
//
// The token is compared against the rookery_csrf cookie value.
// GET, HEAD, and OPTIONS pass through unconditionally.
//
// Safe-method pass-through + SameSite=Lax on the session cookie together
// mean a network attacker needs both conditions to exploit: a cross-site
// form POST (blocked by SameSite) or a credentialed fetch (blocked by CORS
// default policy unless the target relaxes it). The synchronizer token is
// an additional layer per §11.2.
func CSRFMiddleware(onFail func(w http.ResponseWriter, r *http.Request)) func(http.Handler) http.Handler {
	safeMethods := map[string]bool{
		http.MethodGet:     true,
		http.MethodHead:    true,
		http.MethodOptions: true,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if safeMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}
			csrfCookie, err := r.Cookie(CSRFCookieName)
			if err != nil || csrfCookie.Value == "" {
				onFail(w, r)
				return
			}
			// Check header first (used by partials.js and API clients).
			token := r.Header.Get(CSRFHeaderName)
			if token == "" {
				// Fallback: form field (used by plain HTML form POSTs).
				token = r.FormValue("_csrf")
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(csrfCookie.Value)) != 1 {
				onFail(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
