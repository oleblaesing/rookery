package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
)

// contextKey is private so context values can't collide with other packages'.
type contextKey int

const (
	ctxKeySession contextKey = iota
	ctxKeyUserID
)

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

			// Resync the CSRF cookie to the session token, but only when it's
			// missing or stale, to avoid duplicate Set-Cookie headers per page load.
			if c, err := r.Cookie(CSRFCookieName); err != nil || c.Value != session.CSRFToken {
				SetCSRFCookie(w, r, session.CSRFToken)
			}

			ctx := context.WithValue(r.Context(), ctxKeySession, session)
			ctx = context.WithValue(ctx, ctxKeyUserID, session.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(ctxKeySession).(*Session)
	return s
}

func UserIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyUserID).(string)
	return id
}

func CSRFTokenFromContext(ctx context.Context) string {
	s := SessionFromContext(ctx)
	if s == nil {
		return ""
	}
	return s.CSRFToken
}

// Defence-in-depth on top of SameSite=Lax.
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
			token := r.Header.Get(CSRFHeaderName)
			if token == "" {
				token = r.FormValue("_csrf") // plain HTML form POSTs
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(csrfCookie.Value)) != 1 {
				onFail(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
