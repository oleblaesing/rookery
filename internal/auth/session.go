package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/config"
)

// sessionExecer is the subset of *pgxpool.Pool and pgx.Tx needed to insert
// a session row. Both types satisfy it. Using an interface lets callers
// choose between the pool-level Create and the transactional CreateInTx
// path without duplicating logic.
type sessionExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const (
	// SessionCookieName is the HttpOnly session cookie placed in the browser.
	SessionCookieName = "rookery_session"

	// sessionTokenBytes is the length of the raw random token before hex-encoding.
	// 32 bytes → 256 bits of entropy → 64-char hex string in the cookie.
	sessionTokenBytes = 32

	// CSRFCookieName is the CSRF token cookie (not HttpOnly so JS can read it).
	CSRFCookieName = "rookery_csrf"
	// CSRFHeaderName is the header the browser sends the CSRF token in.
	CSRFHeaderName = "X-CSRF-Token"
)

// Session represents an active login session.
type Session struct {
	ID        string
	UserID    string
	TokenHash string // SHA-256 of the raw cookie value; never exposed
	CSRFToken string // synchronizer token; stable for the session
	LastSeen  time.Time
	CreatedAt time.Time
}

// SessionStore manages sessions in Postgres.
type SessionStore struct {
	db  *pgxpool.Pool
	cfg *config.Config
}

// NewSessionStore creates a SessionStore backed by the given pool.
func NewSessionStore(db *pgxpool.Pool, cfg *config.Config) *SessionStore {
	return &SessionStore{db: db, cfg: cfg}
}

// Create inserts a new session for userID and returns the raw token (to be
// placed in the cookie) and the CSRF token for this session. The session
// token is never stored — only its SHA-256 hash. The CSRF token is stored
// verbatim and remains stable for the lifetime of the session.
func (ss *SessionStore) Create(ctx context.Context, userID string) (rawToken, csrfToken string, err error) {
	return ss.createWith(ctx, ss.db, userID)
}

// CreateInTx is the transactional variant of Create. Callers that perform
// session creation as part of a larger atomic operation (e.g. registration,
// where the invite must not be consumed if session creation fails) pass
// the open transaction here. The same rules as Create apply.
func (ss *SessionStore) CreateInTx(ctx context.Context, tx pgx.Tx, userID string) (rawToken, csrfToken string, err error) {
	return ss.createWith(ctx, tx, userID)
}

func (ss *SessionStore) createWith(ctx context.Context, q sessionExecer, userID string) (rawToken, csrfToken string, err error) {
	rawToken, err = GenerateToken(sessionTokenBytes)
	if err != nil {
		return "", "", err
	}
	csrfToken, err = GenerateToken(32)
	if err != nil {
		return "", "", err
	}
	tokenHash := SHA256Hex([]byte(rawToken))

	_, err = q.Exec(ctx, `
		INSERT INTO sessions (user_id, token_hash, csrf_token)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, csrfToken)
	if err != nil {
		return "", "", fmt.Errorf("session: create: %w", err)
	}
	return rawToken, csrfToken, nil
}

// Get looks up the session for rawToken, refreshes last_seen, and returns
// the Session. Returns ErrSessionNotFound if the token is unknown or expired.
func (ss *SessionStore) Get(ctx context.Context, rawToken string) (*Session, error) {
	tokenHash := SHA256Hex([]byte(rawToken))
	expiryDays := ss.cfg.Policy.SessionExpiryDays

	var s Session
	err := ss.db.QueryRow(ctx, `
		UPDATE sessions
		SET    last_seen = now()
		WHERE  token_hash = $1
		  AND  last_seen > now() - make_interval(days => $2)
		RETURNING id, user_id, token_hash, csrf_token, last_seen, created_at
	`, tokenHash, expiryDays).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.CSRFToken, &s.LastSeen, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("session: get: %w", err)
	}
	return &s, nil
}

// Delete invalidates a session by its ID (used by logout and session revoke).
func (ss *SessionStore) Delete(ctx context.Context, sessionID string) error {
	_, err := ss.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	if err != nil {
		return fmt.Errorf("session: delete: %w", err)
	}
	return nil
}

// DeleteByToken invalidates the session identified by the raw cookie token.
func (ss *SessionStore) DeleteByToken(ctx context.Context, rawToken string) error {
	tokenHash := SHA256Hex([]byte(rawToken))
	_, err := ss.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return fmt.Errorf("session: delete by token: %w", err)
	}
	return nil
}

// ListByUser returns all active (non-expired) sessions for a user, ordered
// by last_seen descending. No IP or UA is returned — pseudonymity default.
func (ss *SessionStore) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	expiryDays := ss.cfg.Policy.SessionExpiryDays
	rows, err := ss.db.Query(ctx, `
		SELECT id, user_id, token_hash, csrf_token, last_seen, created_at
		FROM   sessions
		WHERE  user_id = $1
		  AND  last_seen > now() - make_interval(days => $2)
		ORDER  BY last_seen DESC
	`, userID, expiryDays)
	if err != nil {
		return nil, fmt.Errorf("session: list: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CSRFToken, &s.LastSeen, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("session: list scan: %w", err)
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

// ErrSessionNotFound is returned when a session token is unknown or expired.
var ErrSessionNotFound = errors.New("session not found or expired")

// isSecure returns true when the request arrived over HTTPS — either directly
// (r.TLS != nil) or via a TLS-terminating proxy that set X-Forwarded-Proto.
// Cookies must not be marked Secure over plain HTTP or browsers will drop them.
func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

// SetCookie writes the session cookie to the response. Secure is set only
// when the connection is HTTPS so that local HTTP dev works without browsers
// silently dropping the cookie.
func SetCookie(w http.ResponseWriter, r *http.Request, rawToken string, expiryDays int) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    rawToken,
		Path:     "/",
		MaxAge:   expiryDays * 86400,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie removes the session cookie from the browser.
func ClearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// SetCSRFCookie writes the CSRF token cookie. Not HttpOnly so that
// partials.js can read it and include it in the X-CSRF-Token header.
func SetCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // JS must read this
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// EnsureUnauthCSRFCookie returns a CSRF token suitable for unauthenticated
// forms (login, invite). If the request already carries a rookery_csrf
// cookie, its value is reused so concurrent open tabs all post the same
// token. Otherwise a fresh token is generated and the cookie is set on the
// response. The token is stable for the browser's cookie lifetime.
func EnsureUnauthCSRFCookie(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(CSRFCookieName); err == nil && c.Value != "" {
		return c.Value, nil
	}
	token, err := GenerateToken(32)
	if err != nil {
		return "", err
	}
	SetCSRFCookie(w, r, token)
	return token, nil
}

// TokenFromRequest extracts the raw session token from the request cookie.
// Returns ("", false) if the cookie is absent or empty.
func TokenFromRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}
