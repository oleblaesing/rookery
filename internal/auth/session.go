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

// sessionExecer lets createWith run against either the pool or an open tx.
type sessionExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const (
	SessionCookieName = "rookery_session"

	sessionTokenBytes = 32

	CSRFCookieName = "rookery_csrf" // not HttpOnly: JS reads it for the header
	CSRFHeaderName = "X-CSRF-Token"
)

type Session struct {
	ID        string
	UserID    string
	TokenHash string // SHA-256 of the raw cookie value; never exposed
	CSRFToken string
	LastSeen  time.Time
	CreatedAt time.Time
}

type SessionStore struct {
	db  *pgxpool.Pool
	cfg *config.Config
}

func NewSessionStore(db *pgxpool.Pool, cfg *config.Config) *SessionStore {
	return &SessionStore{db: db, cfg: cfg}
}

// Only the token's SHA-256 hash is stored.
func (ss *SessionStore) Create(ctx context.Context, userID string) (rawToken, csrfToken string, err error) {
	return ss.createWith(ctx, ss.db, userID)
}

// Lets session creation join a caller's transaction, so registration doesn't
// consume the invite if session creation fails.
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

func (ss *SessionStore) Delete(ctx context.Context, sessionID string) error {
	_, err := ss.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	if err != nil {
		return fmt.Errorf("session: delete: %w", err)
	}
	return nil
}

func (ss *SessionStore) DeleteByToken(ctx context.Context, rawToken string) error {
	tokenHash := SHA256Hex([]byte(rawToken))
	_, err := ss.db.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	if err != nil {
		return fmt.Errorf("session: delete by token: %w", err)
	}
	return nil
}

// No IP or UA is returned, by pseudonymity default.
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

var ErrSessionNotFound = errors.New("session not found or expired")

// Marking a cookie Secure over plain HTTP makes browsers drop it, so cookie
// setters gate Secure on this (true also for a TLS-terminating proxy's
// X-Forwarded-Proto).
func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

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

func SetCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // partials.js must read this for the X-CSRF-Token header
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// Reuses an existing rookery_csrf cookie so concurrent tabs post the same token.
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

func TokenFromRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}
