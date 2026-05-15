package web

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
)

// challengeTTL is how long an issued challenge nonce remains valid.
// Short enough to limit replay windows; long enough to be usable on slow
// connections.
const challengeTTL = 5 * time.Minute

// -------------------------------------------------------------------------
// GET /api/v1/auth/challenge?address=…
//
// Issues a single-use nonce for the given address. The client must sign
// this nonce with their PGP private key and POST the signature to
// /api/v1/auth/login within challengeTTL.
//
// To prevent user-enumeration via timing, we always insert a challenge row
// regardless of whether the address exists — the existence check happens at
// claim time.
// -------------------------------------------------------------------------

type challengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
}

func handleAPILoginChallenge(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		address := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("address")))
		if address == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "address query parameter is required.")
			return
		}
		if !strings.Contains(address, "@") {
			address = address + "@" + cfg.Domain
		}

		nonce, err := auth.GenerateToken(32) // 64-char hex string
		if err != nil {
			slog.Error("login challenge: generate nonce", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not generate challenge.")
			return
		}

		var challengeID string
		err = db.QueryRow(r.Context(), `
			INSERT INTO auth_challenges (address, nonce)
			VALUES ($1, $2)
			RETURNING id
		`, address, nonce).Scan(&challengeID)
		if err != nil {
			slog.Error("login challenge: insert", "address", address, "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not store challenge.")
			return
		}

		slog.Info("login challenge: issued", "address", address, "challenge_id", challengeID)
		respondJSON(w, http.StatusOK, challengeResponse{
			ChallengeID: challengeID,
			Nonce:       nonce,
		})
	}
}

// -------------------------------------------------------------------------
// POST /api/v1/auth/login
//
// Verifies a detached PGP signature of a previously issued challenge nonce.
// On success, creates a session and sets the session + CSRF cookies.
//
// Request body:
//   {
//     "address":          "alice@example.com",
//     "challenge_id":     "<uuid>",
//     "signed_challenge": "<armored detached PGP signature>"
//   }
// -------------------------------------------------------------------------

type loginRequest struct {
	Address         string `json:"address"`
	ChallengeID     string `json:"challenge_id"`
	SignedChallenge string `json:"signed_challenge"`
}

type userProfile struct {
	ID                   string  `json:"id"`
	PrimaryAddress       string  `json:"primary_address"`
	DisplayName          string  `json:"display_name"`
	PublicKeyFingerprint string  `json:"public_key_fingerprint"`
	CreatedAt            string  `json:"created_at"`
	QuotaBytes           int64   `json:"quota_bytes"`
	UsedBytes            int64   `json:"used_bytes"`
	SuspendedAt          *string `json:"suspended_at"`
	TOTPEnabled          bool    `json:"totp_enabled"`
}

func handleAPILogin(db *pgxpool.Pool, ss *auth.SessionStore, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}
		req.Address = strings.ToLower(strings.TrimSpace(req.Address))
		if req.Address == "" || req.ChallengeID == "" || req.SignedChallenge == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "address, challenge_id, and signed_challenge are required.")
			return
		}
		if !strings.Contains(req.Address, "@") {
			req.Address = req.Address + "@" + cfg.Domain
		}

		// Claim the challenge: verify it exists, belongs to this address,
		// has not been used, and has not expired. Mark it used atomically.
		var nonce string
		err := db.QueryRow(r.Context(), `
			UPDATE auth_challenges
			SET    used_at = now()
			WHERE  id       = $1
			  AND  address  = $2
			  AND  used_at  IS NULL
			  AND  created_at > now() - make_interval(secs => $3)
			RETURNING nonce
		`, req.ChallengeID, req.Address, challengeTTL.Seconds()).Scan(&nonce)
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("login: challenge claim failed — not found, already used, wrong address, or expired",
				"address", req.Address,
				"challenge_id", req.ChallengeID,
			)
			respondError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid or expired challenge.")
			return
		}
		if err != nil {
			slog.Error("login: challenge claim query", "address", req.Address, "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "An unexpected error occurred.")
			return
		}
		slog.Info("login: challenge claimed", "address", req.Address, "challenge_id", req.ChallengeID)

		// Fetch the user and their stored public key.
		user, armoredPublicKey, err := fetchUserByAddressWithKey(r.Context(), db, req.Address)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				slog.Info("login: user or active key not found", "address", req.Address)
				respondError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid or expired challenge.")
				return
			}
			slog.Error("login: fetch user", "address", req.Address, "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "An unexpected error occurred.")
			return
		}

		if user.SuspendedAt != nil {
			respondError(w, http.StatusForbidden, "ACCOUNT_SUSPENDED", "This account is suspended.")
			return
		}

		// Verify the detached PGP signature of the nonce.
		if err := verifyDetachedSignature(armoredPublicKey, nonce, req.SignedChallenge); err != nil {
			slog.Info("login: signature verification failed", "address", req.Address, "err", err)
			respondError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Signature verification failed.")
			return
		}

		rawToken, csrfToken, err := ss.Create(r.Context(), user.ID)
		if err != nil {
			slog.Error("login: create session", "address", req.Address, "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not create session.")
			return
		}
		auth.SetCookie(w, r, rawToken, cfg.Policy.SessionExpiryDays)
		auth.SetCSRFCookie(w, r, csrfToken)
		respondJSON(w, http.StatusOK, user)
	}
}

// verifyDetachedSignature checks that armoredSig is a valid detached PGP
// signature of plaintext made by the key in armoredPublicKey.
func verifyDetachedSignature(armoredPublicKey, plaintext, armoredSig string) error {
	keyBlock, err := armor.Decode(strings.NewReader(armoredPublicKey))
	if err != nil {
		return err
	}
	keyRing, err := pgpcrypto.ReadKeyRing(keyBlock.Body)
	if err != nil {
		return err
	}

	sigBlock, err := armor.Decode(strings.NewReader(armoredSig))
	if err != nil {
		return err
	}

	_, err = pgpcrypto.CheckDetachedSignature(
		keyRing,
		strings.NewReader(plaintext),
		sigBlock.Body,
		&packet.Config{},
	)
	return err
}

// -------------------------------------------------------------------------
// POST /api/v1/auth/logout
// -------------------------------------------------------------------------

func handleAPILogout(ss *auth.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawToken, ok := auth.TokenFromRequest(r)
		if ok {
			// Best-effort — ignore errors (already expired tokens are fine).
			_ = ss.DeleteByToken(r.Context(), rawToken)
		}
		auth.ClearCookie(w, r)
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// -------------------------------------------------------------------------
// GET /api/v1/users/me
// -------------------------------------------------------------------------

func handleAPIGetMe(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch user.")
			return
		}
		respondJSON(w, http.StatusOK, user)
	}
}

// -------------------------------------------------------------------------
// GET /api/v1/users/me/sessions
// -------------------------------------------------------------------------

type sessionSummary struct {
	ID        string    `json:"id"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
	IsCurrent bool      `json:"is_current"`
}

func handleAPIListSessions(ss *auth.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		currentSession := auth.SessionFromContext(r.Context())

		sessions, err := ss.ListByUser(r.Context(), userID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not list sessions.")
			return
		}

		summaries := make([]sessionSummary, len(sessions))
		for i, s := range sessions {
			summaries[i] = sessionSummary{
				ID:        s.ID,
				LastSeen:  s.LastSeen,
				CreatedAt: s.CreatedAt,
				IsCurrent: currentSession != nil && s.ID == currentSession.ID,
			}
		}
		respondJSON(w, http.StatusOK, map[string]any{"items": summaries})
	}
}

// -------------------------------------------------------------------------
// DELETE /api/v1/users/me/sessions/{id}
// -------------------------------------------------------------------------

func handleAPIDeleteSession(db *pgxpool.Pool, ss *auth.SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		sessionID := r.PathValue("id")

		// Verify the session belongs to this user before deleting.
		var ownerID string
		err := db.QueryRow(r.Context(),
			`SELECT user_id FROM sessions WHERE id = $1`, sessionID,
		).Scan(&ownerID)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "SESSION_NOT_FOUND", "Session not found.")
			return
		}
		if err != nil || ownerID != userID {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "Cannot revoke another user's session.")
			return
		}

		if err := ss.Delete(r.Context(), sessionID); err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not revoke session.")
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// -------------------------------------------------------------------------
// DB helpers
// -------------------------------------------------------------------------

// dbUser is the raw row returned by user queries (before converting to the
// JSON-facing userProfile).
type dbUser struct {
	id                   string
	primaryAddress       string
	displayName          string
	publicKeyFingerprint string
	createdAt            time.Time
	quotaBytes           int64
	usedBytes            int64
	suspendedAt          *time.Time
	totpSecret           *string
}

func (u *dbUser) toProfile() *userProfile {
	p := &userProfile{
		ID:                   u.id,
		PrimaryAddress:       u.primaryAddress,
		DisplayName:          u.displayName,
		PublicKeyFingerprint: u.publicKeyFingerprint,
		CreatedAt:            u.createdAt.UTC().Format(time.RFC3339),
		QuotaBytes:           u.quotaBytes,
		UsedBytes:            u.usedBytes,
		TOTPEnabled:          u.totpSecret != nil,
	}
	if u.suspendedAt != nil {
		s := u.suspendedAt.UTC().Format(time.RFC3339)
		p.SuspendedAt = &s
	}
	return p
}

// fetchUserByAddressWithKey returns the user profile and their armored public
// key for the given address. Returns pgx.ErrNoRows if not found.
func fetchUserByAddressWithKey(ctx context.Context, db *pgxpool.Pool, address string) (*userProfile, string, error) {
	var u dbUser
	var armoredPublicKey string
	err := db.QueryRow(ctx, `
		SELECT u.id, a.address, u.display_name,
		       COALESCE(k.fingerprint, ''),
		       u.created_at, u.quota_bytes, u.used_bytes,
		       u.suspended_at, u.totp_secret,
		       COALESCE(k.armored_public_key, '')
		FROM   users u
		JOIN   addresses a ON a.id = u.primary_address_id
		LEFT   JOIN user_keys k ON k.user_id = u.id AND k.is_active = TRUE
		WHERE  a.address = $1
	`, address).Scan(
		&u.id, &u.primaryAddress, &u.displayName,
		&u.publicKeyFingerprint,
		&u.createdAt, &u.quotaBytes, &u.usedBytes,
		&u.suspendedAt, &u.totpSecret,
		&armoredPublicKey,
	)
	if err != nil {
		return nil, "", err
	}
	if armoredPublicKey == "" {
		// User exists but has no active key — cannot authenticate.
		return nil, "", pgx.ErrNoRows
	}
	return u.toProfile(), armoredPublicKey, nil
}

// fetchUserByID returns the user profile for the given UUID.
func fetchUserByID(ctx context.Context, db *pgxpool.Pool, userID string) (*userProfile, error) {
	var u dbUser
	err := db.QueryRow(ctx, `
		SELECT u.id, a.address, u.display_name,
		       COALESCE(k.fingerprint, ''),
		       u.created_at, u.quota_bytes, u.used_bytes,
		       u.suspended_at, u.totp_secret
		FROM   users u
		JOIN   addresses a ON a.id = u.primary_address_id
		LEFT   JOIN user_keys k ON k.user_id = u.id AND k.is_active = TRUE
		WHERE  u.id = $1
	`, userID).Scan(
		&u.id, &u.primaryAddress, &u.displayName,
		&u.publicKeyFingerprint,
		&u.createdAt, &u.quotaBytes, &u.usedBytes,
		&u.suspendedAt, &u.totpSecret,
	)
	if err != nil {
		return nil, err
	}
	return u.toProfile(), nil
}


