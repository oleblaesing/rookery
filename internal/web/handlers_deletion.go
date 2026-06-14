package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/lifecycle"
	"rookery/internal/store"
)

// Tagged purpose='deletion' so the login endpoint (which only claims 'login'
// rows) can't consume it.
func handleAPIDeletionChallenge(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var address string
		err := db.QueryRow(r.Context(), `
			SELECT a.address
			FROM   users u
			JOIN   addresses a ON a.id = u.primary_address_id
			WHERE  u.id = $1
		`, userID).Scan(&address)
		if err != nil {
			slog.Error("deletion challenge: fetch address", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not issue challenge.")
			return
		}

		nonce, err := auth.GenerateToken(32)
		if err != nil {
			slog.Error("deletion challenge: generate nonce", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not generate challenge.")
			return
		}

		var challengeID string
		err = db.QueryRow(r.Context(), `
			INSERT INTO auth_challenges (address, nonce, purpose)
			VALUES ($1, $2, 'deletion')
			RETURNING id
		`, address, nonce).Scan(&challengeID)
		if err != nil {
			slog.Error("deletion challenge: insert", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not store challenge.")
			return
		}

		respondJSON(w, http.StatusOK, challengeResponse{
			ChallengeID: challengeID,
			Nonce:       nonce,
		})
	}
}

type deletionRequest struct {
	ChallengeID     string `json:"challenge_id"`
	SignedChallenge string `json:"signed_challenge"`
	ConfirmAddress  string `json:"confirm_address"`
}

// Deletes the account only after the caller re-proves control of the PGP key
// (signed challenge + typed-address match); a session cookie alone is not enough.
func handleAPIDeletion(db *pgxpool.Pool, ss *auth.SessionStore, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var req deletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}
		req.ConfirmAddress = strings.ToLower(strings.TrimSpace(req.ConfirmAddress))
		if req.ChallengeID == "" || req.SignedChallenge == "" || req.ConfirmAddress == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST",
				"challenge_id, signed_challenge, and confirm_address are required.")
			return
		}

		var primaryAddress, armoredPublicKey string
		err := db.QueryRow(r.Context(), `
			SELECT a.address, COALESCE(k.armored_public_key, '')
			FROM   users u
			JOIN   addresses a ON a.id = u.primary_address_id
			LEFT   JOIN user_keys k ON k.user_id = u.id AND k.is_active = TRUE
			WHERE  u.id = $1
		`, userID).Scan(&primaryAddress, &armoredPublicKey)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "User not found.")
			return
		}
		if err != nil {
			slog.Error("deletion: fetch user", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "An unexpected error occurred.")
			return
		}
		if armoredPublicKey == "" {
			respondError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "No active key found.")
			return
		}

		if req.ConfirmAddress != strings.ToLower(primaryAddress) {
			respondError(w, http.StatusBadRequest, "ADDRESS_MISMATCH",
				"Typed address does not match your primary address.")
			return
		}

		// Claim atomically so a replay can't reuse the challenge.
		var nonce string
		err = db.QueryRow(r.Context(), `
			UPDATE auth_challenges
			SET    used_at = now()
			WHERE  id         = $1
			  AND  address    = $2
			  AND  purpose    = 'deletion'
			  AND  used_at    IS NULL
			  AND  created_at > now() - make_interval(secs => $3)
			RETURNING nonce
		`, req.ChallengeID, primaryAddress, challengeTTL.Seconds()).Scan(&nonce)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusUnauthorized, "INVALID_CHALLENGE",
				"Invalid, expired, or already-used deletion challenge.")
			return
		}
		if err != nil {
			slog.Error("deletion: claim challenge", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "An unexpected error occurred.")
			return
		}

		if err := verifyDetachedSignature(armoredPublicKey, nonce, req.SignedChallenge); err != nil {
			slog.Info("deletion: signature verification failed", "err", err)
			respondError(w, http.StatusUnauthorized, "INVALID_SIGNATURE",
				"Signature verification failed.")
			return
		}

		// The cascade drops all session rows, invalidating other sessions at once.
		if err := lifecycle.DeleteUser(r.Context(), db, st, userID); err != nil {
			slog.Error("deletion: DeleteUser", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Account deletion failed.")
			return
		}

		auth.ClearCookie(w, r)

		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
