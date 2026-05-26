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

// -------------------------------------------------------------------------
// POST /api/v1/users/me/deletion/challenge
//
// Issues a one-shot deletion challenge nonce for the authenticated user.
// The client must sign the nonce with their PGP private key and POST it to
// /api/v1/users/me/deletion within challengeTTL (5 min).
//
// The challenge is tagged purpose='deletion' so it cannot be consumed by the
// login endpoint (which only claims purpose='login' rows, default).
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// POST /api/v1/users/me/deletion
//
// Verifies a deletion challenge signature and deletes the user's account.
//
// Request body:
//
//	{
//	  "challenge_id":     "<uuid>",
//	  "signed_challenge": "<armored detached PGP signature>",
//	  "confirm_address":  "alice@example.com"
//	}
//
// The server:
//  1. Fetches the user's primary address and active public key from the DB.
//  2. Verifies confirm_address matches the primary address (server-side check).
//  3. Claims the deletion challenge (purpose='deletion', same 5-min TTL).
//  4. Verifies the detached PGP signature of the nonce.
//  5. Calls lifecycle.DeleteUser.
//  6. Clears the session cookie and returns {"status":"ok"}.
//
// A stale session cookie alone is not sufficient — the caller must prove
// control of the PGP private key at the moment of deletion.
// -------------------------------------------------------------------------

type deletionRequest struct {
	ChallengeID     string `json:"challenge_id"`
	SignedChallenge string `json:"signed_challenge"`
	ConfirmAddress  string `json:"confirm_address"`
}

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

		// Fetch the user's primary address and active public key.
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

		// Typed-address confirmation check (server-side; client also validates).
		if req.ConfirmAddress != strings.ToLower(primaryAddress) {
			respondError(w, http.StatusBadRequest, "ADDRESS_MISMATCH",
				"Typed address does not match your primary address.")
			return
		}

		// Claim the deletion challenge atomically.
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

		// Verify the detached PGP signature of the nonce.
		if err := verifyDetachedSignature(armoredPublicKey, nonce, req.SignedChallenge); err != nil {
			slog.Info("deletion: signature verification failed", "err", err)
			respondError(w, http.StatusUnauthorized, "INVALID_SIGNATURE",
				"Signature verification failed.")
			return
		}

		// Delete the account. The cascade removes all session rows, so existing
		// sessions for this user become invalid immediately after commit.
		if err := lifecycle.DeleteUser(r.Context(), db, st, userID); err != nil {
			slog.Error("deletion: DeleteUser", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Account deletion failed.")
			return
		}

		// Best-effort cookie clear — the session row is already gone.
		auth.ClearCookie(w, r)

		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}
