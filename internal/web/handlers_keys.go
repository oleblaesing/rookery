package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/discovery"
	"rookery/internal/keydir"
)

type keyResponse struct {
	Fingerprint      string    `json:"fingerprint"`
	ArmoredPublicKey string    `json:"armored_public_key"`
	Algorithm        string    `json:"algorithm"`
	CreatedAt        time.Time `json:"created_at"`
	IsActive         bool      `json:"is_active"`
}

func handleAPIGetMyKey(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var k keyResponse
		err := db.QueryRow(r.Context(), `
			SELECT fingerprint, armored_public_key, algorithm, created_at, is_active
			FROM   user_keys
			WHERE  user_id = $1 AND is_active = TRUE
		`, userID).Scan(&k.Fingerprint, &k.ArmoredPublicKey, &k.Algorithm, &k.CreatedAt, &k.IsActive)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "KEY_NOT_FOUND", "No active key for this user.")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch key.")
			return
		}
		respondJSON(w, http.StatusOK, k)
	}
}

type putKeyRequest struct {
	ArmoredPublicKey string `json:"armored_public_key"`
}

func handleAPIPutMyKey(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var req putKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}
		if req.ArmoredPublicKey == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "armored_public_key is required.")
			return
		}

		fingerprint, algo, err := parsePGPPublicKey(req.ArmoredPublicKey)
		if err != nil {
			respondErrorDetail(w, http.StatusUnprocessableEntity, "INVALID_PUBLIC_KEY",
				"Not a valid OpenPGP public key: "+err.Error(),
				map[string]string{"field": "armored_public_key"})
			return
		}

		var existingFingerprint string
		err = db.QueryRow(r.Context(), `
			SELECT fingerprint FROM user_keys WHERE user_id = $1 AND is_active = TRUE
		`, userID).Scan(&existingFingerprint)

		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not check existing key.")
			return
		}

		if existingFingerprint != "" && existingFingerprint != fingerprint {
			respondError(w, http.StatusConflict, "KEY_ROTATION_REQUIRED",
				"Replacing your active key with a different key requires the rotation "+
					"endpoint (POST /keys/me/rotation), which proves control of both keys. "+
					"This endpoint only accepts a re-upload of your current key.")
			return
		}

		if existingFingerprint == fingerprint {
			// Same key re-uploaded: refresh the armored text, return 200.
			if _, err := db.Exec(r.Context(), `
				UPDATE user_keys SET armored_public_key = $1 WHERE user_id = $2 AND is_active = TRUE
			`, req.ArmoredPublicKey, userID); err != nil {
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not update key.")
				return
			}
			var k keyResponse
			if err := db.QueryRow(r.Context(), `
				SELECT fingerprint, armored_public_key, algorithm, created_at, is_active
				FROM   user_keys WHERE user_id = $1 AND is_active = TRUE
			`, userID).Scan(&k.Fingerprint, &k.ArmoredPublicKey, &k.Algorithm, &k.CreatedAt, &k.IsActive); err != nil {
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch updated key.")
				return
			}
			respondJSON(w, http.StatusOK, k)
			return
		}

		var k keyResponse
		if err := db.QueryRow(r.Context(), `
			INSERT INTO user_keys (user_id, fingerprint, armored_public_key, algorithm)
			VALUES ($1, $2, $3, $4)
			RETURNING fingerprint, armored_public_key, algorithm, created_at, is_active
		`, userID, fingerprint, req.ArmoredPublicKey, algo).Scan(
			&k.Fingerprint, &k.ArmoredPublicKey, &k.Algorithm, &k.CreatedAt, &k.IsActive,
		); err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not store key.")
			return
		}
		respondJSON(w, http.StatusCreated, k)
	}
}

// rotationStatement is the canonical text both keys sign during a rotation. The
// old key's signature over it doubles as the continuity attestation (it binds
// old->new); the nonce only matters to the server's freshness/replay check and
// is ignored by later continuity verifiers.
func rotationStatement(oldFP, newFP, nonce string) string {
	return fmt.Sprintf("rookery-key-rotation:v1\nold:%s\nnew:%s\nnonce:%s", oldFP, newFP, nonce)
}

// Tagged purpose='rotation' so the login/deletion endpoints can't consume it.
func handleAPIRotationChallenge(db *pgxpool.Pool) http.HandlerFunc {
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
			slog.Error("rotation challenge: fetch address", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not issue challenge.")
			return
		}

		nonce, err := auth.GenerateToken(32)
		if err != nil {
			slog.Error("rotation challenge: generate nonce", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not generate challenge.")
			return
		}

		var challengeID string
		err = db.QueryRow(r.Context(), `
			INSERT INTO auth_challenges (address, nonce, purpose)
			VALUES ($1, $2, 'rotation')
			RETURNING id
		`, address, nonce).Scan(&challengeID)
		if err != nil {
			slog.Error("rotation challenge: insert", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not store challenge.")
			return
		}

		respondJSON(w, http.StatusOK, challengeResponse{
			ChallengeID: challengeID,
			Nonce:       nonce,
		})
	}
}

type rotateKeyRequest struct {
	ChallengeID         string `json:"challenge_id"`
	NewArmoredPublicKey string `json:"new_armored_public_key"`
	OldSignature        string `json:"old_signature"`
	NewSignature        string `json:"new_signature"`
}

// Replaces the active key with a different one. The caller must prove control of
// both the current key (which signs the old->new binding, stored as a continuity
// attestation) and the new key (proving it's actually usable).
func handleAPIRotateKey(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var req rotateKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}
		if req.ChallengeID == "" || req.NewArmoredPublicKey == "" ||
			req.OldSignature == "" || req.NewSignature == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST",
				"challenge_id, new_armored_public_key, old_signature, and new_signature are required.")
			return
		}

		newFP, newAlgo, err := parsePGPPublicKey(req.NewArmoredPublicKey)
		if err != nil {
			respondErrorDetail(w, http.StatusUnprocessableEntity, "INVALID_PUBLIC_KEY",
				"Not a valid OpenPGP public key: "+err.Error(),
				map[string]string{"field": "new_armored_public_key"})
			return
		}

		var oldFP, oldArmored, address string
		err = db.QueryRow(r.Context(), `
			SELECT COALESCE(k.fingerprint, ''), COALESCE(k.armored_public_key, ''), a.address
			FROM   users u
			JOIN   addresses a ON a.id = u.primary_address_id
			LEFT   JOIN user_keys k ON k.user_id = u.id AND k.is_active = TRUE
			WHERE  u.id = $1
		`, userID).Scan(&oldFP, &oldArmored, &address)
		if err != nil {
			slog.Error("rotation: fetch active key", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not load current key.")
			return
		}
		if oldArmored == "" {
			respondError(w, http.StatusConflict, "NO_ACTIVE_KEY",
				"No active key to rotate from. Upload your first key via PUT /keys/me.")
			return
		}
		if newFP == oldFP {
			respondError(w, http.StatusBadRequest, "SAME_KEY",
				"The new key is identical to your current key. Use PUT /keys/me to re-upload.")
			return
		}

		// Claim atomically so a replay can't reuse the challenge.
		var nonce string
		err = db.QueryRow(r.Context(), `
			UPDATE auth_challenges
			SET    used_at = now()
			WHERE  id         = $1
			  AND  address    = $2
			  AND  purpose    = 'rotation'
			  AND  used_at    IS NULL
			  AND  created_at > now() - make_interval(secs => $3)
			RETURNING nonce
		`, req.ChallengeID, address, challengeTTL.Seconds()).Scan(&nonce)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusUnauthorized, "INVALID_CHALLENGE",
				"Invalid, expired, or already-used rotation challenge.")
			return
		}
		if err != nil {
			slog.Error("rotation: claim challenge", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "An unexpected error occurred.")
			return
		}

		statement := rotationStatement(oldFP, newFP, nonce)
		if err := verifyDetachedSignature(oldArmored, statement, req.OldSignature); err != nil {
			slog.Info("rotation: old-key signature failed", "err", err)
			respondError(w, http.StatusUnauthorized, "INVALID_SIGNATURE",
				"Old-key signature verification failed.")
			return
		}
		if err := verifyDetachedSignature(req.NewArmoredPublicKey, statement, req.NewSignature); err != nil {
			slog.Info("rotation: new-key signature failed", "err", err)
			respondError(w, http.StatusUnauthorized, "INVALID_SIGNATURE",
				"New-key signature verification failed.")
			return
		}

		tx, err := db.Begin(r.Context())
		if err != nil {
			slog.Error("rotation: begin tx", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "An unexpected error occurred.")
			return
		}
		defer tx.Rollback(r.Context())

		if _, err := tx.Exec(r.Context(),
			`UPDATE user_keys SET is_active = FALSE WHERE user_id = $1 AND is_active = TRUE`,
			userID,
		); err != nil {
			slog.Error("rotation: deactivate old key", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not deactivate old key.")
			return
		}

		// fingerprint is globally UNIQUE, so rotating back to a previously-held key
		// reactivates that row instead of inserting a duplicate.
		var k keyResponse
		if err := tx.QueryRow(r.Context(), `
			INSERT INTO user_keys (user_id, fingerprint, armored_public_key, algorithm, is_active)
			VALUES ($1, $2, $3, $4, TRUE)
			ON CONFLICT (fingerprint) DO UPDATE
			  SET is_active = TRUE, armored_public_key = EXCLUDED.armored_public_key
			RETURNING fingerprint, armored_public_key, algorithm, created_at, is_active
		`, userID, newFP, req.NewArmoredPublicKey, newAlgo).Scan(
			&k.Fingerprint, &k.ArmoredPublicKey, &k.Algorithm, &k.CreatedAt, &k.IsActive,
		); err != nil {
			slog.Error("rotation: activate new key", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not store new key.")
			return
		}

		if _, err := tx.Exec(r.Context(), `
			INSERT INTO key_rotations
			  (user_id, old_fingerprint, new_fingerprint,
			   old_armored_public_key, new_armored_public_key, attestation, statement)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (user_id, old_fingerprint, new_fingerprint) DO UPDATE
			  SET old_armored_public_key = EXCLUDED.old_armored_public_key,
			      new_armored_public_key = EXCLUDED.new_armored_public_key,
			      attestation            = EXCLUDED.attestation,
			      statement              = EXCLUDED.statement,
			      created_at             = now()
		`, userID, oldFP, newFP, oldArmored, req.NewArmoredPublicKey, req.OldSignature, statement,
		); err != nil {
			slog.Error("rotation: record attestation", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not record rotation.")
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("rotation: commit", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Rotation failed.")
			return
		}

		respondJSON(w, http.StatusCreated, k)
	}
}

type keyLookupResponse struct {
	Found       bool       `json:"found"`
	Key         *keyResult `json:"key,omitempty"`
	Method      string     `json:"method,omitempty"`
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
}

type keyResult struct {
	Fingerprint      string `json:"fingerprint"`
	ArmoredPublicKey string `json:"armored_public_key"`
	Algorithm        string `json:"algorithm"`
}

func handleAPIKeyLookup(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		address := r.URL.Query().Get("address")
		if address == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "address query parameter is required.")
			return
		}
		userID := auth.UserIDFromContext(r.Context())

		// Local users → this user's known-keys cache → WKD/keyserver discovery,
		// caching any externally-discovered key for next time.
		result, err := discovery.Discover(r.Context(), db, userID, address)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Key lookup failed.")
			return
		}
		if result == nil {
			respondJSON(w, http.StatusOK, keyLookupResponse{Found: false})
			return
		}

		respondJSON(w, http.StatusOK, keyLookupResponse{
			Found:       true,
			Key:         &keyResult{Fingerprint: result.Fingerprint, ArmoredPublicKey: result.ArmoredPublicKey},
			Method:      result.Source,
			FirstSeenAt: result.FirstSeenAt,
		})
	}
}

func handleWKDKey(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := r.PathValue("hash")
		if hash == "" {
			http.NotFound(w, r)
			return
		}

		// The path segment carries the (possibly custom) domain, reached via the
		// openpgpkey.<domain> CNAME.
		domain := r.PathValue("domain")
		var wkdActive bool
		if err := db.QueryRow(r.Context(),
			`SELECT wkd_active FROM domains WHERE domain = $1 AND verified_at IS NOT NULL`,
			domain,
		).Scan(&wkdActive); err != nil || !wkdActive {
			http.NotFound(w, r)
			return
		}

		// Linear scan comparing WKD hashes; fine at this scale, no precomputed index.
		rows, err := db.Query(r.Context(), `
			SELECT a.local_part, k.armored_public_key
			FROM   addresses a
			JOIN   domains d ON d.id = a.domain_id
			JOIN   users u ON u.id = a.user_id
			JOIN   user_keys k ON k.user_id = u.id AND k.is_active = TRUE
			WHERE  d.domain = $1 AND a.is_alias = FALSE
		`, domain)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var localPart, armoredKey string
			if err := rows.Scan(&localPart, &armoredKey); err != nil {
				continue
			}
			if keydir.WKDHash(localPart) == hash {
				binaryKey, err := keydir.BinaryPublicKey(armoredKey)
				if err != nil {
					http.Error(w, "key encoding error", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(binaryKey)
				return
			}
		}
		http.NotFound(w, r)
	}
}

// The WKD policy file is empty per the spec.
func handleWKDPolicy(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

func parsePGPPublicKey(armored string) (fingerprint, algorithm string, err error) {
	return keydir.ParsePublicKey(armored)
}
