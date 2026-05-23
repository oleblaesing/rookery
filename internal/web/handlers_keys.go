package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/keydir"
)

// -------------------------------------------------------------------------
// GET /api/v1/keys/me
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// PUT /api/v1/keys/me
//
// Phase 1: initial key upload only. Replacing a key with a *different* key
// is rejected with 409 — key rotation (with the attestation protocol from
// ADR-0028) lands in Phase 6.
// -------------------------------------------------------------------------

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

		// Check if a key already exists for this user.
		var existingFingerprint string
		err = db.QueryRow(r.Context(), `
			SELECT fingerprint FROM user_keys WHERE user_id = $1 AND is_active = TRUE
		`, userID).Scan(&existingFingerprint)

		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not check existing key.")
			return
		}

		if existingFingerprint != "" && existingFingerprint != fingerprint {
			// Different key — reject until Phase 6 rotation protocol is implemented.
			respondError(w, http.StatusConflict, "KEY_ROTATION_NOT_IMPLEMENTED",
				"Replacing a key with a different key requires the rotation protocol (Phase 6). "+
					"If you are uploading the same key again, the fingerprints must match.")
			return
		}

		if existingFingerprint == fingerprint {
			// Idempotent re-upload of the same key: update the armored text and return 200.
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

		// No existing key — insert.
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

// -------------------------------------------------------------------------
// GET /api/v1/keys/lookup?address=...
// -------------------------------------------------------------------------

type keyLookupResponse struct {
	Found       bool        `json:"found"`
	Key         *keyResult  `json:"key,omitempty"`
	Method      string      `json:"method,omitempty"` // "local", "known_keys"
	FirstSeenAt *time.Time  `json:"first_seen_at,omitempty"`
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

		// 1. Check local user directory.
		var fp, armoredKey, algo string
		err := db.QueryRow(r.Context(), `
			SELECT k.fingerprint, k.armored_public_key, k.algorithm
			FROM   user_keys k
			JOIN   users u ON u.id = k.user_id
			JOIN   addresses a ON a.id = u.primary_address_id
			WHERE  a.address = $1 AND k.is_active = TRUE
		`, address).Scan(&fp, &armoredKey, &algo)
		if err == nil {
			respondJSON(w, http.StatusOK, keyLookupResponse{
				Found:  true,
				Key:    &keyResult{Fingerprint: fp, ArmoredPublicKey: armoredKey, Algorithm: algo},
				Method: "local",
			})
			return
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Key lookup failed.")
			return
		}

		// 2. Check this user's known-keys cache.
		var firstSeen time.Time
		err = db.QueryRow(r.Context(), `
			SELECT fingerprint, armored_public_key, first_seen_at
			FROM   known_keys
			WHERE  user_id = $1 AND address = $2
			ORDER  BY last_seen_at DESC
			LIMIT  1
		`, userID, address).Scan(&fp, &armoredKey, &firstSeen)
		if err == nil {
			respondJSON(w, http.StatusOK, keyLookupResponse{
				Found:       true,
				Key:         &keyResult{Fingerprint: fp, ArmoredPublicKey: armoredKey},
				Method:      "known_keys",
				FirstSeenAt: &firstSeen,
			})
			return
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Key lookup failed.")
			return
		}

		// 3. WKD lookup (Phase 2+ for the discovery pipeline; stub here).
		// TODO(phase2): implement WKD + keyserver discovery via internal/discovery.
		respondJSON(w, http.StatusOK, keyLookupResponse{Found: false})
	}
}

// -------------------------------------------------------------------------
// WKD endpoint — GET /.well-known/openpgpkey/{domain}/hu/{hash}
// -------------------------------------------------------------------------
// This handler is mounted on the openpgpkey.<domain> virtual host.
// It serves binary (non-armored) OpenPGP public key data.

func handleWKDKey(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := r.PathValue("hash")
		if hash == "" {
			http.NotFound(w, r)
			return
		}

		// Accept any domain that is verified and has WKD active. Custom domains
		// use openpgpkey.<custom-domain> CNAME → openpgpkey.<primary> so the
		// path segment carries the custom domain name (ADR-0036).
		domain := r.PathValue("domain")
		var wkdActive bool
		if err := db.QueryRow(r.Context(),
			`SELECT wkd_active FROM domains WHERE domain = $1 AND verified_at IS NOT NULL`,
			domain,
		).Scan(&wkdActive); err != nil || !wkdActive {
			http.NotFound(w, r)
			return
		}

		// Find the user whose local-part hashes to this WKD hash.
		// We iterate users on this domain and compare hashes. For a small
		// instance this is fine; a larger instance would maintain a precomputed
		// index (Phase 7 optimisation if ever needed).
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

// handleWKDPolicy serves the WKD policy file (an empty file per spec).
func handleWKDPolicy(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	// Empty body is compliant with the WKD spec.
}

// -------------------------------------------------------------------------
// Shared helper: parse + validate a PGP public key (used in register + put)
// -------------------------------------------------------------------------

func parsePGPPublicKey(armored string) (fingerprint, algorithm string, err error) {
	return keydir.ParsePublicKey(armored)
}
