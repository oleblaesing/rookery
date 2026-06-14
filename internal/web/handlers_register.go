package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
)

// a-z 0-9 . _ - only (no plus: reserved for plus-addressing), alphanumeric at
// both ends, length 1–64. Consecutive separators are left for the check below
// to reject, which keeps the regex readable.
var localPartRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$|^[a-z0-9]$`)

// RFC 5322 bans consecutive dots; we extend that to _ and - so addresses stay
// unambiguous.
var localPartConsecutiveSepRe = regexp.MustCompile(`[._-]{2,}`)

func isValidLocalPart(local string) bool {
	if !localPartRe.MatchString(local) {
		return false
	}
	if localPartConsecutiveSepRe.MatchString(local) {
		return false
	}
	return true
}

type inviteInfoResponse struct {
	Valid        bool    `json:"valid"`
	InstanceName string  `json:"instance_name"`
	Domain       string  `json:"domain"`
	ExpiresAt    *string `json:"expires_at,omitempty"`
}

func handleAPIGetInvite(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		if token == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Token is required.")
			return
		}

		var expiresAt *string
		var used bool
		err := db.QueryRow(r.Context(), `
			SELECT used_at IS NOT NULL, expires_at::text
			FROM   invites
			WHERE  token = $1
			  AND  (expires_at IS NULL OR expires_at > now())
		`, token).Scan(&used, &expiresAt)

		if errors.Is(err, pgx.ErrNoRows) || used {
			respondJSON(w, http.StatusOK, inviteInfoResponse{Valid: false})
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not validate invite.")
			return
		}

		respondJSON(w, http.StatusOK, inviteInfoResponse{
			Valid:        true,
			InstanceName: cfg.InstanceName,
			Domain:       cfg.Domain,
			ExpiresAt:    expiresAt,
		})
	}
}

type registerRequest struct {
	InviteToken      string `json:"invite_token"`
	LocalPart        string `json:"local_part"`
	ArmoredPublicKey string `json:"armored_public_key"`
}

func handleAPIRegister(db *pgxpool.Pool, ss *auth.SessionStore, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}

		req.LocalPart = strings.ToLower(strings.TrimSpace(req.LocalPart))
		if req.InviteToken == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "invite_token is required.")
			return
		}
		if !isValidLocalPart(req.LocalPart) {
			respondErrorDetail(w, http.StatusUnprocessableEntity, "INVALID_LOCAL_PART",
				"local_part must be 1–64 characters of lowercase letters, digits, . _ -; cannot start or end with a separator and cannot contain consecutive separators.",
				map[string]string{"field": "local_part"})
			return
		}
		if req.ArmoredPublicKey == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "armored_public_key is required.")
			return
		}

		fingerprint, algo, err := parsePGPPublicKey(req.ArmoredPublicKey)
		if err != nil {
			respondErrorDetail(w, http.StatusUnprocessableEntity, "INVALID_PUBLIC_KEY",
				"armored_public_key is not a valid OpenPGP public key: "+err.Error(),
				map[string]string{"field": "armored_public_key"})
			return
		}

		userProfile, rawToken, csrfToken, err := registerUser(r.Context(), db, ss, cfg, registerParams{
			inviteToken:      req.InviteToken,
			localPart:        req.LocalPart,
			armoredPublicKey: req.ArmoredPublicKey,
			fingerprint:      fingerprint,
			algorithm:        algo,
		})
		if err != nil {
			switch {
			case errors.Is(err, errInviteInvalid):
				respondError(w, http.StatusBadRequest, "INVITE_INVALID", "Invite token is invalid, expired, or already used.")
			case errors.Is(err, errLocalPartTaken):
				respondErrorDetail(w, http.StatusConflict, "LOCAL_PART_TAKEN",
					"That username is already taken on this instance.",
					map[string]string{"field": "local_part"})
			case errors.Is(err, errLocalPartReserved):
				respondErrorDetail(w, http.StatusUnprocessableEntity, "LOCAL_PART_RESERVED",
					"That username is reserved.",
					map[string]string{"field": "local_part"})
			default:
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Registration failed.")
			}
			return
		}

		auth.SetCookie(w, r, rawToken, cfg.Policy.SessionExpiryDays)
		auth.SetCSRFCookie(w, r, csrfToken)
		respondJSON(w, http.StatusCreated, userProfile)
	}
}

var (
	errInviteInvalid     = errors.New("invite invalid or used")
	errLocalPartTaken    = errors.New("local part taken")
	errLocalPartReserved = errors.New("local part reserved")
)

type registerParams struct {
	inviteToken      string
	localPart        string
	armoredPublicKey string
	fingerprint      string
	algorithm        string
}

// Runs the whole registration in one transaction — including session creation —
// so a failure anywhere rolls back invite consumption and the user/address/key
// inserts, leaving no half-state.
func registerUser(
	ctx context.Context,
	db *pgxpool.Pool,
	ss *auth.SessionStore,
	cfg *config.Config,
	p registerParams,
) (*userProfile, string, string, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, "", "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var inviteID string
	err = tx.QueryRow(ctx, `
		SELECT id FROM invites
		WHERE  token    = $1
		  AND  used_at  IS NULL
		  AND  (expires_at IS NULL OR expires_at > now())
		FOR UPDATE
	`, p.inviteToken).Scan(&inviteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", "", errInviteInvalid
	}
	if err != nil {
		return nil, "", "", err
	}

	var reserved bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM reserved_local_parts WHERE local_part = $1)`,
		p.localPart,
	).Scan(&reserved); err != nil {
		return nil, "", "", err
	}
	if reserved {
		return nil, "", "", errLocalPartReserved
	}

	var domainID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM domains WHERE domain = $1 AND is_primary = TRUE`,
		cfg.Domain,
	).Scan(&domainID)
	if errors.Is(err, pgx.ErrNoRows) {
		// The primary domain is seeded on first run; missing means misconfiguration.
		return nil, "", "", errors.New("primary domain not found in DB; run the server once to seed it")
	}
	if err != nil {
		return nil, "", "", err
	}

	address := p.localPart + "@" + cfg.Domain
	var taken bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM addresses WHERE address = $1)`,
		address,
	).Scan(&taken); err != nil {
		return nil, "", "", err
	}
	if taken {
		return nil, "", "", errLocalPartTaken
	}

	// primary_address_id is set after the address exists; the FK is DEFERRABLE.
	var userID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (quota_bytes)
		VALUES ($1)
		RETURNING id
	`, cfg.Policy.DefaultQuotaBytes).Scan(&userID); err != nil {
		return nil, "", "", err
	}

	var addrID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, userID, domainID, p.localPart, address).Scan(&addrID); err != nil {
		return nil, "", "", err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE users SET primary_address_id = $1 WHERE id = $2`,
		addrID, userID,
	); err != nil {
		return nil, "", "", err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO user_keys (user_id, fingerprint, armored_public_key, algorithm)
		VALUES ($1, $2, $3, $4)
	`, userID, p.fingerprint, p.armoredPublicKey, p.algorithm); err != nil {
		return nil, "", "", err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE invites SET used_at = now(), used_by_id = $1 WHERE id = $2
	`, userID, inviteID); err != nil {
		return nil, "", "", err
	}

	rawToken, csrfToken, err := ss.CreateInTx(ctx, tx, userID)
	if err != nil {
		return nil, "", "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, "", "", err
	}

	profile := &userProfile{
		ID:                   userID,
		PrimaryAddress:       address,
		DisplayName:          "",
		PublicKeyFingerprint: p.fingerprint,
		QuotaBytes:           cfg.Policy.DefaultQuotaBytes,
		UsedBytes:            0,
		TOTPEnabled:          false,
	}
	return profile, rawToken, csrfToken, nil
}
