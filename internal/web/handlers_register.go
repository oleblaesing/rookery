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

// localPartRe validates that a local-part contains only safe characters.
// Allowed: a-z 0-9 . _ - (no plus — that's reserved for plus-addressing
// tags which are stripped before lookup). Must start and end with an
// alphanumeric. Length 1–64.
//
// The regex permits consecutive separators (e.g. "a..b"); that is
// disallowed by isValidLocalPart's additional check, which keeps the regex
// readable.
var localPartRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$|^[a-z0-9]$`)

// localPartConsecutiveSepRe matches any run of two or more separator
// characters (., _, -). RFC 5322 forbids consecutive dots in unquoted
// local-parts; we extend the same rule to _ and - to keep displayable
// addresses unambiguous.
var localPartConsecutiveSepRe = regexp.MustCompile(`[._-]{2,}`)

// isValidLocalPart applies both the regex and the no-consecutive-separators
// rule.
func isValidLocalPart(local string) bool {
	if !localPartRe.MatchString(local) {
		return false
	}
	if localPartConsecutiveSepRe.MatchString(local) {
		return false
	}
	return true
}

// -------------------------------------------------------------------------
// GET /api/v1/invites/{token}
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// POST /api/v1/users/register
// -------------------------------------------------------------------------

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

		// ---- Validate inputs ----
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

		// ---- Parse and validate the PGP public key ----
		fingerprint, algo, err := parsePGPPublicKey(req.ArmoredPublicKey)
		if err != nil {
			respondErrorDetail(w, http.StatusUnprocessableEntity, "INVALID_PUBLIC_KEY",
				"armored_public_key is not a valid OpenPGP public key: "+err.Error(),
				map[string]string{"field": "armored_public_key"})
			return
		}

		// ---- Transactionally register the user ----
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

// ---- Registration errors ----

var (
	errInviteInvalid    = errors.New("invite invalid or used")
	errLocalPartTaken   = errors.New("local part taken")
	errLocalPartReserved = errors.New("local part reserved")
)

type registerParams struct {
	inviteToken      string
	localPart        string
	armoredPublicKey string
	fingerprint      string
	algorithm        string
}

// registerUser runs the full registration inside a single transaction:
//  1. Locks and validates the invite token (not used, not expired).
//  2. Checks the local-part is not reserved and not taken.
//  3. Inserts: user row, address row, user_key row.
//  4. Links primary_address_id back to the user row.
//  5. Marks the invite as used.
//  6. Inserts the session row.
//
// No passphrase or passphrase hash is stored — authentication is purely
// challenge/response via the user's PGP key (§11.2 / PLAN.md §5.3).
//
// Returns the new user's profile, a raw session token, and a CSRF token on
// success. Session creation lives inside the transaction so a failure there
// rolls back the user/invite/key inserts — there is no half-state where the
// invite is consumed but the caller never receives a session cookie.
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

	// 1. Validate and lock the invite.
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

	// 2a. Check reserved local-parts.
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

	// 2b. Check uniqueness on the primary domain.
	var domainID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM domains WHERE domain = $1 AND is_primary = TRUE`,
		cfg.Domain,
	).Scan(&domainID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Primary domain row should have been seeded on first run; this is a
		// configuration error, but don't panic — return a useful error.
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

	// 3. Insert user (without primary_address_id yet — FK is DEFERRABLE).
	// No passphrase or hash is stored: auth is PGP challenge/response only.
	var userID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (quota_bytes)
		VALUES ($1)
		RETURNING id
	`, cfg.Policy.DefaultQuotaBytes).Scan(&userID); err != nil {
		return nil, "", "", err
	}

	// 3b. Insert the primary address.
	var addrID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, userID, domainID, p.localPart, address).Scan(&addrID); err != nil {
		return nil, "", "", err
	}

	// 3c. Set primary_address_id on the user.
	if _, err := tx.Exec(ctx,
		`UPDATE users SET primary_address_id = $1 WHERE id = $2`,
		addrID, userID,
	); err != nil {
		return nil, "", "", err
	}

	// 3d. Insert the public key.
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_keys (user_id, fingerprint, armored_public_key, algorithm)
		VALUES ($1, $2, $3, $4)
	`, userID, p.fingerprint, p.armoredPublicKey, p.algorithm); err != nil {
		return nil, "", "", err
	}

	// 4. Mark invite as used.
	if _, err := tx.Exec(ctx, `
		UPDATE invites SET used_at = now(), used_by_id = $1 WHERE id = $2
	`, userID, inviteID); err != nil {
		return nil, "", "", err
	}

	// 5. Create the session inside the same transaction — a failure here
	//    rolls back the user, address, key, and invite consumption so the
	//    caller never sees a half-state.
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
