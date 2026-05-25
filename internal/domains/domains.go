// Package domains manages custom-domain registration, DNS verification,
// reserved-address auto-creation, and MTA-STS lifecycle for a rookery instance.
//
// Design constraints (Phase 4, ADR-0034 through ADR-0038):
//   - Domain verification requires challenge TXT + correct MX (ADR-0034).
//   - MTA-STS transitions from testing to enforce 48h after verification (ADR-0037).
//   - Reserved local-parts (postmaster/abuse/hostmaster/webmaster) are auto-created
//     as alias rows on every newly verified domain (ADR-0018).
//   - DNS drift detection runs in a background worker once per hour (ADR-0038).
package domains

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a domain row does not exist.
var ErrNotFound = errors.New("domains: not found")

// ErrConflict is returned when a domain is already registered.
var ErrConflict = errors.New("domains: already registered")

// ErrForbidden is returned when the caller does not own the domain.
var ErrForbidden = errors.New("domains: forbidden")

// ErrAddressesExist is returned when attempting to delete a domain that still
// has non-reserved addresses associated with it.
var ErrAddressesExist = errors.New("domains: non-reserved addresses still exist on this domain")

// reservedLocalParts are auto-created as aliases on every verified domain.
var reservedLocalParts = []string{"postmaster", "abuse", "hostmaster", "webmaster"}

// tokenTTL is how long a verification token remains valid.
const tokenTTL = 7 * 24 * time.Hour

// Domain holds the data model for a managed domain.
type Domain struct {
	ID              string
	Domain          string
	IsPrimary       bool
	OwnerUserID     *string
	VerifiedAt      *time.Time
	WKDActive       bool
	CreatedAt       time.Time

	// Verification
	VerificationToken      *string
	VerificationExpiresAt  *time.Time
	VerificationCheckedAt  *time.Time

	// MTA-STS
	MTASTSMode          *string // nil = auto (testing 48h → enforce)
	MTASTSID            *string
	MTASTSModeChangedAt *time.Time

	// Catch-all
	CatchAllEnabled   bool
	CatchAllAddressID *string

	// DNS drift
	DNSLastCheckedAt *time.Time
	DNSStatus        map[string]string // record key → "ok" | "drifted" | "missing" | "unknown"
}

// RecordStatus holds a per-DNS-record verification/drift result.
type RecordStatus struct {
	Name     string // DNS record name, e.g. "rookery-ed25519._domainkey.example.com"
	Type     string // DNS RR type: "A", "AAAA", "TXT", "MX", "CNAME"
	Key      string // internal identifier, e.g. "MX", "DKIM_ED25519_CNAME"
	Expected string
	Actual   string // empty = not found
	Status   string // "" (unchecked) | "ok" | "drifted" | "unknown" | "missing"
}

// VerificationResult is returned by CheckVerification.
type VerificationResult struct {
	Verified bool
	Records  []RecordStatus
}

// Manager handles domain lifecycle for an instance.
type Manager struct {
	db            *pgxpool.Pool
	primaryDomain string
	resolver      *net.Resolver
}

// NewManager creates a Manager. resolverAddr is the DNS resolver to use for
// checks (e.g. "9.9.9.9:53"); an empty string uses the system default.
func NewManager(db *pgxpool.Pool, primaryDomain, resolverAddr string) *Manager {
	m := &Manager{db: db, primaryDomain: primaryDomain}
	if resolverAddr != "" {
		m.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", resolverAddr)
			},
		}
	}
	return m
}

// PrimaryDomain returns the primary domain name for this instance.
func (m *Manager) PrimaryDomain() string { return m.primaryDomain }

// Register creates a pending domain row for the given user. Returns ErrConflict
// if the domain is already registered (by anyone).
func (m *Manager) Register(ctx context.Context, userID, domainName string) (*Domain, error) {
	domainName = strings.ToLower(strings.TrimSpace(domainName))
	if domainName == "" {
		return nil, fmt.Errorf("domains: empty domain name")
	}

	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("domains: generate token: %w", err)
	}
	expires := time.Now().UTC().Add(tokenTTL)

	// Generate an MTA-STS ID at registration time so the DNS record set we
	// show to the user immediately has the right id= value.
	mtsID, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("domains: generate mta-sts id: %w", err)
	}
	// MTA-STS IDs are conventionally alphanumeric; use hex-like base64url (16 chars).
	mtsID = mtsID[:16]

	var id string
	err = m.db.QueryRow(ctx, `
		INSERT INTO domains
			(domain, is_primary, owner_user_id,
			 verification_token, verification_expires_at,
			 mta_sts_id, mta_sts_mode_changed_at)
		VALUES ($1, FALSE, $2, $3, $4, $5, now())
		RETURNING id
	`, domainName, userID, token, expires, mtsID).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("domains: insert: %w", err)
	}

	return m.Get(ctx, id)
}

// Get returns a domain by ID.
func (m *Manager) Get(ctx context.Context, id string) (*Domain, error) {
	return m.scanOne(ctx, `
		SELECT id, domain, is_primary, owner_user_id, verified_at, wkd_active, created_at,
		       verification_token, verification_expires_at, verification_checked_at,
		       mta_sts_mode, mta_sts_id, mta_sts_mode_changed_at,
		       catch_all_enabled, catch_all_address_id,
		       dns_last_checked_at, dns_status
		FROM   domains WHERE id = $1
	`, id)
}

// GetByName returns a domain by its domain name.
func (m *Manager) GetByName(ctx context.Context, name string) (*Domain, error) {
	return m.scanOne(ctx, `
		SELECT id, domain, is_primary, owner_user_id, verified_at, wkd_active, created_at,
		       verification_token, verification_expires_at, verification_checked_at,
		       mta_sts_mode, mta_sts_id, mta_sts_mode_changed_at,
		       catch_all_enabled, catch_all_address_id,
		       dns_last_checked_at, dns_status
		FROM   domains WHERE domain = $1
	`, name)
}

// ListForUser returns all non-primary domains owned by the user.
func (m *Manager) ListForUser(ctx context.Context, userID string) ([]Domain, error) {
	rows, err := m.db.Query(ctx, `
		SELECT id, domain, is_primary, owner_user_id, verified_at, wkd_active, created_at,
		       verification_token, verification_expires_at, verification_checked_at,
		       mta_sts_mode, mta_sts_id, mta_sts_mode_changed_at,
		       catch_all_enabled, catch_all_address_id,
		       dns_last_checked_at, dns_status
		FROM   domains
		WHERE  owner_user_id = $1 AND is_primary = FALSE
		ORDER  BY created_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("domains: list: %w", err)
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// Delete removes a custom domain. Returns ErrForbidden if the caller does not
// own it, ErrAddressesExist if non-reserved addresses still use it.
func (m *Manager) Delete(ctx context.Context, id, userID string) error {
	d, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if d.IsPrimary {
		return ErrForbidden
	}
	if d.OwnerUserID == nil || *d.OwnerUserID != userID {
		return ErrForbidden
	}

	// Check for non-reserved addresses.
	var count int
	if err := m.db.QueryRow(ctx, `
		SELECT count(*) FROM addresses
		WHERE domain_id = $1 AND is_reserved = FALSE AND is_alias = FALSE
	`, id).Scan(&count); err != nil {
		return fmt.Errorf("domains: check addresses: %w", err)
	}
	if count > 0 {
		return ErrAddressesExist
	}

	_, err = m.db.Exec(ctx, `DELETE FROM domains WHERE id = $1`, id)
	return err
}

// CheckVerification performs a DNS check for the domain and updates the
// domains row. Returns the per-record result. If all required records are
// present the domain is marked verified and reserved addresses are created.
func (m *Manager) CheckVerification(ctx context.Context, id string) (*VerificationResult, error) {
	d, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if d.VerificationToken == nil {
		return nil, fmt.Errorf("domains: no verification token for %s", id)
	}

	// Refresh token if expired.
	if d.VerificationExpiresAt != nil && time.Now().After(*d.VerificationExpiresAt) {
		newToken, err := generateToken()
		if err != nil {
			return nil, fmt.Errorf("domains: refresh token: %w", err)
		}
		expires := time.Now().UTC().Add(tokenTTL)
		if _, err := m.db.Exec(ctx, `
			UPDATE domains
			SET verification_token = $1, verification_expires_at = $2
			WHERE id = $3
		`, newToken, expires, id); err != nil {
			return nil, err
		}
		d.VerificationToken = &newToken
	}

	result := &VerificationResult{}
	result.Records = m.checkDNSRecords(ctx, d, *d.VerificationToken)

	// All required records must be present before the domain is considered verified.
	allOK := len(result.Records) > 0
	for _, r := range result.Records {
		if r.Status != "ok" {
			allOK = false
			break
		}
	}
	result.Verified = allOK

	now := time.Now().UTC()
	if result.Verified && d.VerifiedAt == nil {
		// Mark verified, activate WKD.
		if _, err := m.db.Exec(ctx, `
			UPDATE domains
			SET verified_at = $1, wkd_active = TRUE, verification_checked_at = $1
			WHERE id = $2
		`, now, id); err != nil {
			return nil, fmt.Errorf("domains: mark verified: %w", err)
		}
		// Auto-create reserved addresses.
		if d.OwnerUserID != nil {
			if err := m.EnsureReservedAddresses(ctx, id, *d.OwnerUserID); err != nil {
				slog.Error("domains: create reserved addresses failed", "domain_id", id, "err", err)
			}
		}
		slog.Info("domains: domain verified", "domain", d.Domain,
			"event_key", "domain_verified")
	} else {
		if _, err := m.db.Exec(ctx,
			`UPDATE domains SET verification_checked_at = $1 WHERE id = $2`,
			now, id,
		); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// EnsureReservedAddresses creates postmaster/abuse/hostmaster/webmaster alias
// rows for the domain, pointing to the owner's primary address, and ensures
// the owner's own local-part has a direct address on the domain. Idempotent.
func (m *Manager) EnsureReservedAddresses(ctx context.Context, domainID, ownerUserID string) error {
	// Fetch owner's primary_address_id and local_part.
	var primaryAddrID, primaryLocalPart string
	err := m.db.QueryRow(ctx, `
		SELECT a.id, a.local_part
		FROM   users u
		JOIN   addresses a ON a.id = u.primary_address_id
		WHERE  u.id = $1
	`, ownerUserID).Scan(&primaryAddrID, &primaryLocalPart)
	if err != nil {
		return fmt.Errorf("domains: reserved: fetch owner primary address: %w", err)
	}

	// Fetch the domain name.
	var domainName string
	if err := m.db.QueryRow(ctx,
		`SELECT domain FROM domains WHERE id = $1`, domainID,
	).Scan(&domainName); err != nil {
		return err
	}

	// Ensure the owner's own address exists on this domain as a direct address.
	ownerAddr := primaryLocalPart + "@" + domainName
	if _, err := m.db.Exec(ctx, `
		INSERT INTO addresses
			(user_id, domain_id, local_part, address,
			 is_alias, is_reserved, delivery_method)
		VALUES ($1, $2, $3, $4, FALSE, FALSE, 'direct')
		ON CONFLICT (local_part, domain_id) DO NOTHING
	`, ownerUserID, domainID, primaryLocalPart, ownerAddr); err != nil {
		return fmt.Errorf("domains: insert owner address %s: %w", ownerAddr, err)
	}

	for _, lp := range reservedLocalParts {
		addr := lp + "@" + domainName
		_, err := m.db.Exec(ctx, `
			INSERT INTO addresses
				(user_id, domain_id, local_part, address,
				 is_alias, alias_target_id, is_reserved, delivery_method)
			VALUES ($1, $2, $3, $4, TRUE, $5, TRUE, 'alias')
			ON CONFLICT (local_part, domain_id) DO NOTHING
		`, ownerUserID, domainID, lp, addr, primaryAddrID)
		if err != nil {
			return fmt.Errorf("domains: insert reserved address %s: %w", addr, err)
		}
	}
	return nil
}

// BackfillOwnerAddresses ensures every verified custom domain has a direct
// address row for its owner's local-part. Safe to call at startup; idempotent.
func (m *Manager) BackfillOwnerAddresses(ctx context.Context) error {
	rows, err := m.db.Query(ctx, `
		SELECT id, owner_user_id FROM domains
		WHERE  is_primary = FALSE AND verified_at IS NOT NULL AND owner_user_id IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("domains: backfill query: %w", err)
	}
	defer rows.Close()
	type pair struct{ domainID, ownerID string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.domainID, &p.ownerID); err != nil {
			return err
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range pairs {
		if err := m.EnsureReservedAddresses(ctx, p.domainID, p.ownerID); err != nil {
			slog.Error("domains: backfill owner address failed",
				"domain_id", p.domainID, "err", err)
		}
	}
	return nil
}

// SetCatchAll enables or disables catch-all on a domain. When enabling,
// targetAddressID must be an address owned by the user on this domain.
func (m *Manager) SetCatchAll(ctx context.Context, domainID, userID string, enabled bool, targetAddressID string) error {
	d, err := m.Get(ctx, domainID)
	if err != nil {
		return err
	}
	if d.OwnerUserID == nil || *d.OwnerUserID != userID {
		return ErrForbidden
	}
	if !enabled {
		_, err = m.db.Exec(ctx,
			`UPDATE domains SET catch_all_enabled = FALSE, catch_all_address_id = NULL WHERE id = $1`,
			domainID)
		return err
	}
	// Validate targetAddressID belongs to the user and is on this domain.
	var count int
	if err := m.db.QueryRow(ctx, `
		SELECT count(*) FROM addresses
		WHERE id = $1 AND user_id = $2 AND domain_id = $3 AND is_alias = FALSE
	`, targetAddressID, userID, domainID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("domains: catch-all target address not found on this domain")
	}
	_, err = m.db.Exec(ctx, `
		UPDATE domains SET catch_all_enabled = TRUE, catch_all_address_id = $1 WHERE id = $2
	`, targetAddressID, domainID)
	return err
}

// SetMTASTSMode sets a manual override for the MTA-STS mode. Pass an empty
// string to clear the override and return to auto-schedule.
func (m *Manager) SetMTASTSMode(ctx context.Context, domainID, userID, mode string) error {
	d, err := m.Get(ctx, domainID)
	if err != nil {
		return err
	}
	if d.OwnerUserID == nil || *d.OwnerUserID != userID {
		return ErrForbidden
	}
	if mode == "" {
		_, err = m.db.Exec(ctx, `UPDATE domains SET mta_sts_mode = NULL WHERE id = $1`, domainID)
		return err
	}
	if mode != "testing" && mode != "enforce" && mode != "disabled" {
		return fmt.Errorf("domains: invalid mta_sts_mode %q", mode)
	}
	_, err = m.db.Exec(ctx,
		`UPDATE domains SET mta_sts_mode = $1, mta_sts_mode_changed_at = now() WHERE id = $2`,
		mode, domainID)
	return err
}

// EffectiveMTASTSMode returns the MTA-STS mode that should be served to
// external senders. Applies the auto-schedule: if mta_sts_mode is NULL and
// the domain has been in "testing" for ≥48h, returns "enforce"; otherwise
// returns "testing".
func (m *Manager) EffectiveMTASTSMode(d *Domain) string {
	if d.MTASTSMode != nil {
		return *d.MTASTSMode
	}
	if d.MTASTSModeChangedAt == nil {
		return "testing"
	}
	if time.Since(*d.MTASTSModeChangedAt) >= 48*time.Hour {
		return "enforce"
	}
	return "testing"
}

// UpgradeMTASTSModes scans for domains that have been in auto-testing mode for
// ≥48h and flips them to enforce. Called by the background worker.
func (m *Manager) UpgradeMTASTSModes(ctx context.Context) error {
	rows, err := m.db.Query(ctx, `
		SELECT id, mta_sts_id FROM domains
		WHERE  mta_sts_mode IS NULL
		  AND  mta_sts_mode_changed_at < now() - interval '48 hours'
		  AND  verified_at IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("domains: mta-sts upgrade query: %w", err)
	}
	defer rows.Close()

	type row struct{ id, oldID string }
	var toUpgrade []row
	for rows.Next() {
		var r row
		var oldID *string
		if err := rows.Scan(&r.id, &oldID); err != nil {
			return err
		}
		if oldID != nil {
			r.oldID = *oldID
		}
		toUpgrade = append(toUpgrade, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, r := range toUpgrade {
		newID, err := generateToken()
		if err != nil {
			continue
		}
		newID = newID[:16]
		if _, err := m.db.Exec(ctx, `
			UPDATE domains
			SET mta_sts_mode = 'enforce',
			    mta_sts_id = $1,
			    mta_sts_mode_changed_at = now()
			WHERE id = $2
		`, newID, r.id); err != nil {
			slog.Error("domains: mta-sts upgrade failed", "domain_id", r.id, "err", err)
			continue
		}
		slog.Info("domains: MTA-STS upgraded to enforce",
			"event_key", "mta_sts_mode_enforced",
			"domain_id", r.id,
			"new_mta_sts_id", newID)
	}
	return nil
}

// checkDNSRecords performs DNS lookups for all Phase 4 records and returns
// per-record status.
func (m *Manager) checkDNSRecords(ctx context.Context, d *Domain, token string) []RecordStatus {
	primary := m.primaryDomain
	domain := d.Domain
	lookupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var results []RecordStatus

	// Challenge TXT
	results = append(results, m.checkTXT(lookupCtx, "_rookery-challenge."+domain, token, "CHALLENGE"))

	// MX — match by host (any priority is fine), surface the full record
	// value (priority + host) as the suggested publishable form.
	results = append(results, m.checkMX(lookupCtx, domain, primary, "10 "+primary))

	// SPF TXT — match by prefix (operators may append qualifiers), but
	// surface the full recommended value as the suggested record to publish.
	results = append(results, m.checkTXTPrefix(lookupCtx, domain,
		"v=spf1 include:_spf."+primary,
		"v=spf1 include:_spf."+primary+" ~all", "SPF"))

	// DKIM CNAMEs
	results = append(results, m.checkCNAME(lookupCtx,
		"rookery-ed25519._domainkey."+domain,
		"rookery-ed25519._domainkey."+primary,
		"DKIM_ED25519_CNAME"))
	results = append(results, m.checkCNAME(lookupCtx,
		"rookery-rsa._domainkey."+domain,
		"rookery-rsa._domainkey."+primary,
		"DKIM_RSA_CNAME"))

	// WKD CNAME
	results = append(results, m.checkCNAME(lookupCtx,
		"openpgpkey."+domain,
		"openpgpkey."+primary,
		"WKD_CNAME"))

	// MTA-STS CNAME
	results = append(results, m.checkCNAME(lookupCtx,
		"mta-sts."+domain,
		"mta-sts."+primary,
		"MTA_STS_CNAME"))

	// MTA-STS policy-version TXT. The id value is generated at registration
	// time (Register) and stored on the domains row, so it's always available.
	// Exact match: the id rotates when the policy changes, so a stale id is drift.
	if d.MTASTSID != nil && *d.MTASTSID != "" {
		results = append(results, m.checkTXT(lookupCtx, "_mta-sts."+domain,
			"v=STSv1; id="+*d.MTASTSID, "MTA_STS_TXT"))
	}

	return results
}

func (m *Manager) checkTXT(ctx context.Context, name, expected, key string) RecordStatus {
	rs := RecordStatus{Name: name, Type: "TXT", Key: key, Expected: expected}
	records, err := m.lookup().LookupTXT(ctx, name)
	if err != nil {
		rs.Status = dnsErrStatus(err)
		return rs
	}
	for _, r := range records {
		if r == expected {
			rs.Actual = r
			rs.Status = "ok"
			return rs
		}
	}
	if len(records) > 0 {
		rs.Actual = records[0]
	}
	rs.Status = "drifted"
	return rs
}

// checkTXTPrefix verifies that some TXT record at name starts with prefix.
// suggested is the full record value displayed to the operator as the
// recommended publishable form; the actual match is prefix-only so operators
// can append qualifiers (e.g. SPF "include:..." chains).
func (m *Manager) checkTXTPrefix(ctx context.Context, name, prefix, suggested, key string) RecordStatus {
	rs := RecordStatus{Name: name, Type: "TXT", Key: key, Expected: suggested}
	records, err := m.lookup().LookupTXT(ctx, name)
	if err != nil {
		rs.Status = dnsErrStatus(err)
		return rs
	}
	for _, r := range records {
		if strings.HasPrefix(r, prefix) {
			rs.Actual = r
			rs.Status = "ok"
			return rs
		}
	}
	if len(records) > 0 {
		rs.Actual = records[0]
	}
	rs.Status = "drifted"
	return rs
}

// checkMX verifies that some MX record at name points to expectedHost. The
// MX priority is ignored — operators may use any value. suggested is the full
// record (priority + host) shown to the operator as the recommended form.
func (m *Manager) checkMX(ctx context.Context, name, expectedHost, suggested string) RecordStatus {
	rs := RecordStatus{Name: name, Type: "MX", Key: "MX", Expected: suggested}
	mxs, err := m.lookup().LookupMX(ctx, name)
	if err != nil {
		rs.Status = dnsErrStatus(err)
		return rs
	}
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		if strings.EqualFold(host, expectedHost) {
			rs.Actual = fmt.Sprintf("%d %s", mx.Pref, host)
			rs.Status = "ok"
			return rs
		}
	}
	if len(mxs) > 0 {
		rs.Actual = fmt.Sprintf("%d %s", mxs[0].Pref, strings.TrimSuffix(mxs[0].Host, "."))
	}
	rs.Status = "drifted"
	return rs
}

func (m *Manager) checkCNAME(ctx context.Context, name, expectedTarget, key string) RecordStatus {
	rs := RecordStatus{Name: name, Type: "CNAME", Key: key, Expected: expectedTarget}
	target, err := m.lookup().LookupCNAME(ctx, name)
	if err != nil {
		rs.Status = dnsErrStatus(err)
		return rs
	}
	target = strings.TrimSuffix(target, ".")
	if strings.EqualFold(target, expectedTarget) || strings.EqualFold(target, name) {
		// LookupCNAME returns the canonical name, which may equal the input if
		// no CNAME exists. We treat "same as input" as missing.
		if strings.EqualFold(target, name) {
			rs.Status = "drifted"
			return rs
		}
		rs.Actual = target
		rs.Status = "ok"
		return rs
	}
	rs.Actual = target
	rs.Status = "drifted"
	return rs
}

// dnsErrStatus maps a DNS lookup error to a record status string.
// A confirmed "not found" (NXDOMAIN / no records) becomes "missing";
// transient or indeterminate failures become "unknown".
func dnsErrStatus(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return "missing"
	}
	return "unknown"
}

func (m *Manager) lookup() *net.Resolver {
	if m.resolver != nil {
		return m.resolver
	}
	return net.DefaultResolver
}

// DNSCheckAll re-checks all verified custom domains for drift and writes
// dns_status + dns_last_checked_at. Called by the background drift worker.
func (m *Manager) DNSCheckAll(ctx context.Context) error {
	rows, err := m.db.Query(ctx, `
		SELECT id, domain, verification_token, mta_sts_id
		FROM   domains
		WHERE  is_primary = FALSE AND verified_at IS NOT NULL
		ORDER  BY dns_last_checked_at ASC NULLS FIRST
	`)
	if err != nil {
		return fmt.Errorf("domains: drift query: %w", err)
	}
	defer rows.Close()

	type dRow struct {
		id, domain, token string
		mtsID             *string
	}
	var domains []dRow
	for rows.Next() {
		var dr dRow
		var tok *string
		if err := rows.Scan(&dr.id, &dr.domain, &tok, &dr.mtsID); err != nil {
			return err
		}
		if tok != nil {
			dr.token = *tok
		}
		domains = append(domains, dr)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, dr := range domains {
		d := &Domain{Domain: dr.domain, MTASTSID: dr.mtsID}
		records := m.checkDNSRecords(ctx, d, dr.token)
		status := make(map[string]string, len(records))
		for _, r := range records {
			status[r.Key] = r.Status
			if r.Status == "drifted" {
				slog.Warn("DNS drift detected",
					"event_key", "dns_drift_detected",
					"domain", dr.domain,
					"record", r.Key,
					"expected", r.Expected,
					"actual", r.Actual,
				)
			}
		}
		statusJSON, _ := json.Marshal(status)
		if _, err := m.db.Exec(ctx, `
			UPDATE domains
			SET dns_status = $1, dns_last_checked_at = now()
			WHERE id = $2
		`, statusJSON, dr.id); err != nil {
			slog.Error("domains: update dns_status", "domain_id", dr.id, "err", err)
		}
	}
	return nil
}

// scanOne runs a single-row query using the given SQL and args and returns a Domain.
func (m *Manager) scanOne(ctx context.Context, sql string, args ...any) (*Domain, error) {
	row := m.db.QueryRow(ctx, sql, args...)
	d, err := scanDomain(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// rowScanner is the common interface for pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(...any) error
}

func scanDomain(row rowScanner) (*Domain, error) {
	var d Domain
	var statusJSON []byte
	err := row.Scan(
		&d.ID, &d.Domain, &d.IsPrimary, &d.OwnerUserID,
		&d.VerifiedAt, &d.WKDActive, &d.CreatedAt,
		&d.VerificationToken, &d.VerificationExpiresAt, &d.VerificationCheckedAt,
		&d.MTASTSMode, &d.MTASTSID, &d.MTASTSModeChangedAt,
		&d.CatchAllEnabled, &d.CatchAllAddressID,
		&d.DNSLastCheckedAt, &statusJSON,
	)
	if err != nil {
		return nil, err
	}
	if len(statusJSON) > 0 {
		_ = json.Unmarshal(statusJSON, &d.DNSStatus)
	}
	return &d, nil
}

// generateToken returns a 32-byte cryptographically random URL-safe base64
// string (no padding). Used for verification tokens and MTA-STS IDs.
func generateToken() (string, error) {
	b := make([]byte, 24) // 24 bytes → 32 base64url chars
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
