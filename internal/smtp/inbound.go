// Package smtp provides the inbound SMTP listener for a rookery instance.
//
// Phase 1 scope (from PLAN.md §8 Phase 1):
//   - Accept inbound mail on port 25 for the instance's primary domain.
//   - STARTTLS-preferred (accepts unencrypted mail because the open internet
//     still sends some; MTA-STS on our domain encourages senders to use TLS).
//   - Plus-addressing: alice+tag@domain routes to alice@domain.
//   - Reserved local-parts (postmaster, abuse, etc.) are accepted.
//   - Stores the raw RFC 5322 blob content-addressed on disk.
//   - Inserts a message metadata row in Postgres.
//   - Detects PGP/MIME structure and sets security_state accordingly.
//
// Phase 2 adds: outbound submission, DKIM signing, key harvest from auto-attached
// keys, bounce/DSN handling.
//
// §11.4 ADR-0019 decisions implemented here:
//   - Port 25, STARTTLS-preferred.
//   - Maximum message size from config (default 25 MiB).
//   - AUTH is NOT offered on port 25 (inbound MX only; submission is Phase 2).
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	netmail "net/mail"

	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-smtp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/config"
	"rookery/internal/keydir"
	"rookery/internal/store"
)

// Server wraps the go-smtp listener for inbound mail on port 25.
type Server struct {
	smtpServer *smtp.Server
	cfg        *config.Config
	db         *pgxpool.Pool
	st         *store.Store
}

// NewServer creates (but does not start) the inbound SMTP server.
// tlsConfig may be nil (no STARTTLS); when non-nil, STARTTLS is advertised.
// SMTP STARTTLS provisioning is deferred — Caddy handles HTTP TLS but cannot
// terminate SMTP, so a separate cert-management solution is needed for port 25.
func NewServer(cfg *config.Config, db *pgxpool.Pool, st *store.Store, tlsCfg *tls.Config) *Server {
	s := &Server{cfg: cfg, db: db, st: st}

	be := &inboundBackend{cfg: cfg, db: db, st: st}
	srv := smtp.NewServer(be)

	srv.Addr = net.JoinHostPort("0.0.0.0", "25")
	srv.Domain = cfg.Domain
	srv.ReadTimeout = 5 * time.Minute
	srv.WriteTimeout = 5 * time.Minute
	srv.MaxMessageBytes = cfg.SMTP.MaxMessageBytes
	srv.MaxRecipients = 100
	srv.AllowInsecureAuth = false // AUTH not offered on port 25
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
	}

	s.smtpServer = srv
	return s
}

// ListenAndServe starts the SMTP listener. It blocks until ctx is cancelled
// or an unrecoverable error occurs.
func (s *Server) ListenAndServe(ctx context.Context) error {
	slog.Info("smtp: inbound listener starting", "addr", s.smtpServer.Addr)
	errCh := make(chan error, 1)
	go func() {
		if err := s.smtpServer.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		return s.smtpServer.Close()
	case err := <-errCh:
		return err
	}
}

// -------------------------------------------------------------------------
// go-smtp backend implementation
// -------------------------------------------------------------------------

type inboundBackend struct {
	cfg *config.Config
	db  *pgxpool.Pool
	st  *store.Store
}

func (b *inboundBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &inboundSession{backend: b}, nil
}

type inboundSession struct {
	backend    *inboundBackend
	from       string
	recipients []string
}

func (s *inboundSession) AuthPlain(_, _ string) error {
	// AUTH is not offered or accepted on the inbound MX port (port 25).
	// go-smtp will not call this unless the client explicitly tries AUTH,
	// in which case we reject it.
	return smtp.ErrAuthUnsupported
}

func (s *inboundSession) Mail(from string, _ *smtp.MailOptions) error {
	s.from = strings.ToLower(strings.TrimSpace(from))
	return nil
}

func (s *inboundSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	to = strings.ToLower(strings.TrimSpace(to))
	if len(s.recipients) >= 100 {
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message: "Too many recipients"}
	}

	// Check that the recipient is a user on this instance.
	userID, _, err := resolveRecipient(context.Background(), s.backend.db, s.backend.cfg, to)
	if err != nil {
		if errors.Is(err, ErrNoSuchUser) {
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message: "No such user"}
		}
		slog.Error("smtp: rcpt lookup failed", "to", to, "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message: "Temporary error, try again later"}
	}

	// Check per-user quota.
	var quotaBytes, usedBytes int64
	if err := s.backend.db.QueryRow(context.Background(),
		`SELECT quota_bytes, used_bytes FROM users WHERE id = $1`, userID,
	).Scan(&quotaBytes, &usedBytes); err == nil {
		if quotaBytes > 0 && usedBytes >= quotaBytes {
			return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2},
				Message: "Mailbox full"}
		}
	}

	s.recipients = append(s.recipients, to)
	return nil
}

func (s *inboundSession) Data(r io.Reader) error {
	if len(s.recipients) == 0 {
		return errors.New("no recipients")
	}

	// Read the full message into memory (max size enforced by go-smtp).
	rawMsg, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("smtp: read data: %w", err)
	}

	ctx := context.Background()

	// Write the blob once; all recipients share the same blob ref.
	blobDigest, err := s.backend.st.WriteBlob(rawMsg)
	if err != nil {
		slog.Error("smtp: write blob", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message: "Temporary storage error"}
	}

	// Parse MIME headers for metadata (subject, date, to, cc, security state).
	meta := parseMeta(rawMsg)

	// Harvest any auto-attached PGP public keys from the message. This is done
	// once per message (not per recipient) since the key belongs to the sender.
	harvestedKey := extractAttachedPublicKey(rawMsg)

	for _, to := range s.recipients {
		userID, _, err := resolveRecipient(ctx, s.backend.db, s.backend.cfg, to)
		if err != nil {
			slog.Warn("smtp: recipient resolve failed at delivery time", "to", to, "err", err)
			continue
		}
		if err := storeMessage(ctx, s.backend.db, userID, s.from, meta, blobDigest, int64(len(rawMsg))); err != nil {
			slog.Error("smtp: store message", "user_id", userID, "err", err)
			// Continue to next recipient.
			continue
		}
		slog.Info("smtp: message delivered", "to", to, "from", s.from, "subject", meta.Subject, "blob", blobDigest)

		// Cache the sender's harvested key into this recipient's known_keys.
		if harvestedKey != "" {
			if err := harvestKey(ctx, s.backend.db, userID, s.from, harvestedKey); err != nil {
				slog.Debug("smtp: key harvest failed", "from", s.from, "err", err)
			}
		}
	}
	return nil
}

func (s *inboundSession) Reset() {
	s.from = ""
	s.recipients = nil
}

func (s *inboundSession) Logout() error {
	return nil
}

// -------------------------------------------------------------------------
// Recipient resolution (plus-addressing, reserved local-parts)
// -------------------------------------------------------------------------

// ErrNoSuchUser is returned by ResolveRecipient and DeliverLocal when the
// address is not a known local user.
var ErrNoSuchUser = errors.New("no such user")

// resolveRecipient maps an envelope recipient address to a user ID and the
// canonical address. It handles plus-addressing (alice+tag → alice), one-hop
// aliases, and catch-all delivery on any verified domain.
func resolveRecipient(ctx context.Context, db *pgxpool.Pool, _ *config.Config, to string) (userID, canonicalAddr string, err error) {
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return "", "", ErrNoSuchUser
	}
	localRaw, domain := parts[0], parts[1]

	// Accept any domain that is verified by this instance.
	var domainID string
	var catchAllEnabled bool
	var catchAllAddrID string // empty if NULL
	err = db.QueryRow(ctx, `
		SELECT id, catch_all_enabled, COALESCE(catch_all_address_id::text, '')
		FROM   domains
		WHERE  domain = $1 AND verified_at IS NOT NULL
	`, domain).Scan(&domainID, &catchAllEnabled, &catchAllAddrID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNoSuchUser
	}
	if err != nil {
		return "", "", err
	}

	// Strip plus-tag: alice+tag → alice.
	local := localRaw
	if idx := strings.IndexByte(local, '+'); idx >= 0 {
		local = local[:idx]
	}
	canonical := local + "@" + domain

	// Look up address by local_part + domain_id.
	var uid string
	var suspended bool
	err = db.QueryRow(ctx, `
		SELECT u.id, u.suspended_at IS NOT NULL
		FROM   addresses a
		JOIN   users u ON u.id = a.user_id
		WHERE  a.local_part = $1 AND a.domain_id = $2
	`, local, domainID).Scan(&uid, &suspended)
	if errors.Is(err, pgx.ErrNoRows) {
		// No direct match — try catch-all for this domain.
		if !catchAllEnabled || catchAllAddrID == "" {
			return "", "", ErrNoSuchUser
		}
		err = db.QueryRow(ctx, `
			SELECT u.id, u.suspended_at IS NOT NULL
			FROM   addresses a
			JOIN   users u ON u.id = a.user_id
			WHERE  a.id = $1
		`, catchAllAddrID).Scan(&uid, &suspended)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNoSuchUser
		}
		if err != nil {
			return "", "", err
		}
	} else if err != nil {
		return "", "", err
	}

	if suspended {
		return "", "", &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message: "Account suspended"}
	}
	return uid, canonical, nil
}

// -------------------------------------------------------------------------
// Message metadata parsing
// -------------------------------------------------------------------------

// MsgMeta holds the parsed metadata fields extracted from an RFC 5322 message.
type MsgMeta struct {
	Subject         string
	MessageDate     time.Time
	To              []string
	Cc              []string
	SecurityState   string // pgp_encrypted | pgp_signed_plaintext | plaintext
	SignatureStatus string // verified | unknown_key | invalid | none
	HasAttachments  bool
}

// ParseMeta parses MIME headers and structure from a raw RFC 5322 message and
// returns the metadata fields used when inserting a messages row.
func ParseMeta(raw []byte) MsgMeta {
	m := MsgMeta{
		SecurityState:   "plaintext",
		SignatureStatus: "none",
	}

	entity, err := gomessage.Read(strings.NewReader(string(raw)))
	if err != nil {
		return m
	}

	header := entity.Header
	m.Subject = header.Get("Subject")

	if dateStr := header.Get("Date"); dateStr != "" {
		if t, err := netmail.ParseDate(dateStr); err == nil {
			m.MessageDate = t
		}
	}
	if m.MessageDate.IsZero() {
		m.MessageDate = time.Now().UTC()
	}

	m.To = addressList(header.Get("To"))
	m.Cc = addressList(header.Get("Cc"))

	// Detect PGP/MIME structure.
	ct, _, _ := entity.Header.ContentType()
	switch {
	case ct == "multipart/encrypted":
		m.SecurityState = "pgp_encrypted"
	case ct == "multipart/signed":
		m.SecurityState = "pgp_signed_plaintext"
		m.SignatureStatus = "unknown_key" // JS module verifies on read
	}

	// Detect attachments: walk MIME parts.
	if mr := entity.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			disp, _, _ := part.Header.ContentDisposition()
			if strings.EqualFold(disp, "attachment") {
				m.HasAttachments = true
				break
			}
		}
	}
	return m
}

// parseMeta is an unexported alias kept for internal use.
func parseMeta(raw []byte) MsgMeta { return ParseMeta(raw) }

// DeliverLocal stores rawMsg directly into a local user's inbox without going
// through external SMTP. Used by the outbound queue worker for same-domain
// delivery so that @local messages never leave the host.
func DeliverLocal(ctx context.Context, db *pgxpool.Pool, st *store.Store, cfg *config.Config, from, to string, rawMsg []byte) error {
	userID, _, err := resolveRecipient(ctx, db, cfg, to)
	if err != nil {
		return err
	}
	blobDigest, err := st.WriteBlob(rawMsg)
	if err != nil {
		return fmt.Errorf("local delivery: write blob: %w", err)
	}
	meta := ParseMeta(rawMsg)
	return storeMessage(ctx, db, userID, from, meta, blobDigest, int64(len(rawMsg)))
}

// addressList parses an RFC 5322 address-list header value (To, Cc) into
// lower-cased email addresses, discarding display names and groups. Quoted
// names that contain commas (e.g. `"Doe, John" <john@x>`) and angle-addr
// forms are handled correctly because we delegate to net/mail's parser
// rather than splitting on raw commas.
func addressList(header string) []string {
	if header == "" {
		return []string{}
	}
	parsed, err := netmail.ParseAddressList(header)
	if err != nil {
		// Malformed header — fall back to a permissive split rather than
		// dropping the metadata entirely. The values land in the DB for
		// display only; delivery uses envelope recipients (see Rcpt).
		return fallbackAddressList(header)
	}
	addrs := make([]string, 0, len(parsed))
	for _, a := range parsed {
		if a.Address != "" {
			addrs = append(addrs, strings.ToLower(a.Address))
		}
	}
	return addrs
}

// fallbackAddressList is the previous naive splitter, kept only for
// malformed headers that net/mail rejects.
func fallbackAddressList(header string) []string {
	var addrs []string
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "<"); idx >= 0 {
			end := strings.Index(part, ">")
			if end > idx {
				part = part[idx+1 : end]
			}
		}
		if part != "" {
			addrs = append(addrs, strings.ToLower(part))
		}
	}
	return addrs
}

// -------------------------------------------------------------------------
// Message storage
// -------------------------------------------------------------------------

func storeMessage(ctx context.Context, db *pgxpool.Pool,
	userID, from string, meta MsgMeta, blobDigest string, sizeBytes int64) error {

	_, err := db.Exec(ctx, `
		INSERT INTO messages
		  (user_id, folder, from_address, to_addresses, cc_addresses,
		   subject, message_date, size_bytes, blob_sha256,
		   security_state, signature_status, has_attachments)
		VALUES ($1, 'inbox', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`,
		userID, from,
		meta.To, meta.Cc,
		meta.Subject, meta.MessageDate, sizeBytes, blobDigest,
		meta.SecurityState, meta.SignatureStatus, meta.HasAttachments,
	)
	if err != nil {
		return fmt.Errorf("storeMessage: %w", err)
	}

	// Update the user's used_bytes counter.
	_, _ = db.Exec(ctx,
		`UPDATE users SET used_bytes = used_bytes + $1 WHERE id = $2`,
		sizeBytes, userID)

	return nil
}

// -------------------------------------------------------------------------
// Key harvest — extract and cache auto-attached PGP public keys
// -------------------------------------------------------------------------

// extractAttachedPublicKey walks the MIME structure looking for an
// application/pgp-keys part and returns its content (ASCII armored) if found.
// Returns "" when no key part is present.
func extractAttachedPublicKey(raw []byte) string {
	entity, err := gomessage.Read(strings.NewReader(string(raw)))
	if err != nil {
		return ""
	}
	return walkForKey(entity)
}

func walkForKey(entity *gomessage.Entity) string {
	ct, _, _ := entity.Header.ContentType()
	if strings.EqualFold(ct, "application/pgp-keys") {
		body, err := io.ReadAll(entity.Body)
		if err == nil && len(body) > 0 {
			return string(body)
		}
	}
	mr := entity.MultipartReader()
	if mr == nil {
		return ""
	}
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if key := walkForKey(part); key != "" {
			return key
		}
	}
	return ""
}

// harvestKey upserts a sender's PGP public key into the recipient user's
// known_keys cache tagged as "auto_attach".
func harvestKey(ctx context.Context, db *pgxpool.Pool, userID, fromAddress, armoredKey string) error {
	if !strings.Contains(armoredKey, "BEGIN PGP PUBLIC KEY BLOCK") {
		return nil
	}
	fp, _, err := keydir.ParsePublicKey(armoredKey)
	if err != nil {
		return fmt.Errorf("harvestKey: parse key: %w", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO known_keys (user_id, address, fingerprint, armored_public_key, source)
		VALUES ($1, $2, $3, $4, 'auto_attach')
		ON CONFLICT (user_id, fingerprint) DO UPDATE
		  SET armored_public_key = EXCLUDED.armored_public_key,
		      last_seen_at = now()
	`, userID, fromAddress, fp, armoredKey)
	return err
}
