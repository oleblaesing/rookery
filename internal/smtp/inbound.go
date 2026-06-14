package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	netmail "net/mail"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-smtp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/config"
	"rookery/internal/keydir"
	"rookery/internal/store"
)

type Server struct {
	smtpServer *smtp.Server
	cfg        *config.Config
	db         *pgxpool.Pool
	st         *store.Store
}

// STARTTLS is advertised only when tlsCfg is non-nil; Caddy can't terminate
// SMTP, so port 25 needs its own cert source.
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
	srv.AllowInsecureAuth = false
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
	}

	s.smtpServer = srv
	return s
}

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
	// MX port never offers AUTH; reject if a client tries anyway.
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

	userID, _, err := resolveRecipient(context.Background(), s.backend.db, s.backend.cfg, to)
	if err != nil {
		if errors.Is(err, ErrNoSuchUser) {
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message: "No such user"}
		}
		slog.Error("smtp: rcpt lookup failed", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message: "Temporary error, try again later"}
	}

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

	rawMsg, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("smtp: read data: %w", err)
	}

	ctx := context.Background()

	// Spam check soft-fails: on any rspamd error we deliver anyway.
	if url := s.backend.cfg.Spam.RspamdURL; url != "" {
		action, score, checkErr := rspamdCheck(ctx, url, s.from, s.recipients, rawMsg)
		if checkErr != nil {
			slog.Warn("smtp: rspamd check failed, delivering anyway", "err", checkErr)
		} else {
			switch action {
			case "reject":
				slog.Info("smtp: rspamd rejected message", "score", score, "from", s.from)
				return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
					Message: "Message rejected as spam"}
			case "greylist", "soft reject":
				slog.Info("smtp: rspamd soft-rejected message", "action", action, "score", score)
				return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 0},
					Message: "Please try again later"}
			default:
				// "add header"/"rewrite subject": rspamd already edited the body.
			}
		}
	}

	// One blob, shared by every recipient's message row.
	blobDigest, err := s.backend.st.WriteBlob(rawMsg)
	if err != nil {
		slog.Error("smtp: write blob", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message: "Temporary storage error"}
	}

	meta := parseMeta(rawMsg)

	// Harvested once: the key belongs to the sender, not the recipient.
	harvestedKey := extractAttachedPublicKey(rawMsg)

	for _, to := range s.recipients {
		userID, _, err := resolveRecipient(ctx, s.backend.db, s.backend.cfg, to)
		if err != nil {
			slog.Warn("smtp: recipient resolve failed at delivery time", "err", err)
			continue
		}
		if _, err := storeMessage(ctx, s.backend.db, userID, s.from, meta, blobDigest, int64(len(rawMsg))); err != nil {
			slog.Error("smtp: store message", "user_id", userID, "err", err)
			continue
		}
		slog.Info("smtp: message delivered", "blob", blobDigest)

		if harvestedKey != "" {
			if err := harvestKey(ctx, s.backend.db, userID, s.from, harvestedKey); err != nil {
				slog.Debug("smtp: key harvest failed", "err", err)
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

var ErrNoSuchUser = errors.New("no such user")

func resolveRecipient(ctx context.Context, db *pgxpool.Pool, _ *config.Config, to string) (userID, canonicalAddr string, err error) {
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return "", "", ErrNoSuchUser
	}
	localRaw, domain := parts[0], parts[1]

	var domainID string
	var catchAllEnabled bool
	var catchAllAddrID string
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

	local := localRaw
	if idx := strings.IndexByte(local, '+'); idx >= 0 {
		local = local[:idx]
	}
	canonical := local + "@" + domain

	var uid string
	var suspended bool
	err = db.QueryRow(ctx, `
		SELECT u.id, u.suspended_at IS NOT NULL
		FROM   addresses a
		JOIN   users u ON u.id = a.user_id
		WHERE  a.local_part = $1 AND a.domain_id = $2
	`, local, domainID).Scan(&uid, &suspended)
	if errors.Is(err, pgx.ErrNoRows) {
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

type AttachmentMeta struct {
	PartIndex   int
	Filename    string
	ContentType string
	SizeBytes   int64
}

type AttachmentPart struct {
	Filename    string
	ContentType string
	Body        []byte
}

type MsgMeta struct {
	Subject         string
	MessageDate     time.Time
	To              []string
	Cc              []string
	SecurityState   string
	SignatureStatus string
	HasAttachments  bool
	// nil for encrypted messages; the browser rebuilds the list after decrypt.
	Attachments []AttachmentMeta
}

// Excludes PGP wrapper types and the text body so only user-visible attachments count.
func isAttachmentPart(ct, disp string) bool {
	ctLower := strings.ToLower(strings.TrimSpace(ct))
	switch ctLower {
	case "application/pgp-encrypted", "application/pgp-keys", "application/pgp-signature":
		return false
	}
	if strings.EqualFold(disp, "attachment") {
		return true
	}
	return !strings.HasPrefix(ctLower, "text/") &&
		!strings.HasPrefix(ctLower, "multipart/") &&
		ctLower != ""
}

// Discards body bytes after sizing them to keep memory flat.
func collectAttachmentMeta(entity *gomessage.Entity, result *[]AttachmentMeta, idx *int) {
	ct, ctParams, _ := entity.Header.ContentType()
	disp, dispParams, _ := entity.Header.ContentDisposition()

	if mr := entity.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			collectAttachmentMeta(part, result, idx)
		}
		return
	}

	if !isAttachmentPart(ct, disp) {
		return
	}

	filename := dispParams["filename"]
	if filename == "" {
		filename = ctParams["name"]
	}
	if filename == "" {
		filename = fmt.Sprintf("attachment-%d", *idx)
	}

	n, _ := io.Copy(io.Discard, entity.Body)
	*result = append(*result, AttachmentMeta{
		PartIndex:   *idx,
		Filename:    filename,
		ContentType: ct,
		SizeBytes:   n,
	})
	(*idx)++
}

func collectAllParts(entity *gomessage.Entity, parts *[]*AttachmentPart) {
	ct, ctParams, _ := entity.Header.ContentType()
	disp, dispParams, _ := entity.Header.ContentDisposition()

	if mr := entity.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			collectAllParts(part, parts)
		}
		return
	}

	if !isAttachmentPart(ct, disp) {
		return
	}

	filename := dispParams["filename"]
	if filename == "" {
		filename = ctParams["name"]
	}
	if filename == "" {
		filename = fmt.Sprintf("attachment-%d", len(*parts))
	}

	body, _ := io.ReadAll(entity.Body)
	*parts = append(*parts, &AttachmentPart{
		Filename:    filename,
		ContentType: ct,
		Body:        body,
	})
}

func ReadAttachmentAt(raw []byte, index int) (*AttachmentPart, error) {
	entity, err := gomessage.Read(strings.NewReader(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("parse MIME: %w", err)
	}
	var parts []*AttachmentPart
	collectAllParts(entity, &parts)
	if index < 0 || index >= len(parts) {
		return nil, fmt.Errorf("attachment index %d out of range (message has %d attachment(s))", index, len(parts))
	}
	return parts[index], nil
}

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

	ct, _, _ := entity.Header.ContentType()
	switch {
	case ct == "multipart/encrypted":
		m.SecurityState = "pgp_encrypted"
	case ct == "multipart/signed":
		m.SecurityState = "pgp_signed_plaintext"
		m.SignatureStatus = "unknown_key" // the JS module verifies on read
	}

	// Encrypted messages reveal nothing on the outer MIME, so skip the walk and
	// let the browser list attachments after decrypt. A fresh reader avoids
	// disturbing the content-type read above.
	if m.SecurityState != "pgp_encrypted" {
		entity2, err2 := gomessage.Read(strings.NewReader(string(raw)))
		if err2 == nil {
			var idx int
			collectAttachmentMeta(entity2, &m.Attachments, &idx)
			m.HasAttachments = len(m.Attachments) > 0
		}
	}
	return m
}

func parseMeta(raw []byte) MsgMeta { return ParseMeta(raw) }

// Stores into a local inbox so same-domain mail never leaves the host.
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
	_, err = storeMessage(ctx, db, userID, from, meta, blobDigest, int64(len(rawMsg)))
	return err
}

// Delegates to net/mail so commas inside quoted display names don't split an address.
func addressList(header string) []string {
	if header == "" {
		return []string{}
	}
	parsed, err := netmail.ParseAddressList(header)
	if err != nil {
		// These values are display-only (delivery uses envelope recipients), so
		// a malformed header falls back to a split rather than dropping metadata.
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

// Handles only headers net/mail rejects.
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

func storeMessage(ctx context.Context, db *pgxpool.Pool,
	userID, from string, meta MsgMeta, blobDigest string, sizeBytes int64) (string, error) {

	var messageID string
	err := db.QueryRow(ctx, `
		INSERT INTO messages
		  (user_id, folder, from_address, to_addresses, cc_addresses,
		   subject, message_date, size_bytes, blob_sha256,
		   security_state, signature_status, has_attachments)
		VALUES ($1, 'inbox', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`,
		userID, from,
		meta.To, meta.Cc,
		meta.Subject, meta.MessageDate, sizeBytes, blobDigest,
		meta.SecurityState, meta.SignatureStatus, meta.HasAttachments,
	).Scan(&messageID)
	if err != nil {
		return "", fmt.Errorf("storeMessage: %w", err)
	}

	_, _ = db.Exec(ctx,
		`UPDATE users SET used_bytes = used_bytes + $1 WHERE id = $2`,
		sizeBytes, userID)

	// Non-fatal: the message is already stored, so a failed attachment row just
	// makes the download endpoint 404 rather than corrupting anything.
	for _, a := range meta.Attachments {
		_, _ = db.Exec(ctx, `
			INSERT INTO message_attachments (message_id, part_index, filename, content_type, size_bytes)
			VALUES ($1, $2, $3, $4, $5)
		`, messageID, a.PartIndex, a.Filename, a.ContentType, a.SizeBytes)
	}

	return messageID, nil
}

func extractAttachedPublicKey(raw []byte) string {
	entity, err := gomessage.Read(strings.NewReader(string(raw)))
	if err != nil {
		return ""
	}
	if key := walkForKey(entity); key != "" {
		return key
	}
	return extractAutocryptKey(entity)
}

func extractAutocryptKey(entity *gomessage.Entity) string {
	hdr := entity.Header.Get("Autocrypt")
	if hdr == "" {
		return ""
	}
	var keydata string
	for _, field := range strings.Split(hdr, ";") {
		field = strings.TrimSpace(field)
		if strings.HasPrefix(strings.ToLower(field), "keydata=") {
			keydata = field[len("keydata="):]
			break
		}
	}
	if keydata == "" {
		return ""
	}
	// Drop whitespace inserted by header folding before base64-decoding.
	keydata = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, keydata)
	binKey, err := base64.StdEncoding.DecodeString(keydata)
	if err != nil {
		return ""
	}
	return armorBinaryKey(binKey)
}

func armorBinaryKey(binKey []byte) string {
	entities, err := pgpcrypto.ReadKeyRing(bytes.NewReader(binKey))
	if err != nil || len(entities) == 0 {
		return ""
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return ""
	}
	if err := entities[0].Serialize(w); err != nil {
		return ""
	}
	w.Close()
	return buf.String()
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

// Callers treat any error as soft-fail.
func rspamdCheck(ctx context.Context, rspamdURL, from string, rcpts []string, msg []byte) (action string, score float64, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		rspamdURL+"/checkv2", bytes.NewReader(msg))
	if err != nil {
		return "no action", 0, err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	if from != "" {
		req.Header.Set("From", from)
	}
	for _, r := range rcpts {
		req.Header.Add("Rcpt", r)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "no action", 0, err
	}
	defer resp.Body.Close()

	var result struct {
		Action string  `json:"action"`
		Score  float64 `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "no action", 0, fmt.Errorf("rspamd: decode response: %w", err)
	}
	if result.Action == "" {
		result.Action = "no action"
	}
	return result.Action, result.Score, nil
}
