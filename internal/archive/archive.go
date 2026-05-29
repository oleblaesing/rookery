// Package archive implements per-user data export and import for rookery.
//
// ExportUser assembles a PGP-encrypted tar archive of all portable user data
// and writes it to w. The archive is encrypted to the user's active public key
// in binary (non-armored) OpenPGP format:
//
//	gpg -d rookery-archive-*.tar.gpg | tar x
//
// ImportUser accepts a plaintext tar stream (decrypted by the caller's browser)
// and ingests the contents into the target user's mailbox. Import is idempotent
// for messages and known_keys; drafts are always inserted.
//
// See ADR-0039 for design rationale.
package archive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/store"
)

const schemaVersion = 1

// maxTarEntries guards against resource exhaustion from malicious archives.
const maxTarEntries = 1_000_000

// Manifest is the first entry in every archive.
type Manifest struct {
	SchemaVersion  int       `json:"schema_version"`
	ExportedAt     time.Time `json:"exported_at"`
	SourceInstance string    `json:"source_instance"`
	KeyFingerprint string    `json:"key_fingerprint"`
	DisplayName    string    `json:"display_name"`
	MessageCount   int       `json:"message_count"`
	BlobCount      int       `json:"blob_count"`
	KnownKeyCount  int       `json:"known_key_count"`
	DraftCount     int       `json:"draft_count"`
	Addresses      []string  `json:"addresses"`
	CustomDomains  []string  `json:"custom_domains"`
}

// ImportSummary is returned by ImportUser.
type ImportSummary struct {
	ImportedMessages  int `json:"imported_messages"`
	ImportedBlobs     int `json:"imported_blobs"`
	ImportedKnownKeys int `json:"imported_known_keys"`
	ImportedDrafts    int `json:"imported_drafts"`
	SkippedMessages   int `json:"skipped_messages"`
}

// ---- internal data types ----------------------------------------------------

type exportedMessage struct {
	ID              string     `json:"id"`
	ThreadID        *string    `json:"thread_id,omitempty"`
	Folder          string     `json:"folder"`
	FromAddress     string     `json:"from_address"`
	ToAddresses     []string   `json:"to_addresses"`
	CcAddresses     []string   `json:"cc_addresses"`
	Subject         string     `json:"subject"`
	MessageDate     time.Time  `json:"message_date"`
	SizeBytes       int64      `json:"size_bytes"`
	BlobSHA256      string     `json:"blob_sha256"`
	IsRead          bool       `json:"is_read"`
	IsStarred       bool       `json:"is_starred"`
	SecurityState   string     `json:"security_state"`
	SignatureStatus string     `json:"signature_status"`
	HasAttachments  bool       `json:"has_attachments"`
	MessageIDHeader *string    `json:"message_id_header,omitempty"`
	DeletedAt       *time.Time `json:"deleted_at,omitempty"`
	ReceivedAt      time.Time  `json:"received_at"`
}

type exportedAttachment struct {
	MessageID   string `json:"message_id"`
	PartIndex   int    `json:"part_index"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
}

type exportedKnownKey struct {
	Address          string    `json:"address"`
	Fingerprint      string    `json:"fingerprint"`
	ArmoredPublicKey string    `json:"armored_public_key"`
	Source           string    `json:"source"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
}

type exportedDraft struct {
	FromAddress   string    `json:"from_address"`
	ToAddresses   []string  `json:"to_addresses"`
	CcAddresses   []string  `json:"cc_addresses"`
	BccAddresses  []string  `json:"bcc_addresses"`
	Subject       string    `json:"subject"`
	BodyText      string    `json:"body_text"`
	InReplyTo     *string   `json:"in_reply_to,omitempty"`
	ReferencesHdr *string   `json:"references_hdr,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ---- ExportUser -------------------------------------------------------------

// ExportUser streams a PGP-encrypted tar archive of all portable user data to w.
// The archive is encrypted to the user's active public key (binary OpenPGP).
// domain is used in the manifest's source_instance field.
func ExportUser(ctx context.Context, db *pgxpool.Pool, st *store.Store, userID, domain string, w io.Writer) error {
	// 1. Fetch user's active public key and display name.
	var armoredKey, fingerprint, displayName string
	if err := db.QueryRow(ctx, `
		SELECT uk.armored_public_key, uk.fingerprint, u.display_name
		FROM   users u
		JOIN   user_keys uk ON uk.user_id = u.id AND uk.is_active = TRUE
		WHERE  u.id = $1
	`, userID).Scan(&armoredKey, &fingerprint, &displayName); err != nil {
		return fmt.Errorf("archive: fetch user key: %w", err)
	}

	// 2. Set up binary PGP encryption writer.
	pgpWriter, err := encryptTo(w, armoredKey)
	if err != nil {
		return fmt.Errorf("archive: set up PGP encryption: %w", err)
	}

	tw := tar.NewWriter(pgpWriter)

	// 3. Gather metadata (buffered in memory for JSON parts; blobs streamed from disk).
	msgs, err := fetchMessages(ctx, db, userID)
	if err != nil {
		return err
	}

	// Collect unique blob digests in first-seen order.
	seen := make(map[string]struct{}, len(msgs))
	var blobs []string
	for i := range msgs {
		d := msgs[i].BlobSHA256
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			blobs = append(blobs, d)
		}
	}

	attachments, err := fetchAttachments(ctx, db, userID)
	if err != nil {
		return err
	}
	knownKeys, err := fetchKnownKeys(ctx, db, userID)
	if err != nil {
		return err
	}
	drafts, err := fetchDrafts(ctx, db, userID)
	if err != nil {
		return err
	}
	addresses, err := fetchAddresses(ctx, db, userID)
	if err != nil {
		return err
	}
	customDomains, err := fetchCustomDomains(ctx, db, userID)
	if err != nil {
		return err
	}

	// 4. Build and write manifest (first entry).
	manifest := Manifest{
		SchemaVersion:  schemaVersion,
		ExportedAt:     time.Now().UTC(),
		SourceInstance: domain,
		KeyFingerprint: fingerprint,
		DisplayName:    displayName,
		MessageCount:   len(msgs),
		BlobCount:      len(blobs),
		KnownKeyCount:  len(knownKeys),
		DraftCount:     len(drafts),
		Addresses:      addresses,
		CustomDomains:  customDomains,
	}
	if err := writeJSON(tw, "manifest.json", manifest); err != nil {
		return fmt.Errorf("archive: write manifest: %w", err)
	}
	if err := writeBytes(tw, "public_key.asc", []byte(armoredKey)); err != nil {
		return fmt.Errorf("archive: write public_key.asc: %w", err)
	}
	if err := writeJSON(tw, "known_keys.json", knownKeys); err != nil {
		return fmt.Errorf("archive: write known_keys: %w", err)
	}
	if err := writeJSON(tw, "drafts.json", drafts); err != nil {
		return fmt.Errorf("archive: write drafts: %w", err)
	}
	if err := writeJSON(tw, "messages.json", msgs); err != nil {
		return fmt.Errorf("archive: write messages: %w", err)
	}
	if err := writeJSON(tw, "message_attachments.json", attachments); err != nil {
		return fmt.Errorf("archive: write message_attachments: %w", err)
	}

	// Stream blobs from disk last (messages.json references them; import handles ordering).
	for _, digest := range blobs {
		blobData, err := os.ReadFile(st.BlobPath(digest))
		if err != nil {
			return fmt.Errorf("archive: read blob %s: %w", digest, err)
		}
		if err := writeBytes(tw, "blobs/"+digest+".eml", blobData); err != nil {
			return fmt.Errorf("archive: write blob %s: %w", digest, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("archive: close tar: %w", err)
	}
	return pgpWriter.Close()
}

// ---- ImportUser -------------------------------------------------------------

// ImportUser reads a plaintext tar stream (already decrypted by the browser) and
// ingests the contents into userID's mailbox.
//
// Security guarantees:
//   - manifest.key_fingerprint must match the importing user's active key.
//   - Tar entry names are validated against path traversal.
//   - Each blob's SHA-256 is verified against its tar entry name.
//   - schema_version must match the known version.
func ImportUser(ctx context.Context, db *pgxpool.Pool, st *store.Store, userID string, r io.Reader) (ImportSummary, error) {
	var summary ImportSummary

	var myFingerprint string
	if err := db.QueryRow(ctx,
		`SELECT fingerprint FROM user_keys WHERE user_id = $1 AND is_active = TRUE`,
		userID,
	).Scan(&myFingerprint); err != nil {
		return summary, fmt.Errorf("archive: fetch active key: %w", err)
	}

	tr := tar.NewReader(r)

	// messages.json appears before blobs/ in the archive, so we buffer message
	// rows in memory and insert them after all blobs have been written to disk.
	var (
		manifest    *Manifest
		msgs        []exportedMessage
		attachments []exportedAttachment
		knownKeys   []exportedKnownKey
		drafts      []exportedDraft
	)

	entryCount := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return summary, fmt.Errorf("archive: read tar: %w", err)
		}

		entryCount++
		if entryCount > maxTarEntries {
			return summary, errors.New("archive: too many entries in archive")
		}

		if err := validateEntryName(hdr.Name); err != nil {
			return summary, err
		}

		switch {
		case hdr.Name == "manifest.json":
			var m Manifest
			if err := json.NewDecoder(tr).Decode(&m); err != nil {
				return summary, fmt.Errorf("archive: parse manifest: %w", err)
			}
			if m.SchemaVersion != schemaVersion {
				return summary, fmt.Errorf("archive: unsupported schema_version %d (expected %d)", m.SchemaVersion, schemaVersion)
			}
			if !strings.EqualFold(m.KeyFingerprint, myFingerprint) {
				return summary, fmt.Errorf("archive: archive fingerprint %s does not match your active key %s — cannot import someone else's archive", m.KeyFingerprint, myFingerprint)
			}
			manifest = &m

		case hdr.Name == "public_key.asc":
			_, _ = io.Copy(io.Discard, tr)

		case hdr.Name == "known_keys.json":
			if err := json.NewDecoder(tr).Decode(&knownKeys); err != nil {
				return summary, fmt.Errorf("archive: parse known_keys: %w", err)
			}

		case hdr.Name == "drafts.json":
			if err := json.NewDecoder(tr).Decode(&drafts); err != nil {
				return summary, fmt.Errorf("archive: parse drafts: %w", err)
			}

		case hdr.Name == "messages.json":
			if err := json.NewDecoder(tr).Decode(&msgs); err != nil {
				return summary, fmt.Errorf("archive: parse messages: %w", err)
			}

		case hdr.Name == "message_attachments.json":
			if err := json.NewDecoder(tr).Decode(&attachments); err != nil {
				return summary, fmt.Errorf("archive: parse message_attachments: %w", err)
			}

		case strings.HasPrefix(hdr.Name, "blobs/") && strings.HasSuffix(hdr.Name, ".eml"):
			digest := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "blobs/"), ".eml")
			if len(digest) != 64 {
				return summary, fmt.Errorf("archive: unexpected blob entry name %q", hdr.Name)
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				return summary, fmt.Errorf("archive: read blob %s: %w", digest, err)
			}
			sum := sha256.Sum256(data)
			if got := hex.EncodeToString(sum[:]); got != digest {
				return summary, fmt.Errorf("archive: blob hash mismatch for %s (computed %s)", digest, got)
			}
			if _, err := st.WriteBlob(data); err != nil {
				return summary, fmt.Errorf("archive: write blob %s: %w", digest, err)
			}
			summary.ImportedBlobs++

		default:
			_, _ = io.Copy(io.Discard, tr)
		}
	}

	if manifest == nil {
		return summary, errors.New("archive: manifest.json missing from archive")
	}

	// Insert messages now that blobs are on disk.
	// msgIDMap maps exported message ID → newly inserted DB row ID (for attachments).
	msgIDMap := make(map[string]string, len(msgs))
	for i := range msgs {
		m := &msgs[i]
		newID, inserted, err := insertMessageIfAbsent(ctx, db, userID, m)
		if err != nil {
			return summary, fmt.Errorf("archive: insert message: %w", err)
		}
		if inserted {
			summary.ImportedMessages++
			msgIDMap[m.ID] = newID
		} else {
			summary.SkippedMessages++
		}
	}

	// Insert attachment metadata only for messages we just inserted.
	for i := range attachments {
		a := &attachments[i]
		newMsgID, ok := msgIDMap[a.MessageID]
		if !ok {
			continue
		}
		_, err := db.Exec(ctx, `
			INSERT INTO message_attachments (message_id, part_index, filename, content_type, size_bytes)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT DO NOTHING
		`, newMsgID, a.PartIndex, a.Filename, a.ContentType, a.SizeBytes)
		if err != nil {
			return summary, fmt.Errorf("archive: insert attachment: %w", err)
		}
	}

	// Upsert known_keys (dedup by user_id + fingerprint).
	for i := range knownKeys {
		k := &knownKeys[i]
		_, err := db.Exec(ctx, `
			INSERT INTO known_keys (user_id, address, fingerprint, armored_public_key, source, first_seen_at, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (user_id, fingerprint) DO UPDATE
			  SET armored_public_key = EXCLUDED.armored_public_key,
			      last_seen_at = GREATEST(known_keys.last_seen_at, EXCLUDED.last_seen_at)
		`, userID, k.Address, k.Fingerprint, k.ArmoredPublicKey, k.Source, k.FirstSeenAt, k.LastSeenAt)
		if err != nil {
			return summary, fmt.Errorf("archive: upsert known_key: %w", err)
		}
		summary.ImportedKnownKeys++
	}

	// Insert drafts (no natural dedup key — re-import will duplicate them).
	for i := range drafts {
		d := &drafts[i]
		_, err := db.Exec(ctx, `
			INSERT INTO drafts
			    (user_id, from_address, to_addresses, cc_addresses, bcc_addresses,
			     subject, body_text, in_reply_to, references_hdr, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		`, userID, d.FromAddress, d.ToAddresses, d.CcAddresses, d.BccAddresses,
			d.Subject, d.BodyText, d.InReplyTo, d.ReferencesHdr, d.CreatedAt, d.UpdatedAt)
		if err != nil {
			return summary, fmt.Errorf("archive: insert draft: %w", err)
		}
		summary.ImportedDrafts++
	}

	return summary, nil
}

// insertMessageIfAbsent inserts a message row if it does not already exist.
// Dedup key: (user_id, message_id_header) when message_id_header is non-null;
// otherwise (user_id, blob_sha256, received_at).
// Returns (newID, true) if inserted, ("", false) if already present.
func insertMessageIfAbsent(ctx context.Context, db *pgxpool.Pool, userID string, m *exportedMessage) (string, bool, error) {
	// Check for existing row.
	var existingID string
	var err error
	if m.MessageIDHeader != nil && *m.MessageIDHeader != "" {
		err = db.QueryRow(ctx,
			`SELECT id FROM messages WHERE user_id = $1 AND message_id_header = $2 LIMIT 1`,
			userID, *m.MessageIDHeader,
		).Scan(&existingID)
	} else {
		err = db.QueryRow(ctx,
			`SELECT id FROM messages WHERE user_id = $1 AND blob_sha256 = $2 AND received_at = $3 LIMIT 1`,
			userID, m.BlobSHA256, m.ReceivedAt,
		).Scan(&existingID)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}
	if existingID != "" {
		return "", false, nil
	}

	var newID string
	err = db.QueryRow(ctx, `
		INSERT INTO messages
		    (user_id, thread_id, folder, from_address, to_addresses, cc_addresses,
		     subject, message_date, size_bytes, blob_sha256,
		     is_read, is_starred, security_state, signature_status, has_attachments,
		     message_id_header, deleted_at, received_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		RETURNING id
	`, userID, m.ThreadID, m.Folder, m.FromAddress, m.ToAddresses, m.CcAddresses,
		m.Subject, m.MessageDate, m.SizeBytes, m.BlobSHA256,
		m.IsRead, m.IsStarred, m.SecurityState, m.SignatureStatus, m.HasAttachments,
		m.MessageIDHeader, m.DeletedAt, m.ReceivedAt,
	).Scan(&newID)
	if err != nil {
		return "", false, err
	}
	return newID, true, nil
}

// validateEntryName rejects path traversal and absolute paths.
func validateEntryName(name string) error {
	if name == "" {
		return errors.New("archive: empty tar entry name")
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("archive: absolute path in archive: %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return fmt.Errorf("archive: path traversal in archive: %q", name)
		}
	}
	return nil
}

// ---- DB fetch helpers -------------------------------------------------------

func fetchMessages(ctx context.Context, db *pgxpool.Pool, userID string) ([]exportedMessage, error) {
	rows, err := db.Query(ctx, `
		SELECT id, thread_id, folder, from_address, to_addresses, cc_addresses,
		       subject, message_date, size_bytes, blob_sha256,
		       is_read, is_starred, security_state, signature_status, has_attachments,
		       message_id_header, deleted_at, received_at
		FROM   messages
		WHERE  user_id = $1
		ORDER  BY received_at ASC, id ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("archive: query messages: %w", err)
	}
	defer rows.Close()

	var msgs []exportedMessage
	for rows.Next() {
		var m exportedMessage
		if err := rows.Scan(
			&m.ID, &m.ThreadID, &m.Folder, &m.FromAddress, &m.ToAddresses, &m.CcAddresses,
			&m.Subject, &m.MessageDate, &m.SizeBytes, &m.BlobSHA256,
			&m.IsRead, &m.IsStarred, &m.SecurityState, &m.SignatureStatus, &m.HasAttachments,
			&m.MessageIDHeader, &m.DeletedAt, &m.ReceivedAt,
		); err != nil {
			return nil, fmt.Errorf("archive: scan message: %w", err)
		}
		if m.ToAddresses == nil {
			m.ToAddresses = []string{}
		}
		if m.CcAddresses == nil {
			m.CcAddresses = []string{}
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

func fetchAttachments(ctx context.Context, db *pgxpool.Pool, userID string) ([]exportedAttachment, error) {
	rows, err := db.Query(ctx, `
		SELECT ma.message_id, ma.part_index, ma.filename, ma.content_type, ma.size_bytes
		FROM   message_attachments ma
		JOIN   messages m ON m.id = ma.message_id
		WHERE  m.user_id = $1
		ORDER  BY ma.message_id, ma.part_index
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("archive: query attachments: %w", err)
	}
	defer rows.Close()

	var atts []exportedAttachment
	for rows.Next() {
		var a exportedAttachment
		if err := rows.Scan(&a.MessageID, &a.PartIndex, &a.Filename, &a.ContentType, &a.SizeBytes); err != nil {
			return nil, fmt.Errorf("archive: scan attachment: %w", err)
		}
		atts = append(atts, a)
	}
	return atts, rows.Err()
}

func fetchKnownKeys(ctx context.Context, db *pgxpool.Pool, userID string) ([]exportedKnownKey, error) {
	rows, err := db.Query(ctx, `
		SELECT address, fingerprint, armored_public_key, source, first_seen_at, last_seen_at
		FROM   known_keys
		WHERE  user_id = $1
		ORDER  BY first_seen_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("archive: query known_keys: %w", err)
	}
	defer rows.Close()

	var keys []exportedKnownKey
	for rows.Next() {
		var k exportedKnownKey
		if err := rows.Scan(&k.Address, &k.Fingerprint, &k.ArmoredPublicKey, &k.Source, &k.FirstSeenAt, &k.LastSeenAt); err != nil {
			return nil, fmt.Errorf("archive: scan known_key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func fetchDrafts(ctx context.Context, db *pgxpool.Pool, userID string) ([]exportedDraft, error) {
	rows, err := db.Query(ctx, `
		SELECT from_address, to_addresses, cc_addresses, bcc_addresses,
		       subject, body_text, in_reply_to, references_hdr, created_at, updated_at
		FROM   drafts
		WHERE  user_id = $1
		ORDER  BY created_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("archive: query drafts: %w", err)
	}
	defer rows.Close()

	var drafts []exportedDraft
	for rows.Next() {
		var d exportedDraft
		if err := rows.Scan(
			&d.FromAddress, &d.ToAddresses, &d.CcAddresses, &d.BccAddresses,
			&d.Subject, &d.BodyText, &d.InReplyTo, &d.ReferencesHdr, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("archive: scan draft: %w", err)
		}
		if d.ToAddresses == nil {
			d.ToAddresses = []string{}
		}
		if d.CcAddresses == nil {
			d.CcAddresses = []string{}
		}
		if d.BccAddresses == nil {
			d.BccAddresses = []string{}
		}
		drafts = append(drafts, d)
	}
	return drafts, rows.Err()
}

func fetchAddresses(ctx context.Context, db *pgxpool.Pool, userID string) ([]string, error) {
	rows, err := db.Query(ctx,
		`SELECT address FROM addresses WHERE user_id = $1 ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("archive: query addresses: %w", err)
	}
	defer rows.Close()
	var addrs []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		addrs = append(addrs, a)
	}
	return addrs, rows.Err()
}

func fetchCustomDomains(ctx context.Context, db *pgxpool.Pool, userID string) ([]string, error) {
	rows, err := db.Query(ctx,
		`SELECT domain FROM domains WHERE owner_user_id = $1 AND is_primary = FALSE ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("archive: query custom domains: %w", err)
	}
	defer rows.Close()
	var doms []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		doms = append(doms, d)
	}
	return doms, rows.Err()
}

// ---- PGP helper -------------------------------------------------------------

func encryptTo(w io.Writer, armoredKey string) (io.WriteCloser, error) {
	block, err := armor.Decode(strings.NewReader(armoredKey))
	if err != nil {
		return nil, fmt.Errorf("decode armor: %w", err)
	}
	entities, err := pgpcrypto.ReadKeyRing(block.Body)
	if err != nil || len(entities) == 0 {
		return nil, fmt.Errorf("read key ring: %w", err)
	}
	return pgpcrypto.Encrypt(w, entities, nil, nil, nil)
}

// ---- tar write helpers ------------------------------------------------------

func writeJSON(tw *tar.Writer, name string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeBytes(tw, name, data)
}

func writeBytes(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(data)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
