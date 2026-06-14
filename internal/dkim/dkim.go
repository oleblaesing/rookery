package dkim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Manager struct {
	db     *pgxpool.Pool
	aesKey []byte
}

func NewManager(db *pgxpool.Pool, masterKey string) *Manager {
	sum := sha256.Sum256([]byte(masterKey))
	return &Manager{db: db, aesKey: sum[:]}
}

func (m *Manager) EnsureKeys(ctx context.Context, domainID, domainName string) error {
	var count int
	if err := m.db.QueryRow(ctx,
		`SELECT count(*) FROM dkim_keys WHERE domain_id = $1 AND is_active = TRUE`,
		domainID,
	).Scan(&count); err != nil {
		return fmt.Errorf("dkim: check keys: %w", err)
	}
	if count >= 2 {
		m.logDNSRecords(ctx, domainID, domainName, false)
		return nil
	}

	slog.Info("dkim: generating keypairs", "domain", domainName)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("dkim: generate ed25519: %w", err)
	}
	if err := m.storeKey(ctx, domainID, "rookery-ed25519", "ed25519", edPub, edPriv); err != nil {
		return fmt.Errorf("dkim: store ed25519 key: %w", err)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("dkim: generate rsa2048: %w", err)
	}
	rsaPubDER := x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey)
	rsaPrivDER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		return fmt.Errorf("dkim: marshal rsa private key: %w", err)
	}
	if err := m.storeKey(ctx, domainID, "rookery-rsa", "rsa2048", rsaPubDER, rsaPrivDER); err != nil {
		return fmt.Errorf("dkim: store rsa key: %w", err)
	}

	slog.Info("dkim: keypairs generated", "domain", domainName)
	m.logDNSRecords(ctx, domainID, domainName, true)
	return nil
}

func (m *Manager) storeKey(ctx context.Context, domainID, selector, algorithm string, pubKeyDER []byte, privKeyBytes interface{}) error {
	var rawPriv []byte
	switch v := privKeyBytes.(type) {
	case ed25519.PrivateKey:
		rawPriv = []byte(v)
	case []byte:
		rawPriv = v
	default:
		return fmt.Errorf("dkim: unknown private key type")
	}

	encrypted, err := m.encryptKey(rawPriv)
	if err != nil {
		return fmt.Errorf("dkim: encrypt key: %w", err)
	}

	_, err = m.db.Exec(ctx, `
		INSERT INTO dkim_keys (domain_id, selector, algorithm, public_key_der, private_key_enc)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (domain_id, selector) DO NOTHING
	`, domainID, selector, algorithm, pubKeyDER, encrypted)
	return err
}

// Custom domains have no keys of their own: Sign falls back to the primary's
// keys but still sets d=<custom-domain> so receivers' CNAME-based DNS lookup
// resolves.
func (m *Manager) Sign(ctx context.Context, domainName string, r io.Reader) (io.Reader, error) {
	rows, err := m.db.Query(ctx, `
		SELECT dk.selector, dk.algorithm, dk.private_key_enc
		FROM   dkim_keys dk
		JOIN   domains d ON d.id = dk.domain_id
		WHERE  d.domain = $1 AND dk.is_active = TRUE
		ORDER  BY dk.algorithm  -- ed25519 before rsa2048
	`, domainName)
	if err != nil {
		return nil, fmt.Errorf("dkim: load keys: %w", err)
	}
	defer rows.Close()

	type keyRow struct {
		selector  string
		algorithm string
		encBytes  []byte
	}
	var keys []keyRow
	for rows.Next() {
		var k keyRow
		if err := rows.Scan(&k.selector, &k.algorithm, &k.encBytes); err != nil {
			return nil, fmt.Errorf("dkim: scan key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dkim: iterate keys: %w", err)
	}
	if len(keys) == 0 {
		// Expected for CNAME-based custom domains: use the primary's keys.
		rows, err = m.db.Query(ctx, `
			SELECT dk.selector, dk.algorithm, dk.private_key_enc
			FROM   dkim_keys dk
			JOIN   domains d ON d.id = dk.domain_id
			WHERE  d.is_primary = TRUE AND dk.is_active = TRUE
			ORDER  BY dk.algorithm
		`)
		if err != nil {
			return nil, fmt.Errorf("dkim: load primary fallback keys: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var k keyRow
			if err := rows.Scan(&k.selector, &k.algorithm, &k.encBytes); err != nil {
				return nil, fmt.Errorf("dkim: scan primary fallback key: %w", err)
			}
			keys = append(keys, k)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("dkim: iterate primary fallback keys: %w", err)
		}
		if len(keys) == 0 {
			slog.Warn("dkim: no active keys for domain or primary; message not DKIM-signed",
				"domain", domainName)
			return r, nil
		}
		slog.Debug("dkim: using primary domain keys for custom domain", "domain", domainName)
	}

	// Buffer the message so we can sign it once per key.
	rawMsg, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("dkim: read message: %w", err)
	}

	signed := rawMsg
	for _, k := range keys {
		signer, err := m.loadSigner(k.algorithm, k.encBytes)
		if err != nil {
			slog.Error("dkim: load signer", "selector", k.selector, "err", err)
			continue
		}

		opts := &dkim.SignOptions{
			Domain:                 domainName,
			Selector:               k.selector,
			Signer:                 signer,
			Hash:                   crypto.SHA256,
			HeaderCanonicalization: dkim.CanonicalizationRelaxed,
			BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		}

		var buf bytes.Buffer
		if err := dkim.Sign(&buf, bytes.NewReader(signed), opts); err != nil {
			slog.Error("dkim: sign failed", "selector", k.selector, "err", err)
			continue
		}
		signed = buf.Bytes()
	}

	return bytes.NewReader(signed), nil
}

func (m *Manager) loadSigner(algorithm string, encBytes []byte) (crypto.Signer, error) {
	rawPriv, err := m.decryptKey(encBytes)
	if err != nil {
		return nil, fmt.Errorf("dkim: decrypt key: %w", err)
	}

	switch algorithm {
	case "ed25519":
		if len(rawPriv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("dkim: ed25519 key wrong size: %d", len(rawPriv))
		}
		return ed25519.PrivateKey(rawPriv), nil
	case "rsa2048":
		key, err := x509.ParsePKCS8PrivateKey(rawPriv)
		if err != nil {
			return nil, fmt.Errorf("dkim: parse rsa private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("dkim: expected *rsa.PrivateKey")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("dkim: unknown algorithm %q", algorithm)
	}
}

func (m *Manager) ReEncryptKeys(ctx context.Context, newMgr *Manager) (int, error) {
	rows, err := m.db.Query(ctx, `SELECT id, private_key_enc FROM dkim_keys`)
	if err != nil {
		return 0, fmt.Errorf("dkim: re-encrypt: query: %w", err)
	}
	defer rows.Close()

	type pending struct {
		id     string
		newEnc []byte
	}
	var work []pending

	for rows.Next() {
		var id string
		var enc []byte
		if err := rows.Scan(&id, &enc); err != nil {
			return 0, fmt.Errorf("dkim: re-encrypt: scan: %w", err)
		}
		plain, err := m.decryptKey(enc)
		if err != nil {
			return 0, fmt.Errorf("dkim: re-encrypt: decrypt key %s: %w", id, err)
		}
		newEnc, err := newMgr.encryptKey(plain)
		if err != nil {
			return 0, fmt.Errorf("dkim: re-encrypt: re-encrypt key %s: %w", id, err)
		}
		work = append(work, pending{id: id, newEnc: newEnc})
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("dkim: re-encrypt: iterate: %w", err)
	}

	for _, w := range work {
		if _, err := m.db.Exec(ctx,
			`UPDATE dkim_keys SET private_key_enc = $1 WHERE id = $2`,
			w.newEnc, w.id,
		); err != nil {
			return 0, fmt.Errorf("dkim: re-encrypt: update key %s: %w", w.id, err)
		}
	}
	return len(work), nil
}

func (m *Manager) DNSRecords(ctx context.Context, domainName string) ([][2]string, error) {
	rows, err := m.db.Query(ctx, `
		SELECT dk.selector, dk.algorithm, dk.public_key_der
		FROM   dkim_keys dk
		JOIN   domains d ON d.id = dk.domain_id
		WHERE  d.domain = $1 AND dk.is_active = TRUE
		ORDER  BY dk.algorithm
	`, domainName)
	if err != nil {
		return nil, fmt.Errorf("dkim: query records: %w", err)
	}
	defer rows.Close()

	var out [][2]string
	for rows.Next() {
		var selector, algo string
		var pubDER []byte
		if err := rows.Scan(&selector, &algo, &pubDER); err != nil {
			return nil, err
		}
		p := base64.StdEncoding.EncodeToString(pubDER)
		k := "rsa"
		if algo == "ed25519" {
			k = "ed25519"
		}
		txt := fmt.Sprintf("v=DKIM1; k=%s; p=%s", k, p)
		out = append(out, [2]string{selector, txt})
	}
	return out, rows.Err()
}

func (m *Manager) logDNSRecords(ctx context.Context, domainID, domainName string, newKeys bool) {
	records, err := m.DNSRecords(ctx, domainName)
	if err != nil {
		slog.Error("dkim: could not retrieve DNS records for logging", "err", err)
		return
	}
	for _, r := range records {
		selector := r[0]
		txt := r[1]
		attrs := []any{
			"domain", domainName,
			"name", selector + "._domainkey." + domainName,
			"type", "TXT",
			"value", txt,
		}
		if newKeys {
			slog.Warn("DNS: DKIM TXT record required — publish in your DNS provider", attrs...)
		} else {
			slog.Info("DNS: DKIM TXT record", attrs...)
		}
	}
}

// Returns nonce + AES-256-GCM ciphertext, concatenated.
func (m *Manager) encryptKey(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (m *Manager) decryptKey(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("dkim: ciphertext too short")
	}
	nonce, ciphertext := data[:ns], data[ns:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
