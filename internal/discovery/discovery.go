// Package discovery performs server-side PGP public-key lookup for a given
// email address.
//
// Lookup order (§8 Phase 2):
//   1. Local user directory (user_keys table) — own-domain users.
//   2. Per-user known_keys cache (keys previously seen from this correspondent).
//   3. WKD (Web Key Directory) advanced method fetch.
//
// WKD results are cached into known_keys with source="wkd" so subsequent
// lookups for the same address hit the cache instead of the network.
//
// The keyserver path is deferred to Phase 7.
package discovery

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Result is the outcome of a key discovery attempt.
type Result struct {
	ArmoredPublicKey string
	Fingerprint      string
	// Source is one of: "local", "known_keys", "wkd".
	Source      string
	FirstSeenAt *time.Time // non-nil when source == "known_keys"
}

// Discover looks up the OpenPGP public key for address.
// userID is the authenticated user performing the lookup (for known_keys scoping).
// Returns (nil, nil) when no key is found.
func Discover(ctx context.Context, db *pgxpool.Pool, userID, address string) (*Result, error) {
	address = strings.ToLower(strings.TrimSpace(address))

	// 1. Local user directory.
	if r, err := lookupLocal(ctx, db, address); err != nil {
		return nil, err
	} else if r != nil {
		return r, nil
	}

	// 2. Known-keys cache (scoped to this user's observed correspondents).
	if r, err := lookupKnownKeys(ctx, db, userID, address); err != nil {
		return nil, err
	} else if r != nil {
		return r, nil
	}

	// 3. WKD fetch.
	r, err := lookupWKD(ctx, address)
	if err != nil {
		// WKD failures are non-fatal — the address may simply not publish via WKD.
		slog.Debug("discovery: WKD lookup failed", "address", address, "err", err)
		return nil, nil //nolint:nilerr
	}
	if r == nil {
		return nil, nil
	}

	// Cache the WKD result.
	if err := cacheKey(ctx, db, userID, address, r.ArmoredPublicKey, r.Fingerprint, "wkd"); err != nil {
		slog.Warn("discovery: failed to cache WKD result", "address", address, "err", err)
		// Non-fatal.
	}
	return r, nil
}

// HarvestKey upserts a public key into the user's known_keys cache.
// source should be "auto_attach", "wkd", or "manual".
func HarvestKey(ctx context.Context, db *pgxpool.Pool, userID, address, armoredKey, source string) error {
	fp, err := fingerprint(armoredKey)
	if err != nil {
		return fmt.Errorf("discovery: harvest: %w", err)
	}
	return cacheKey(ctx, db, userID, address, armoredKey, fp, source)
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

func lookupLocal(ctx context.Context, db *pgxpool.Pool, address string) (*Result, error) {
	var fp, armored string
	err := db.QueryRow(ctx, `
		SELECT k.fingerprint, k.armored_public_key
		FROM   user_keys k
		JOIN   users u ON u.id = k.user_id
		JOIN   addresses a ON a.id = u.primary_address_id
		WHERE  a.address = $1 AND k.is_active = TRUE
	`, address).Scan(&fp, &armored)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("discovery: local lookup: %w", err)
	}
	return &Result{ArmoredPublicKey: armored, Fingerprint: fp, Source: "local"}, nil
}

func lookupKnownKeys(ctx context.Context, db *pgxpool.Pool, userID, address string) (*Result, error) {
	var fp, armored string
	var firstSeen time.Time
	err := db.QueryRow(ctx, `
		SELECT fingerprint, armored_public_key, first_seen_at
		FROM   known_keys
		WHERE  user_id = $1 AND address = $2
		ORDER  BY last_seen_at DESC
		LIMIT  1
	`, userID, address).Scan(&fp, &armored, &firstSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("discovery: known_keys lookup: %w", err)
	}
	t := firstSeen
	return &Result{ArmoredPublicKey: armored, Fingerprint: fp, Source: "known_keys", FirstSeenAt: &t}, nil
}

func lookupWKD(ctx context.Context, address string) (*Result, error) {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("discovery: invalid address %q", address)
	}
	localPart, domain := parts[0], parts[1]
	hash := wkdHash(localPart)

	// WKD Advanced Method: https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>
	url := fmt.Sprintf("https://openpgpkey.%s/.well-known/openpgpkey/%s/hu/%s", domain, domain, hash)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: WKD returned HTTP %d", resp.StatusCode)
	}

	// Response is a binary (non-armored) OpenPGP public key.
	keyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return nil, fmt.Errorf("discovery: WKD read response: %w", err)
	}

	// Parse binary key.
	entities, err := pgpcrypto.ReadKeyRing(bytes.NewReader(keyBytes))
	if err != nil || len(entities) == 0 {
		return nil, fmt.Errorf("discovery: WKD key parse failed: %w", err)
	}
	entity := entities[0]
	if entity.PrimaryKey == nil {
		return nil, fmt.Errorf("discovery: WKD key has no primary key")
	}
	fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)

	// Re-armor the key.
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: armor encode: %w", err)
	}
	if err := entity.Serialize(w); err != nil {
		return nil, fmt.Errorf("discovery: serialize key: %w", err)
	}
	w.Close()

	return &Result{ArmoredPublicKey: buf.String(), Fingerprint: fp, Source: "wkd"}, nil
}

func cacheKey(ctx context.Context, db *pgxpool.Pool, userID, address, armoredKey, fp, source string) error {
	_, err := db.Exec(ctx, `
		INSERT INTO known_keys (user_id, address, fingerprint, armored_public_key, source)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, fingerprint) DO UPDATE
		  SET armored_public_key = EXCLUDED.armored_public_key,
		      last_seen_at = now(),
		      source = EXCLUDED.source
	`, userID, address, fp, armoredKey, source)
	return err
}

func fingerprint(armoredKey string) (string, error) {
	block, err := armor.Decode(strings.NewReader(armoredKey))
	if err != nil {
		return "", err
	}
	entities, err := pgpcrypto.ReadKeyRing(block.Body)
	if err != nil || len(entities) == 0 {
		return "", fmt.Errorf("parse key ring: %w", err)
	}
	if entities[0].PrimaryKey == nil {
		return "", fmt.Errorf("no primary key")
	}
	return fmt.Sprintf("%X", entities[0].PrimaryKey.Fingerprint), nil
}

// wkdHash computes the z-base-32 encoded SHA-1 hash of the lower-cased
// local-part as required by the WKD spec. This mirrors keydir.WKDHash but is
// inlined here to avoid an import cycle.
func wkdHash(localPart string) string {
	// SHA-1 of lower-cased local part.
	h := sha1Sum([]byte(strings.ToLower(localPart)))
	return zBase32Encode(h[:])
}

// sha1Sum computes a SHA-1 hash without importing crypto/sha1 directly
// (avoiding the nolint comment we'd need). We use encoding/binary and a
// hand-rolled compression to stay dependency-free here.
// Actually, we need crypto/sha1 for correctness. This is WKD-mandated usage.
func sha1Sum(data []byte) [20]byte {
	// We cannot avoid importing crypto/sha1 for a correct SHA-1 implementation.
	// Use a local import via a helper to keep the nolint annotation contained.
	return sha1Digest(data)
}

const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

func zBase32Encode(src []byte) string {
	padded := make([]byte, (len(src)+4)/5*5)
	copy(padded, src)

	out := make([]byte, 0, len(padded)/5*8)
	for i := 0; i < len(padded); i += 5 {
		n := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, padded[i:i+5]...))
		for j := 7; j >= 0; j-- {
			out = append(out, zBase32Alphabet[(n>>(uint(j)*5))&0x1F])
		}
	}

	outputLen := (len(src)*8 + 4) / 5
	return string(out[:outputLen])
}
