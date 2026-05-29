package archive_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/archive"
	"rookery/internal/store"
)

// testStore opens a test DB connection and applies migrations.
// Tests are skipped when ROOKERY_DB_PASSWORD is not set.
func testStore(t *testing.T) (*pgxpool.Pool, *store.Store) {
	t.Helper()
	dbURL := os.Getenv("ROOKERY_TEST_DB_URL")
	if dbURL == "" {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		if pass == "" {
			t.Skip("set ROOKERY_DB_PASSWORD or ROOKERY_TEST_DB_URL to run DB integration tests")
		}
		dbURL = "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
	}
	dir := t.TempDir()
	st, err := store.Open(context.Background(), dbURL, dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	return st.DB, st
}

// generateTestKey generates an in-memory Curve25519 keypair for tests.
// Returns (entity, armoredPublicKey, armoredPrivateKey).
func generateTestKey(t *testing.T, email string) (*pgpcrypto.Entity, string, string) {
	t.Helper()
	cfg := &packet.Config{RSABits: 0} // use default (ECC) config
	entity, err := pgpcrypto.NewEntity("Test User", "", email, cfg)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}

	var pubBuf, privBuf bytes.Buffer
	pw, err := armor.Encode(&pubBuf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("armor public key: %v", err)
	}
	if err := entity.Serialize(pw); err != nil {
		t.Fatalf("serialize public key: %v", err)
	}
	pw.Close()

	prw, err := armor.Encode(&privBuf, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("armor private key: %v", err)
	}
	if err := entity.SerializePrivate(prw, nil); err != nil {
		t.Fatalf("serialize private key: %v", err)
	}
	prw.Close()

	return entity, pubBuf.String(), privBuf.String()
}

// insertTestUser creates a minimal user with a real PGP key.
func insertTestUser(t *testing.T, db *pgxpool.Pool, localPart, domainID, domainName, armoredPubKey string) (userID, addrID string) {
	t.Helper()
	ctx := context.Background()

	if err := db.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	if err := db.QueryRow(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, userID, domainID, localPart, localPart+"@"+domainName).Scan(&addrID); err != nil {
		t.Fatalf("insert address: %v", err)
	}
	if _, err := db.Exec(ctx, `UPDATE users SET primary_address_id = $1 WHERE id = $2`, addrID, userID); err != nil {
		t.Fatalf("set primary address: %v", err)
	}

	// Parse fingerprint from armored key.
	var fp string
	block, _ := armor.Decode(bytes.NewReader([]byte(armoredPubKey)))
	if block != nil {
		entities, err := pgpcrypto.ReadKeyRing(block.Body)
		if err == nil && len(entities) > 0 && entities[0].PrimaryKey != nil {
			fp = hex.EncodeToString(entities[0].PrimaryKey.Fingerprint[:])
		}
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO user_keys (user_id, fingerprint, armored_public_key, algorithm, is_active)
		VALUES ($1, $2, $3, 'cv25519+ed25519', TRUE)
	`, userID, fp, armoredPubKey); err != nil {
		t.Fatalf("insert user_key: %v", err)
	}
	return userID, addrID
}

func cleanupUser(db *pgxpool.Pool, userID string) {
	db.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) //nolint:errcheck
}

// decryptArchive decrypts a binary PGP stream using the given entity's private key.
func decryptArchive(t *testing.T, encrypted []byte, entity *pgpcrypto.Entity) []byte {
	t.Helper()
	keyring := pgpcrypto.EntityList{entity}
	msg, err := pgpcrypto.ReadMessage(bytes.NewReader(encrypted), keyring, nil, nil)
	if err != nil {
		t.Fatalf("pgp read message: %v", err)
	}
	plain, err := io.ReadAll(msg.UnverifiedBody)
	if err != nil {
		t.Fatalf("read decrypted body: %v", err)
	}
	return plain
}

// TestRoundTrip exports Alice's data and imports it into Bob (same key), then verifies counts.
func TestRoundTrip(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	var domainID, domainName string
	if err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&domainID, &domainName); err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	// Alice and Bob share the same PGP key (so import fingerprint check passes).
	entity, armoredPub, _ := generateTestKey(t, "alice_rt@"+domainName)

	aliceID, _ := insertTestUser(t, db, "test_alice_rt", domainID, domainName, armoredPub)
	defer cleanupUser(db, aliceID)
	bobID, _ := insertTestUser(t, db, "test_bob_rt", domainID, domainName, armoredPub)
	defer cleanupUser(db, bobID)

	// Seed messages: msg1 (unique blob), msg2+msg3 (shared blob).
	blobA := []byte("hello blob A for rt test")
	blobB := []byte("hello blob B shared for rt test")

	sumA := sha256.Sum256(blobA)
	digestA := hex.EncodeToString(sumA[:])
	if _, err := st.WriteBlob(blobA); err != nil {
		t.Fatalf("WriteBlob A: %v", err)
	}
	sumB := sha256.Sum256(blobB)
	digestB := hex.EncodeToString(sumB[:])
	if _, err := st.WriteBlob(blobB); err != nil {
		t.Fatalf("WriteBlob B: %v", err)
	}

	insertMsg := func(digest, msgHeader string) {
		t.Helper()
		if _, err := db.Exec(ctx, `
			INSERT INTO messages (user_id, folder, from_address, subject, message_date, blob_sha256, message_id_header)
			VALUES ($1,'inbox','sender@example.com','hi',$2,$3,$4)
		`, aliceID, time.Now().UTC(), digest, msgHeader); err != nil {
			t.Fatalf("insert message: %v", err)
		}
	}
	insertMsg(digestA, "<msg-rt-1@test>")
	insertMsg(digestB, "<msg-rt-2@test>")
	insertMsg(digestB, "<msg-rt-3@test>") // same blob, different Message-ID

	// Add a known_key and a draft.
	if _, err := db.Exec(ctx, `
		INSERT INTO known_keys (user_id, address, fingerprint, armored_public_key)
		VALUES ($1,'ext@example.com','EXTFP_RT','(key)')
	`, aliceID); err != nil {
		t.Fatalf("insert known_key: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO drafts (user_id, from_address) VALUES ($1,'alice@test')`, aliceID); err != nil {
		t.Fatalf("insert draft: %v", err)
	}

	// Export Alice's archive.
	var encBuf bytes.Buffer
	if err := archive.ExportUser(ctx, db, st, aliceID, domainName, &encBuf); err != nil {
		t.Fatalf("ExportUser: %v", err)
	}

	// Decrypt.
	plaintar := decryptArchive(t, encBuf.Bytes(), entity)

	// Import into Bob (first import).
	summary, err := archive.ImportUser(ctx, db, st, bobID, bytes.NewReader(plaintar))
	if err != nil {
		t.Fatalf("ImportUser: %v", err)
	}

	if summary.ImportedMessages != 3 {
		t.Errorf("expected 3 imported messages, got %d", summary.ImportedMessages)
	}
	if summary.SkippedMessages != 0 {
		t.Errorf("expected 0 skipped messages, got %d", summary.SkippedMessages)
	}
	// 2 unique blobs (A and B), but WriteBlob is idempotent — blobs already exist from Alice's seed.
	if summary.ImportedBlobs != 2 {
		t.Errorf("expected 2 blobs processed, got %d", summary.ImportedBlobs)
	}
	if summary.ImportedKnownKeys != 1 {
		t.Errorf("expected 1 known key, got %d", summary.ImportedKnownKeys)
	}
	if summary.ImportedDrafts != 1 {
		t.Errorf("expected 1 draft, got %d", summary.ImportedDrafts)
	}

	// Verify Bob's message count in DB.
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM messages WHERE user_id = $1`, bobID).Scan(&count); err != nil {
		t.Fatalf("count bob messages: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 messages in Bob's mailbox, got %d", count)
	}
}

// TestIdempotentReImport verifies that importing twice does not duplicate messages or known_keys.
func TestIdempotentReImport(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	var domainID, domainName string
	if err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&domainID, &domainName); err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	entity, armoredPub, _ := generateTestKey(t, "alice_idem@"+domainName)

	srcID, _ := insertTestUser(t, db, "test_alice_idem_src", domainID, domainName, armoredPub)
	defer cleanupUser(db, srcID)
	dstID, _ := insertTestUser(t, db, "test_alice_idem_dst", domainID, domainName, armoredPub)
	defer cleanupUser(db, dstID)

	blob := []byte("idem blob content")
	if _, err := st.WriteBlob(blob); err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}
	sum := sha256.Sum256(blob)
	digest := hex.EncodeToString(sum[:])

	var msgID string
	if err := db.QueryRow(ctx, `
		INSERT INTO messages (user_id, folder, from_address, subject, message_date, blob_sha256, message_id_header)
		VALUES ($1,'inbox','s@e.com','test',$2,$3,'<idem-msg@test>')
		RETURNING id
	`, srcID, time.Now().UTC(), digest).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}

	if _, err := db.Exec(ctx, `
		INSERT INTO known_keys (user_id, address, fingerprint, armored_public_key)
		VALUES ($1,'c@e.com','FP_IDEM','(key)')
	`, srcID); err != nil {
		t.Fatalf("insert known_key: %v", err)
	}

	var encBuf bytes.Buffer
	if err := archive.ExportUser(ctx, db, st, srcID, domainName, &encBuf); err != nil {
		t.Fatalf("ExportUser: %v", err)
	}
	plaintar := decryptArchive(t, encBuf.Bytes(), entity)

	// Import once.
	s1, err := archive.ImportUser(ctx, db, st, dstID, bytes.NewReader(plaintar))
	if err != nil {
		t.Fatalf("ImportUser first: %v", err)
	}
	if s1.ImportedMessages != 1 {
		t.Errorf("first import: expected 1 message, got %d", s1.ImportedMessages)
	}

	// Import again (re-use the same plaintar bytes).
	s2, err := archive.ImportUser(ctx, db, st, dstID, bytes.NewReader(plaintar))
	if err != nil {
		t.Fatalf("ImportUser second: %v", err)
	}
	if s2.ImportedMessages != 0 {
		t.Errorf("second import: expected 0 messages, got %d", s2.ImportedMessages)
	}
	if s2.SkippedMessages != 1 {
		t.Errorf("second import: expected 1 skipped message, got %d", s2.SkippedMessages)
	}

	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM messages WHERE user_id = $1`, dstID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 message after two imports, got %d", count)
	}
}

// TestFingerprintMismatch verifies that importing into a user with a different key fingerprint fails.
func TestFingerprintMismatch(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	var domainID, domainName string
	if err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&domainID, &domainName); err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	entity, alicePub, _ := generateTestKey(t, "alice_fpm@"+domainName)
	_, carolPub, _ := generateTestKey(t, "carol_fpm@"+domainName)

	aliceID, _ := insertTestUser(t, db, "test_alice_fpm", domainID, domainName, alicePub)
	defer cleanupUser(db, aliceID)
	carolID, _ := insertTestUser(t, db, "test_carol_fpm", domainID, domainName, carolPub)
	defer cleanupUser(db, carolID)

	var encBuf bytes.Buffer
	if err := archive.ExportUser(ctx, db, st, aliceID, domainName, &encBuf); err != nil {
		t.Fatalf("ExportUser: %v", err)
	}
	plaintar := decryptArchive(t, encBuf.Bytes(), entity)

	// Carol tries to import Alice's archive — should fail.
	_, err := archive.ImportUser(ctx, db, st, carolID, bytes.NewReader(plaintar))
	if err == nil {
		t.Fatal("expected error for fingerprint mismatch, got nil")
	}
}

// TestBlobHashMismatch verifies that a tampered blob entry is rejected.
func TestBlobHashMismatch(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	var domainID, domainName string
	if err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&domainID, &domainName); err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	entity, alicePub, _ := generateTestKey(t, "alice_bhm@"+domainName)

	aliceID, _ := insertTestUser(t, db, "test_alice_bhm", domainID, domainName, alicePub)
	defer cleanupUser(db, aliceID)

	// Seed one message.
	blob := []byte("blob hash mismatch content")
	if _, err := st.WriteBlob(blob); err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}
	sum := sha256.Sum256(blob)
	digest := hex.EncodeToString(sum[:])
	if _, err := db.Exec(ctx, `
		INSERT INTO messages (user_id, folder, from_address, subject, message_date, blob_sha256)
		VALUES ($1,'inbox','s@e.com','t',$2,$3)
	`, aliceID, time.Now().UTC(), digest); err != nil {
		t.Fatalf("insert message: %v", err)
	}

	var encBuf bytes.Buffer
	if err := archive.ExportUser(ctx, db, st, aliceID, domainName, &encBuf); err != nil {
		t.Fatalf("ExportUser: %v", err)
	}
	plaintar := decryptArchive(t, encBuf.Bytes(), entity)

	// Tamper with the blob in the tar.
	tampered := tamperBlob(t, plaintar, digest)

	_, err := archive.ImportUser(ctx, db, st, aliceID, bytes.NewReader(tampered))
	if err == nil {
		t.Fatal("expected error for blob hash mismatch, got nil")
	}
}

// tamperBlob rewrites the blob entry content in a plaintext tar, leaving the
// entry name (and thus expected hash) unchanged.
func tamperBlob(t *testing.T, plaintar []byte, digest string) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	tr := tar.NewReader(bytes.NewReader(plaintar))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tamperBlob read: %v", err)
		}
		data, _ := io.ReadAll(tr)
		if hdr.Name == "blobs/"+digest+".eml" {
			data = []byte("tampered content — hash will not match")
			hdr.Size = int64(len(data))
		}
		tw.WriteHeader(hdr)  //nolint:errcheck
		tw.Write(data)       //nolint:errcheck
	}
	tw.Close() //nolint:errcheck
	return out.Bytes()
}

// TestPathTraversal verifies that a tar entry with ".." in the name is rejected.
func TestPathTraversal(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	var domainID, domainName string
	if err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&domainID, &domainName); err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	_, alicePub, _ := generateTestKey(t, "alice_pt@"+domainName)
	aliceID, _ := insertTestUser(t, db, "test_alice_pt", domainID, domainName, alicePub)
	defer cleanupUser(db, aliceID)

	// Build a malicious tar with a path traversal entry.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	tw.WriteHeader(&tar.Header{Name: "../../etc/passwd", Size: 6, Mode: 0o644}) //nolint:errcheck
	tw.Write([]byte("pwned"))                                                   //nolint:errcheck
	tw.Close()                                                                  //nolint:errcheck

	_, err := archive.ImportUser(ctx, db, st, aliceID, &tarBuf)
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
}

// TestSchemaVersionRejection verifies that archives with unknown schema_version are rejected.
func TestSchemaVersionRejection(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	var domainID, domainName string
	if err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&domainID, &domainName); err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	_, alicePub, _ := generateTestKey(t, "alice_svr@"+domainName)
	aliceID, _ := insertTestUser(t, db, "test_alice_svr", domainID, domainName, alicePub)
	defer cleanupUser(db, aliceID)

	// Build a tar with a manifest containing schema_version=99.
	block, _ := armor.Decode(bytes.NewReader([]byte(alicePub)))
	entities, _ := pgpcrypto.ReadKeyRing(block.Body)
	var fp string
	if len(entities) > 0 && entities[0].PrimaryKey != nil {
		fp = hex.EncodeToString(entities[0].PrimaryKey.Fingerprint[:])
	}

	manifest := `{"schema_version":99,"exported_at":"2026-01-01T00:00:00Z","source_instance":"test","key_fingerprint":"` + fp + `","display_name":"","message_count":0,"blob_count":0,"known_key_count":0,"draft_count":0,"addresses":[],"custom_domains":[]}`
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(manifest)), Mode: 0o644}) //nolint:errcheck
	tw.Write([]byte(manifest))                                                                    //nolint:errcheck
	tw.Close()                                                                                    //nolint:errcheck

	_, err := archive.ImportUser(ctx, db, st, aliceID, &tarBuf)
	if err == nil {
		t.Fatal("expected error for schema_version=99, got nil")
	}
}
