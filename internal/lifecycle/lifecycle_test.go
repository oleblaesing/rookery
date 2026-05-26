package lifecycle_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/lifecycle"
	"rookery/internal/store"
)

// testStore opens a connection to the test postgres instance and applies
// migrations. Tests are skipped when ROOKERY_DB_PASSWORD is not set (local
// dev without a running stack).
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

// insertTestDomain creates a non-primary domain owned by ownerUserID.
// Returns the domain UUID.
func insertTestDomain(t *testing.T, db *pgxpool.Pool, domainName, ownerUserID string) string {
	t.Helper()
	var id string
	err := db.QueryRow(context.Background(), `
		INSERT INTO domains (domain, is_primary, owner_user_id, verified_at)
		VALUES ($1, FALSE, $2, now())
		RETURNING id
	`, domainName, ownerUserID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestDomain %s: %v", domainName, err)
	}
	return id
}

// insertTestUser creates a minimal user with one address on the given domain.
// Returns (userID, addressID).
func insertTestUser(t *testing.T, db *pgxpool.Pool, localPart, domainID, domainName string) (string, string) {
	t.Helper()
	ctx := context.Background()
	address := localPart + "@" + domainName

	var userID string
	err := db.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id`).Scan(&userID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	var addrID string
	err = db.QueryRow(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, $3, $4)
		RETURNING id
	`, userID, domainID, localPart, address).Scan(&addrID)
	if err != nil {
		t.Fatalf("insert address %s: %v", address, err)
	}

	_, err = db.Exec(ctx, `UPDATE users SET primary_address_id = $1 WHERE id = $2`, addrID, userID)
	if err != nil {
		t.Fatalf("set primary_address_id: %v", err)
	}

	// Insert a dummy active public key so the user can authenticate.
	_, err = db.Exec(ctx, `
		INSERT INTO user_keys (user_id, fingerprint, armored_public_key, algorithm, is_active)
		VALUES ($1, $2, '(test key)', 'ed25519', TRUE)
	`, userID, "FP_"+userID)
	if err != nil {
		t.Fatalf("insert user_key: %v", err)
	}

	return userID, addrID
}

// insertMessage inserts a message row and optionally writes a real blob.
// Returns the message UUID.
func insertMessage(t *testing.T, db *pgxpool.Pool, st *store.Store, userID, blobContent string) (string, string) {
	t.Helper()
	ctx := context.Background()

	digest, err := st.WriteBlob([]byte(blobContent))
	if err != nil {
		t.Fatalf("WriteBlob: %v", err)
	}

	var msgID string
	err = db.QueryRow(ctx, `
		INSERT INTO messages
		    (user_id, folder, from_address, subject, message_date, blob_sha256)
		VALUES ($1, 'inbox', 'sender@example.com', 'test', $2, $3)
		RETURNING id
	`, userID, time.Now().UTC(), digest).Scan(&msgID)
	if err != nil {
		t.Fatalf("insert message: %v", err)
	}
	return msgID, digest
}

// cleanup removes the test user and domain by ID so that test isolation holds
// even if the assertion step is reached before the DeleteUser call succeeds.
func cleanupUser(db *pgxpool.Pool, userID string) {
	db.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
}
func cleanupDomain(db *pgxpool.Pool, domainID string) {
	db.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
}

// TestDeleteUser_basic verifies that a user with messages, a draft, known
// keys, and a custom domain they exclusively own is fully removed, while a
// second user's data is untouched.
func TestDeleteUser_basic(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	// Use the existing primary domain for test addresses.
	var primaryDomainID, primaryDomainName string
	err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&primaryDomainID, &primaryDomainName)
	if err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	// Create Alice (the user to delete).
	aliceID, _ := insertTestUser(t, db, "test_alice_del", primaryDomainID, primaryDomainName)
	defer cleanupUser(db, aliceID) // safety net

	// Create Bob (must survive intact).
	bobID, _ := insertTestUser(t, db, "test_bob_del", primaryDomainID, primaryDomainName)
	defer cleanupUser(db, bobID)

	// Alice gets an exclusive blob.
	_, exclusiveBlob := insertMessage(t, db, st, aliceID, "alice-only content "+aliceID)

	// Alice and Bob share a blob (same content → same digest).
	sharedContent := "shared content " + aliceID + bobID
	_, sharedBlob := insertMessage(t, db, st, aliceID, sharedContent)
	insertMessage(t, db, st, bobID, sharedContent) // same digest

	// Alice has a draft.
	_, err = db.Exec(ctx, `INSERT INTO drafts (user_id, from_address) VALUES ($1, $2)`,
		aliceID, "test_alice_del@"+primaryDomainName)
	if err != nil {
		t.Fatalf("insert draft: %v", err)
	}

	// Alice has a known_key entry.
	_, err = db.Exec(ctx, `
		INSERT INTO known_keys (user_id, address, fingerprint, armored_public_key)
		VALUES ($1, 'ext@example.com', 'EXTFP1', '(key)')
	`, aliceID)
	if err != nil {
		t.Fatalf("insert known_key: %v", err)
	}

	// Alice owns a custom domain exclusively.
	customDomainName := "custom-" + aliceID + ".test"
	customDomainID := insertTestDomain(t, db, customDomainName, aliceID)
	defer cleanupDomain(db, customDomainID) // safety net

	// Insert a DKIM key for the custom domain (must cascade when domain is deleted).
	_, err = db.Exec(ctx, `
		INSERT INTO dkim_keys (domain_id, selector, algorithm, public_key_der, private_key_enc)
		VALUES ($1, 'sel1', 'ed25519', '\x01', '\x02')
	`, customDomainID)
	if err != nil {
		t.Fatalf("insert dkim_key: %v", err)
	}

	// Add Alice as having an address on the custom domain.
	var customAddrID string
	err = db.QueryRow(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, 'alice', 'alice@' || $3)
		RETURNING id
	`, aliceID, customDomainID, customDomainName).Scan(&customAddrID)
	if err != nil {
		t.Fatalf("insert custom domain address: %v", err)
	}

	// Verify preconditions.
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, aliceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("precondition: alice must exist")
	}

	// --- Execute ---
	if err := lifecycle.DeleteUser(ctx, db, st, aliceID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// --- Assert: Alice is gone ---
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, aliceID).Scan(&count); err != nil {
		t.Fatalf("count alice: %v", err)
	}
	if count != 0 {
		t.Error("user row should be gone")
	}

	if err := db.QueryRow(ctx, `SELECT count(*) FROM messages WHERE user_id = $1`, aliceID).Scan(&count); err != nil {
		t.Fatalf("count alice messages: %v", err)
	}
	if count != 0 {
		t.Error("alice's messages should be gone")
	}

	if err := db.QueryRow(ctx, `SELECT count(*) FROM drafts WHERE user_id = $1`, aliceID).Scan(&count); err != nil {
		t.Fatalf("count alice drafts: %v", err)
	}
	if count != 0 {
		t.Error("alice's drafts should be gone")
	}

	if err := db.QueryRow(ctx, `SELECT count(*) FROM known_keys WHERE user_id = $1`, aliceID).Scan(&count); err != nil {
		t.Fatalf("count alice known_keys: %v", err)
	}
	if count != 0 {
		t.Error("alice's known_keys should be gone")
	}

	// --- Assert: custom domain + DKIM are gone ---
	if err := db.QueryRow(ctx, `SELECT count(*) FROM domains WHERE id = $1`, customDomainID).Scan(&count); err != nil {
		t.Fatalf("count custom domain: %v", err)
	}
	if count != 0 {
		t.Error("custom domain should be gone")
	}

	if err := db.QueryRow(ctx, `SELECT count(*) FROM dkim_keys WHERE domain_id = $1`, customDomainID).Scan(&count); err != nil {
		t.Fatalf("count dkim_keys: %v", err)
	}
	if count != 0 {
		t.Error("dkim_keys for custom domain should be gone")
	}

	// --- Assert: exclusive blob file deleted ---
	if _, statErr := os.Stat(st.BlobPath(exclusiveBlob)); !os.IsNotExist(statErr) {
		t.Errorf("exclusive blob file should be deleted: %s", exclusiveBlob)
	}

	// --- Assert: shared blob file still present ---
	if _, statErr := os.Stat(st.BlobPath(sharedBlob)); os.IsNotExist(statErr) {
		t.Errorf("shared blob file should still exist: %s", sharedBlob)
	}

	// --- Assert: Bob's mailbox is untouched ---
	if err := db.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, bobID).Scan(&count); err != nil {
		t.Fatalf("count bob: %v", err)
	}
	if count != 1 {
		t.Error("bob's user row must survive")
	}

	if err := db.QueryRow(ctx, `SELECT count(*) FROM messages WHERE user_id = $1`, bobID).Scan(&count); err != nil {
		t.Fatalf("count bob messages: %v", err)
	}
	if count != 1 {
		t.Error("bob's message (shared blob) must survive")
	}
}

// TestDeleteUser_sharedDomainPreserved verifies that a domain with addresses
// belonging to a second user is not deleted when the first user is removed.
func TestDeleteUser_sharedDomainPreserved(t *testing.T) {
	db, st := testStore(t)
	ctx := context.Background()

	var primaryDomainID, primaryDomainName string
	err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&primaryDomainID, &primaryDomainName)
	if err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	// Alice owns a custom domain but Bob also has an address there.
	aliceID, _ := insertTestUser(t, db, "test_alice2_del", primaryDomainID, primaryDomainName)
	defer cleanupUser(db, aliceID)
	bobID, _ := insertTestUser(t, db, "test_bob2_del", primaryDomainID, primaryDomainName)
	defer cleanupUser(db, bobID)

	sharedDomainName := "shared-" + aliceID + ".test"
	sharedDomainID := insertTestDomain(t, db, sharedDomainName, aliceID)
	defer cleanupDomain(db, sharedDomainID)

	// Alice has an address on the shared domain.
	_, err = db.Exec(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, 'alice', 'alice@' || $3)
	`, aliceID, sharedDomainID, sharedDomainName)
	if err != nil {
		t.Fatalf("alice custom addr: %v", err)
	}

	// Bob also has an address on the same domain.
	_, err = db.Exec(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, 'bob', 'bob@' || $3)
	`, bobID, sharedDomainID, sharedDomainName)
	if err != nil {
		t.Fatalf("bob custom addr: %v", err)
	}

	if err := lifecycle.DeleteUser(ctx, db, st, aliceID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM domains WHERE id = $1`, sharedDomainID).Scan(&count); err != nil {
		t.Fatalf("count shared domain: %v", err)
	}
	if count != 1 {
		t.Error("shared domain must not be deleted when another user has addresses there")
	}
}

// TestDeleteUser_notFound returns an error when the user ID does not exist.
func TestDeleteUser_notFound(t *testing.T) {
	db, st := testStore(t)
	err := lifecycle.DeleteUser(context.Background(), db, st, "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error for non-existent user, got nil")
	}
}
