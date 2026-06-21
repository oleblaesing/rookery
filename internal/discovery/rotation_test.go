package discovery

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/jackc/pgx/v5/pgxpool"
)

// genEntity returns a fresh OpenPGP entity and its armored public key.
func genEntity(t *testing.T, email string) (*pgpcrypto.Entity, string) {
	t.Helper()
	e, err := pgpcrypto.NewEntity("test", "", email, nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	w.Close()
	return e, buf.String()
}

// signStatementText produces an armored, text-mode detached signature, matching
// what the browser (openpgp.js, text literal) emits.
func signStatementText(t *testing.T, e *pgpcrypto.Entity, statement string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP SIGNATURE", nil)
	if err != nil {
		t.Fatalf("armor encode sig: %v", err)
	}
	if err := pgpcrypto.DetachSignText(w, e, strings.NewReader(statement), nil); err != nil {
		t.Fatalf("DetachSignText: %v", err)
	}
	w.Close()
	return buf.String()
}

func TestVerifyDetached_acceptsValidRejectsForged(t *testing.T) {
	old, oldPub := genEntity(t, "a@example.com")
	wrong, _ := genEntity(t, "b@example.com")

	// A representative multi-line statement (the real one is built by the server).
	statement := "rookery-key-rotation:v1\nold:AAAA\nnew:BBBB\nnonce:deadbeef"

	goodSig := signStatementText(t, old, statement)
	if err := verifyDetached(oldPub, statement, goodSig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Signed by a different key → must fail against the old key.
	forged := signStatementText(t, wrong, statement)
	if err := verifyDetached(oldPub, statement, forged); err == nil {
		t.Fatal("forged signature accepted")
	}

	// Tampered statement → must fail.
	if err := verifyDetached(oldPub, statement+"x", goodSig); err == nil {
		t.Fatal("signature verified over tampered statement")
	}
}

func rotStatement(oldFP, newFP string) string {
	return "rookery-key-rotation:v1\nold:" + oldFP + "\nnew:" + newFP + "\nnonce:n"
}

func chainTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("ROOKERY_TEST_DB_URL")
	if dbURL == "" {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		if pass == "" {
			t.Skip("set ROOKERY_DB_PASSWORD or ROOKERY_TEST_DB_URL to run DB integration tests")
		}
		dbURL = "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func insertRotation(t *testing.T, db *pgxpool.Pool, userID, oldFP, newFP, oldPub, attestation, statement string) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `
		INSERT INTO key_rotations
		  (user_id, old_fingerprint, new_fingerprint,
		   old_armored_public_key, new_armored_public_key, attestation, statement)
		VALUES ($1, $2, $3, $4, '', $5, $6)
	`, userID, oldFP, newFP, oldPub, attestation, statement); err != nil {
		t.Fatalf("insert key_rotation: %v", err)
	}
}

func TestVerifyRotationChain(t *testing.T) {
	db := chainTestDB(t)
	ctx := context.Background()

	var userID string
	if err := db.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	a, aPub := genEntity(t, "a@x")
	b, bPub := genEntity(t, "b@x")
	_, cPub := genEntity(t, "c@x")
	aFP := mustFP(t, aPub)
	bFP := mustFP(t, bPub)
	cFP := mustFP(t, cPub)

	// A -> B attested by A, B -> C attested by B.
	sAB := rotStatement(aFP, bFP)
	insertRotation(t, db, userID, aFP, bFP, aPub, signStatementText(t, a, sAB), sAB)
	sBC := rotStatement(bFP, cFP)
	insertRotation(t, db, userID, bFP, cFP, bPub, signStatementText(t, b, sBC), sBC)

	if ok, err := VerifyRotationChain(ctx, db, aFP, bFP); err != nil || !ok {
		t.Errorf("single hop A->B: ok=%v err=%v", ok, err)
	}
	if ok, err := VerifyRotationChain(ctx, db, aFP, cFP); err != nil || !ok {
		t.Errorf("multi hop A->C: ok=%v err=%v", ok, err)
	}
	if ok, _ := VerifyRotationChain(ctx, db, aFP, "DEADBEEF"); ok {
		t.Error("chain to unknown fingerprint should not verify")
	}

	// Forged hop: claim C -> D but sign with the wrong key (not C).
	_, dPub := genEntity(t, "d@x")
	dFP := mustFP(t, dPub)
	wrong, _ := genEntity(t, "w@x")
	sCD := rotStatement(cFP, dFP)
	insertRotation(t, db, userID, cFP, dFP, cPub, signStatementText(t, wrong, sCD), sCD)
	if ok, _ := VerifyRotationChain(ctx, db, aFP, dFP); ok {
		t.Error("forged attestation should break the chain")
	}
}

func mustFP(t *testing.T, armoredPub string) string {
	t.Helper()
	fp, err := fingerprint(armoredPub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return fp
}
