package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/keydir"
	"rookery/internal/store"
)

func testDBURL() string {
	if u := os.Getenv("ROOKERY_TEST_DB_URL"); u != "" {
		return u
	}
	return "postgres://rookery:" + os.Getenv("ROOKERY_DB_PASSWORD") + "@postgres:5432/rookery?sslmode=disable"
}

func newKeyTestEnv(t *testing.T) (*pgxpool.Pool, *auth.SessionStore, http.Handler) {
	t.Helper()
	db := testDBPool(t)
	st, err := store.Open(context.Background(), testDBURL(), t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	return db, ss, buildTestRouter(db, ss, st)
}

// genKey returns a fresh entity, its armored public key, and the fingerprint in
// the same uppercase-hex form the server stores (keydir).
func genKey(t *testing.T, email string) (*pgpcrypto.Entity, string, string) {
	t.Helper()
	e, err := pgpcrypto.NewEntity("test", "", email, &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Curve:     packet.Curve25519,
	})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	w.Close()
	pub := buf.String()
	fp, _, err := keydir.ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return e, pub, fp
}

// signText mirrors the browser: an armored, text-mode detached signature.
func signText(t *testing.T, e *pgpcrypto.Entity, msg string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP SIGNATURE", nil)
	if err != nil {
		t.Fatalf("armor sig: %v", err)
	}
	if err := pgpcrypto.DetachSignText(w, e, strings.NewReader(msg), nil); err != nil {
		t.Fatalf("DetachSignText: %v", err)
	}
	w.Close()
	return buf.String()
}

func rotationStmt(oldFP, newFP, nonce string) string {
	return "rookery-key-rotation:v1\nold:" + oldFP + "\nnew:" + newFP + "\nnonce:" + nonce
}

// setActiveKey replaces the dummy key planted by createTestHandlerUser with a
// real one so signature verification can run.
func setActiveKey(t *testing.T, db *pgxpool.Pool, userID, fp, pub string) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`UPDATE user_keys SET fingerprint = $1, armored_public_key = $2 WHERE user_id = $3 AND is_active = TRUE`,
		fp, pub, userID); err != nil {
		t.Fatalf("set active key: %v", err)
	}
}

func issueRotationChallenge(t *testing.T, router http.Handler, rawToken, csrf string) (challengeID, nonce string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/me/rotation/challenge", nil)
	req.AddCookie(&http.Cookie{Name: "rookery_session", Value: rawToken})
	req.AddCookie(&http.Cookie{Name: "rookery_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotation challenge: %d %s", rr.Code, rr.Body)
	}
	var body struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	json.NewDecoder(rr.Body).Decode(&body)
	return body.ChallengeID, body.Nonce
}

func postRotate(router http.Handler, rawToken, csrf string, payload map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/me/rotation", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "rookery_session", Value: rawToken})
	req.AddCookie(&http.Cookie{Name: "rookery_csrf", Value: csrf})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestRotateKey_happyPath(t *testing.T) {
	db, ss, router := newKeyTestEnv(t)
	userID, addr, rawToken, csrf := createTestHandlerUser(t, db, ss, "test_rotate_ok")

	oldKey, oldPub, oldFP := genKey(t, addr)
	setActiveKey(t, db, userID, oldFP, oldPub)
	newKey, newPub, newFP := genKey(t, addr)

	challengeID, nonce := issueRotationChallenge(t, router, rawToken, csrf)
	stmt := rotationStmt(oldFP, newFP, nonce)

	rr := postRotate(router, rawToken, csrf, map[string]string{
		"challenge_id":           challengeID,
		"new_armored_public_key": newPub,
		"old_signature":          signText(t, oldKey, stmt),
		"new_signature":          signText(t, newKey, stmt),
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body)
	}

	ctx := context.Background()
	var activeFP string
	if err := db.QueryRow(ctx,
		`SELECT fingerprint FROM user_keys WHERE user_id = $1 AND is_active = TRUE`, userID).Scan(&activeFP); err != nil {
		t.Fatalf("query active key: %v", err)
	}
	if activeFP != newFP {
		t.Errorf("active fingerprint = %s, want %s", activeFP, newFP)
	}

	var oldActive bool
	if err := db.QueryRow(ctx,
		`SELECT is_active FROM user_keys WHERE user_id = $1 AND fingerprint = $2`, userID, oldFP).Scan(&oldActive); err != nil {
		t.Fatalf("query old key: %v", err)
	}
	if oldActive {
		t.Error("old key should be deactivated")
	}

	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM key_rotations WHERE user_id = $1 AND old_fingerprint = $2 AND new_fingerprint = $3`,
		userID, oldFP, newFP).Scan(&n); err != nil {
		t.Fatalf("query key_rotations: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 key_rotations row, got %d", n)
	}

	// The consumed challenge must not be replayable, even for a fresh rotation
	// (newKey is now active; try to move it on to a third key with the old nonce).
	thirdKey, thirdPub, thirdFP := genKey(t, addr)
	stmt2 := rotationStmt(newFP, thirdFP, nonce)
	rr2 := postRotate(router, rawToken, csrf, map[string]string{
		"challenge_id":           challengeID,
		"new_armored_public_key": thirdPub,
		"old_signature":          signText(t, newKey, stmt2),
		"new_signature":          signText(t, thirdKey, stmt2),
	})
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("replayed challenge: expected 401, got %d: %s", rr2.Code, rr2.Body)
	}
	if !strings.Contains(rr2.Body.String(), "INVALID_CHALLENGE") {
		t.Errorf("expected INVALID_CHALLENGE on replay, got: %s", rr2.Body)
	}
}

func TestRotateKey_wrongOldSignature(t *testing.T) {
	db, ss, router := newKeyTestEnv(t)
	userID, addr, rawToken, csrf := createTestHandlerUser(t, db, ss, "test_rotate_badsig")

	_, oldPub, oldFP := genKey(t, addr)
	setActiveKey(t, db, userID, oldFP, oldPub)
	newKey, newPub, newFP := genKey(t, addr)
	wrongKey, _, _ := genKey(t, addr)

	challengeID, nonce := issueRotationChallenge(t, router, rawToken, csrf)
	stmt := rotationStmt(oldFP, newFP, nonce)

	rr := postRotate(router, rawToken, csrf, map[string]string{
		"challenge_id":           challengeID,
		"new_armored_public_key": newPub,
		"old_signature":          signText(t, wrongKey, stmt), // not the active key
		"new_signature":          signText(t, newKey, stmt),
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad old signature, got %d: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "INVALID_SIGNATURE") {
		t.Errorf("expected INVALID_SIGNATURE, got: %s", rr.Body)
	}
}

func TestRotateKey_missingFields(t *testing.T) {
	db, ss, router := newKeyTestEnv(t)
	_, _, rawToken, csrf := createTestHandlerUser(t, db, ss, "test_rotate_missing")

	rr := postRotate(router, rawToken, csrf, map[string]string{"challenge_id": "x"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing fields, got %d: %s", rr.Code, rr.Body)
	}
}
