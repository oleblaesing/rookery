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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
	"rookery/internal/store"
	"rookery/internal/web"
)

// testDBPool opens a connection for HTTP handler integration tests.
// Skipped if ROOKERY_DB_PASSWORD is not set.
func testDBPool(t *testing.T) *pgxpool.Pool {
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

// minimalConfig returns a config suitable for test handlers.
func minimalConfig() *config.Config {
	return &config.Config{
		Domain:       "localhost",
		InstanceName: "test",
		Policy: config.PolicyConfig{
			SessionExpiryDays: 7,
		},
	}
}

// createTestUser inserts a minimal user into the DB, issues a session, and
// returns (userID, primaryAddress, rawSessionToken, csrfToken).
func createTestHandlerUser(t *testing.T, db *pgxpool.Pool, ss *auth.SessionStore, localPart string) (userID, primaryAddress, rawToken, csrfToken string) {
	t.Helper()
	ctx := context.Background()

	var domainID, domainName string
	if err := db.QueryRow(ctx, `SELECT id, domain FROM domains WHERE is_primary = TRUE LIMIT 1`).
		Scan(&domainID, &domainName); err != nil {
		t.Fatalf("fetch primary domain: %v", err)
	}

	if err := db.QueryRow(ctx, `INSERT INTO users DEFAULT VALUES RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID) })

	primaryAddress = localPart + "@" + domainName
	var addrID string
	if err := db.QueryRow(ctx, `
		INSERT INTO addresses (user_id, domain_id, local_part, address)
		VALUES ($1, $2, $3, $4) RETURNING id
	`, userID, domainID, localPart, primaryAddress).Scan(&addrID); err != nil {
		t.Fatalf("insert address: %v", err)
	}

	if _, err := db.Exec(ctx, `UPDATE users SET primary_address_id = $1 WHERE id = $2`, addrID, userID); err != nil {
		t.Fatalf("set primary_address_id: %v", err)
	}

	// Insert dummy public key (not valid for signature verification, used only
	// for the challenge endpoint; actual signature tests need a real key).
	if _, err := db.Exec(ctx, `
		INSERT INTO user_keys (user_id, fingerprint, armored_public_key, algorithm, is_active)
		VALUES ($1, $2, '(test key)', 'ed25519', TRUE)
	`, userID, "FP_"+userID); err != nil {
		t.Fatalf("insert user_key: %v", err)
	}

	rawToken, csrfToken, err := ss.Create(ctx, userID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return
}

// buildRouter registers only the deletion endpoints under the test auth
// middleware so we can drive them without a full web stack.
func buildTestRouter(db *pgxpool.Pool, ss *auth.SessionStore, st *store.Store) http.Handler {
	cfg := minimalConfig()
	r := chi.NewRouter()
	// Register all routes via the real RegisterRoutes; we rely on the full
	// route table being present so the CSRF and auth middleware are wired up.
	// Pass a nil dkim.Manager and nil domains.Manager — deletion endpoints
	// don't use them.
	web.RegisterRoutes(r, cfg, db, st, nil, nil)
	return r
}

func TestDeletionChallenge_requiresAuth(t *testing.T) {
	db := testDBPool(t)
	dir := t.TempDir()
	st, err := store.Open(context.Background(), os.Getenv("ROOKERY_TEST_DB_URL"), dir)
	if err != nil {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		if pass == "" {
			t.Skip("no DB")
		}
		dbURL := "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
		st, err = store.Open(context.Background(), dbURL, dir)
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
	}
	t.Cleanup(st.Close)
	_ = db

	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	router := buildTestRouter(db, ss, st)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/deletion/challenge", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestDeletionChallenge_issuedForAuthenticatedUser(t *testing.T) {
	db := testDBPool(t)
	dir := t.TempDir()
	dbURL := os.Getenv("ROOKERY_TEST_DB_URL")
	if dbURL == "" {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		dbURL = "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
	}
	st, err := store.Open(context.Background(), dbURL, dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	router := buildTestRouter(db, ss, st)

	_, _, rawToken, csrfToken := createTestHandlerUser(t, db, ss, "test_delchallenge")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/deletion/challenge", nil)
	req.AddCookie(&http.Cookie{Name: "rookery_session", Value: rawToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body)
	}
	var body struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.ChallengeID == "" {
		t.Error("challenge_id must not be empty")
	}
	if body.Nonce == "" {
		t.Error("nonce must not be empty")
	}
}

func TestDeletion_wrongAddress(t *testing.T) {
	db := testDBPool(t)
	dir := t.TempDir()
	dbURL := os.Getenv("ROOKERY_TEST_DB_URL")
	if dbURL == "" {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		dbURL = "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
	}
	st, err := store.Open(context.Background(), dbURL, dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	router := buildTestRouter(db, ss, st)

	_, _, rawToken, csrfToken := createTestHandlerUser(t, db, ss, "test_delwrongaddr")

	// Issue a real challenge first.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/deletion/challenge", nil)
	req.AddCookie(&http.Cookie{Name: "rookery_session", Value: rawToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("challenge: %d %s", rr.Code, rr.Body)
	}
	var challenge struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
	}
	json.NewDecoder(rr.Body).Decode(&challenge)

	// Submit with wrong confirm_address.
	body, _ := json.Marshal(map[string]string{
		"challenge_id":     challenge.ChallengeID,
		"signed_challenge": "fake-sig",
		"confirm_address":  "wrong@example.com",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/deletion",
		bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-CSRF-Token", csrfToken)
	req2.AddCookie(&http.Cookie{Name: "rookery_session", Value: rawToken})
	rr2 := httptest.NewRecorder()
	router.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for wrong address, got %d: %s", rr2.Code, rr2.Body)
	}
	if !strings.Contains(rr2.Body.String(), "ADDRESS_MISMATCH") {
		t.Errorf("expected ADDRESS_MISMATCH error code, got: %s", rr2.Body)
	}
}

func TestDeletion_expiredChallenge(t *testing.T) {
	db := testDBPool(t)
	dir := t.TempDir()
	dbURL := os.Getenv("ROOKERY_TEST_DB_URL")
	if dbURL == "" {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		dbURL = "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
	}
	st, err := store.Open(context.Background(), dbURL, dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	router := buildTestRouter(db, ss, st)

	userID, primaryAddress, rawToken, csrfToken := createTestHandlerUser(t, db, ss, "test_delexpired")

	// Manually insert an already-expired challenge (created_at in the past).
	var challengeID string
	err = db.QueryRow(context.Background(), `
		INSERT INTO auth_challenges (address, nonce, purpose, created_at)
		VALUES ($1, 'testnonce', 'deletion', $2)
		RETURNING id
	`, primaryAddress, time.Now().Add(-10*time.Minute)).Scan(&challengeID)
	if err != nil {
		t.Fatalf("insert expired challenge: %v", err)
	}
	_ = userID

	body, _ := json.Marshal(map[string]string{
		"challenge_id":     challengeID,
		"signed_challenge": "fake-sig",
		"confirm_address":  primaryAddress,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/deletion",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(&http.Cookie{Name: "rookery_session", Value: rawToken})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired challenge, got %d: %s", rr.Code, rr.Body)
	}
	if !strings.Contains(rr.Body.String(), "INVALID_CHALLENGE") {
		t.Errorf("expected INVALID_CHALLENGE, got: %s", rr.Body)
	}
}

func TestDeletion_wrongSignature(t *testing.T) {
	db := testDBPool(t)
	dir := t.TempDir()
	dbURL := os.Getenv("ROOKERY_TEST_DB_URL")
	if dbURL == "" {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		dbURL = "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
	}
	st, err := store.Open(context.Background(), dbURL, dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)

	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	router := buildTestRouter(db, ss, st)

	_, primaryAddress, rawToken, csrfToken := createTestHandlerUser(t, db, ss, "test_delwrong_sig")

	// Insert a real unexpired challenge.
	var challengeID string
	err = db.QueryRow(context.Background(), `
		INSERT INTO auth_challenges (address, nonce, purpose)
		VALUES ($1, 'testnonce', 'deletion')
		RETURNING id
	`, primaryAddress).Scan(&challengeID)
	if err != nil {
		t.Fatalf("insert challenge: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"challenge_id":     challengeID,
		"signed_challenge": "not-a-real-pgp-signature",
		"confirm_address":  primaryAddress,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me/deletion",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	req.AddCookie(&http.Cookie{Name: "rookery_session", Value: rawToken})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// A bad signature must return 401. Note: the challenge is consumed at this
	// point (claimed before sig verification), which is intentional — it
	// prevents replay attempts with different signatures.
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad sig, got %d: %s", rr.Code, rr.Body)
	}
}
