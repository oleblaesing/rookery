package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"rookery/internal/auth"
	"rookery/internal/store"
)

// openTestStore opens a store backed by the test DB, mirroring the skip
// behaviour of testDBPool so these tests no-op without a database.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dbURL := os.Getenv("ROOKERY_TEST_DB_URL")
	if dbURL == "" {
		pass := os.Getenv("ROOKERY_DB_PASSWORD")
		if pass == "" {
			t.Skip("set ROOKERY_DB_PASSWORD or ROOKERY_TEST_DB_URL to run DB integration tests")
		}
		dbURL = "postgres://rookery:" + pass + "@postgres:5432/rookery?sslmode=disable"
	}
	st, err := store.Open(context.Background(), dbURL, t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func TestMigratePage_rendersForAnonymous(t *testing.T) {
	db := testDBPool(t)
	st := openTestStore(t)
	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	router := buildTestRouter(db, ss, st)

	req := httptest.NewRequest(http.MethodGet,
		"/migrate?archive=https%3A%2F%2Fold.example%2Fapi%2Fv1%2Fexport%2Fabc&invite=inv123", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `id="migrate-form"`) {
		t.Error("response should contain the migrate form")
	}
	// Query params are prefilled into the form.
	if !strings.Contains(body, "https://old.example/api/v1/export/abc") {
		t.Error("archive URL should be prefilled from ?archive=")
	}
	if !strings.Contains(body, "inv123") {
		t.Error("invite token should be prefilled from ?invite=")
	}
	// The page must set an unauthenticated CSRF cookie for the register POST.
	var sawCSRF bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == auth.CSRFCookieName && c.Value != "" {
			sawCSRF = true
		}
	}
	if !sawCSRF {
		t.Errorf("expected a %s cookie to be set", auth.CSRFCookieName)
	}
}

func TestMigratePage_redirectsWhenLoggedIn(t *testing.T) {
	db := testDBPool(t)
	st := openTestStore(t)
	cfg := minimalConfig()
	ss := auth.NewSessionStore(db, cfg)
	router := buildTestRouter(db, ss, st)

	_, _, rawToken, _ := createTestHandlerUser(t, db, ss, "test_migrate_loggedin")

	req := httptest.NewRequest(http.MethodGet, "/migrate", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: rawToken})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/inbox" {
		t.Errorf("expected redirect to /inbox, got %q", loc)
	}
}
