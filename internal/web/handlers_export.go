package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/archive"
	"rookery/internal/auth"
	"rookery/internal/config"
	"rookery/internal/store"
)

type exportPageData struct {
	InstanceName string
	CSRFToken    string       // empty — unauthenticated page; required by base template
	User         *userProfile // nil — unauthenticated page
	DownloadURL  string
}

// ---- POST /api/v1/users/me/export -------------------------------------------
//
// Queues an async export job. The encrypted archive is assembled in a background
// goroutine; when ready, a system message is sent to the user's inbox with
// the download and migration links.

type exportJobRequest struct {
	NewInstance string `json:"new_instance"`
}

func handleAPIExport(db *pgxpool.Pool, st *store.Store, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var req exportJobRequest
		// Body is optional — an empty body or omitted new_instance is fine.
		_ = json.NewDecoder(r.Body).Decode(&req)
		newInstance := strings.TrimSpace(req.NewInstance)

		rawToken, err := generateExportToken()
		if err != nil {
			slog.Error("export: generate token", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not generate export token.")
			return
		}
		tokenHash := sha256HexOf(rawToken)

		var jobID string
		err = db.QueryRow(r.Context(), `
			INSERT INTO export_jobs (user_id, token_hash)
			VALUES ($1, $2)
			RETURNING id
		`, userID, tokenHash).Scan(&jobID)
		if err != nil {
			slog.Error("export: insert job", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not create export job.")
			return
		}

		go runExport(context.Background(), db, st, cfg, jobID, userID, rawToken, newInstance)

		respondJSON(w, http.StatusAccepted, map[string]string{
			"job_id": jobID,
			"status": "pending",
		})
	}
}

// ---- GET /api/v1/users/me/export/status -------------------------------------

func handleAPIExportStatus(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var status string
		var expiresAt time.Time
		err := db.QueryRow(r.Context(), `
			SELECT status, expires_at
			FROM   export_jobs
			WHERE  user_id = $1
			ORDER  BY created_at DESC
			LIMIT  1
		`, userID).Scan(&status, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			respondJSON(w, http.StatusOK, map[string]any{"status": "none"})
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch export status.")
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{
			"status":     status,
			"expires_at": expiresAt,
		})
	}
}

// ---- GET /export/{token}  (unauthenticated, HTML) ---------------------------
//
// Human-facing page: shows a download button (linking to the API route) and a
// domain input that generates the migration deep-link client-side.

func handleExportPage(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		token := r.PathValue("token")
		if token == "" {
			http.NotFound(w, r)
			return
		}

		var status, ownerID string
		err := db.QueryRow(r.Context(), `
			SELECT status, user_id FROM export_jobs
			WHERE  token_hash = $1 AND expires_at > now()
		`, sha256HexOf(token)).Scan(&status, &ownerID)
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			slog.Error("export page: query job", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if ownerID != userID {
			http.NotFound(w, r)
			return
		}
		if status != "ready" && status != "downloaded" {
			http.NotFound(w, r)
			return
		}

		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		renderTemplate(w, "export.gohtml", exportPageData{
			InstanceName: cfg.InstanceName,
			User:         user,
			DownloadURL:  cfg.ExternalURL() + "/api/v1/export/" + token,
		})
	}
}

// ---- GET /api/v1/export/{token}  (unauthenticated, binary) ------------------
//
// Streams the encrypted archive. Token is the bearer credential. Used by curl,
// the import proxy on instance B, and the download button on the HTML page.
// CORS-enabled so instance-B browsers can fetch the archive cross-origin.

func handleAPIExportDownload(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		if token == "" {
			http.NotFound(w, r)
			return
		}
		tokenHash := sha256HexOf(token)

		var jobID, filePath, status string
		var fingerprint string
		err := db.QueryRow(r.Context(), `
			SELECT ej.id, ej.file_path, ej.status,
			       COALESCE(uk.fingerprint, '')
			FROM   export_jobs ej
			LEFT   JOIN user_keys uk ON uk.user_id = ej.user_id AND uk.is_active = TRUE
			WHERE  ej.token_hash = $1
			  AND  ej.expires_at > now()
		`, tokenHash).Scan(&jobID, &filePath, &status, &fingerprint)
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			slog.Error("export download: query job", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if status != "ready" && status != "downloaded" {
			http.NotFound(w, r)
			return
		}
		if filePath == "" {
			http.NotFound(w, r)
			return
		}

		f, err := os.Open(filePath)
		if err != nil {
			slog.Error("export download: open file", "path", filePath, "err", err)
			http.NotFound(w, r)
			return
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil {
			slog.Error("export download: stat file", "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		fp8 := "archive"
		if len(fingerprint) >= 8 {
			fp8 = strings.ToLower(fingerprint[len(fingerprint)-8:])
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rookery-archive-%s.tar.gpg"`, fp8))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
		w.Header().Set("Access-Control-Allow-Origin", "*")

		if _, err := io.Copy(w, f); err != nil {
			slog.Error("export download: stream file", "err", err)
			return
		}

		// Mark as downloaded (still served until expiry for retries).
		_, _ = db.Exec(context.Background(), `
			UPDATE export_jobs SET status = 'downloaded' WHERE id = $1 AND status = 'ready'
		`, jobID)
	}
}

// ---- GET /api/v1/users/me/import/fetch?url=... ------------------------------
//
// Instance B's server proxies the encrypted archive from instance A back to the
// browser. The browser decrypts it with the private key in localStorage and then
// POSTs the plaintext tar to /api/v1/users/me/import.
//
// SSRF mitigations:
//   - URL must use HTTPS scheme.
//   - Destination hostname must not resolve to a private or loopback address.
//   - Redirects re-validate the destination IP.
//   - Response is limited to 10 GiB.

const importFetchMaxBytes = 10 * 1024 * 1024 * 1024 // 10 GiB

func handleAPIImportFetch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawURL := r.URL.Query().Get("url")
		if rawURL == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "url query parameter is required.")
			return
		}

		if err := validateExternalURL(rawURL); err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_URL", err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
		defer cancel()

		transport := &http.Transport{
			DialContext: ssrfSafeDialer(),
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if err := validateExternalURL(req.URL.String()); err != nil {
					return fmt.Errorf("redirect blocked: %w", err)
				}
				return nil
			},
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			respondError(w, http.StatusBadRequest, "INVALID_URL", "Could not build request.")
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			slog.Info("import fetch: upstream request failed", "url", rawURL, "err", err)
			respondError(w, http.StatusBadGateway, "FETCH_FAILED", "Could not fetch archive from remote instance.")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respondError(w, http.StatusBadGateway, "FETCH_FAILED",
				fmt.Sprintf("Remote instance returned HTTP %d.", resp.StatusCode))
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, io.LimitReader(resp.Body, importFetchMaxBytes)); err != nil {
			slog.Error("import fetch: stream to client", "err", err)
		}
	}
}

// ---- POST /api/v1/users/me/import -------------------------------------------

func handleAPIImport(db *pgxpool.Pool, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		summary, err := archive.ImportUser(r.Context(), db, st, userID, r.Body)
		if err != nil {
			slog.Info("import: failed", "user_id", userID, "err", err)
			respondError(w, http.StatusUnprocessableEntity, "IMPORT_FAILED", err.Error())
			return
		}

		respondJSON(w, http.StatusOK, summary)
	}
}

// ---- export background goroutine --------------------------------------------

func runExport(ctx context.Context, db *pgxpool.Pool, st *store.Store, cfg *config.Config, jobID, userID, rawToken, newInstance string) {
	filePath := filepath.Join(st.ExportDir, jobID+".tar.gpg")

	// Create the output file.
	f, err := os.Create(filePath)
	if err != nil {
		slog.Error("export worker: create file", "job_id", jobID, "err", err)
		markJobFailed(db, jobID, err.Error())
		return
	}
	defer f.Close()

	if err := archive.ExportUser(ctx, db, st, userID, cfg.Domain, f); err != nil {
		slog.Error("export worker: ExportUser", "job_id", jobID, "err", err)
		f.Close()
		os.Remove(filePath)
		markJobFailed(db, jobID, err.Error())
		return
	}

	if err := f.Close(); err != nil {
		slog.Error("export worker: close file", "job_id", jobID, "err", err)
		os.Remove(filePath)
		markJobFailed(db, jobID, err.Error())
		return
	}

	// Mark job ready.
	if _, err := db.Exec(ctx, `
		UPDATE export_jobs
		SET status = 'ready', file_path = $1, ready_at = now()
		WHERE id = $2
	`, filePath, jobID); err != nil {
		slog.Error("export worker: mark ready", "job_id", jobID, "err", err)
		return
	}

	// Send inbox notification.
	if err := sendExportNotification(ctx, db, st, cfg, userID, rawToken, newInstance); err != nil {
		// Non-fatal — the archive is ready even if the notification fails.
		slog.Warn("export worker: send notification", "job_id", jobID, "err", err)
	}
}

func markJobFailed(db *pgxpool.Pool, jobID, msg string) {
	_, _ = db.Exec(context.Background(), `
		UPDATE export_jobs SET status = 'failed', error_msg = $1 WHERE id = $2
	`, msg, jobID)
}

// sendExportNotification inserts a system inbox message with the download and
// migration links. The archive is already on disk; the token is the bearer.
func sendExportNotification(ctx context.Context, db *pgxpool.Pool, st *store.Store, cfg *config.Config, userID, rawToken, newInstance string) error {
	var primaryAddress string
	if err := db.QueryRow(ctx, `
		SELECT a.address
		FROM   users u
		JOIN   addresses a ON a.id = u.primary_address_id
		WHERE  u.id = $1
	`, userID).Scan(&primaryAddress); err != nil {
		return fmt.Errorf("fetch address: %w", err)
	}

	// pageURL is the human-facing landing page; archiveURL is the raw binary
	// download used in migration links (the import proxy fetches this directly).
	pageURL    := cfg.ExternalURL() + "/export/" + rawToken
	archiveURL := cfg.ExternalURL() + "/api/v1/export/" + rawToken

	var body string
	if newInstance != "" {
		migrateURL := schemeFor(newInstance) + "://" + newInstance + "/migrate?archive=" + url.QueryEscape(archiveURL)
		body = fmt.Sprintf(`Your rookery data archive is ready for download.

It expires in 24 hours.

  %s

To migrate to %s, open this link there (you do not need to be logged in —
you will need an invite for that instance and your recovery file):
  %s

To decrypt manually: gpg -d rookery-archive-*.tar.gpg | tar x
`, pageURL, newInstance, migrateURL)
	} else {
		body = fmt.Sprintf(`Your rookery data archive is ready for download.

It expires in 24 hours.

  %s

To decrypt manually: gpg -d rookery-archive-*.tar.gpg | tar x
`, pageURL)
	}

	domain := cfg.Domain
	rawMsg := buildNotificationMessage(
		"postmaster@"+domain,
		primaryAddress,
		"your rookery archive is ready",
		body,
		domain,
	)

	digest, err := st.WriteBlob([]byte(rawMsg))
	if err != nil {
		return fmt.Errorf("write blob: %w", err)
	}

	now := time.Now().UTC()
	_, err = db.Exec(ctx, `
		INSERT INTO messages
		    (user_id, folder, from_address, to_addresses, subject, message_date,
		     size_bytes, blob_sha256, security_state, signature_status, received_at)
		VALUES ($1, 'inbox', $2, $3, 'your rookery archive is ready', $4,
		        $5, $6, 'plaintext', 'none', $4)
	`, userID,
		"postmaster@"+domain,
		[]string{primaryAddress},
		now,
		int64(len(rawMsg)),
		digest,
	)
	return err
}

// buildNotificationMessage assembles a minimal RFC 5322 message.
func buildNotificationMessage(from, to, subject, body, domain string) string {
	msgID := fmt.Sprintf("<%d.export@%s>", time.Now().UnixNano(), domain)
	return fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		from, to, subject, time.Now().UTC().Format(time.RFC1123Z), msgID, body)
}

// ---- CleanupExpiredExports --------------------------------------------------
//
// Deletes archive files and marks jobs 'expired' when their 24-hour window has
// passed. Called hourly by the server worker.

func CleanupExpiredExports(ctx context.Context, db *pgxpool.Pool, exportDir string) error {
	rows, err := db.Query(ctx, `
		SELECT id, file_path
		FROM   export_jobs
		WHERE  expires_at < now()
		  AND  status NOT IN ('expired', 'failed')
	`)
	if err != nil {
		return fmt.Errorf("export cleanup: query expired: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, path string
		if err := rows.Scan(&id, &path); err != nil {
			slog.Error("export cleanup: scan row", "err", err)
			continue
		}
		if path != "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				slog.Warn("export cleanup: remove file", "path", path, "err", err)
			}
		}
		if _, err := db.Exec(ctx, `UPDATE export_jobs SET status = 'expired', file_path = NULL WHERE id = $1`, id); err != nil {
			slog.Error("export cleanup: mark expired", "id", id, "err", err)
		}
	}
	return rows.Err()
}

// ---- SSRF helpers -----------------------------------------------------------

// validateExternalURL rejects non-HTTPS URLs and URLs that resolve to private
// IP ranges at parse time.
func validateExternalURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("invalid URL")
	}
	if u.Scheme != "https" {
		return errors.New("archive URL must use HTTPS")
	}
	if u.Host == "" {
		return errors.New("archive URL has no host")
	}
	host := u.Hostname()
	// Pre-flight DNS check. The actual dial also validates (TOCTOU mitigation).
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %w", err)
	}
	for _, addr := range addrs {
		if isPrivateIP(addr.IP) {
			return errors.New("archive URL resolves to a private/loopback address")
		}
	}
	return nil
}

// ssrfSafeDialer returns a DialContext function that re-validates the resolved
// IP at connection time, providing defence against TOCTOU DNS rebinding.
func ssrfSafeDialer() func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if isPrivateIP(ip.IP) {
				return nil, errors.New("SSRF: target resolves to a private/loopback address")
			}
		}
		if len(ips) == 0 {
			return nil, errors.New("DNS lookup returned no addresses")
		}
		d := net.Dialer{}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// ---- token helpers ----------------------------------------------------------

// schemeFor returns "http" for localhost/*.localhost domains (including those
// with a port suffix like "localhost:8080"), "https" for everything else.
func schemeFor(host string) string {
	h := strings.SplitN(host, ":", 2)[0] // strip optional port
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return "http"
	}
	return "https"
}

func generateExportToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256HexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

