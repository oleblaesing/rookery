package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/smtp"
	"rookery/internal/store"
)

// -------------------------------------------------------------------------
// GET /api/v1/messages
// -------------------------------------------------------------------------

type messageListItem struct {
	ID              string    `json:"id"`
	ThreadID        *string   `json:"thread_id,omitempty"`
	Folder          string    `json:"folder"`
	FromAddress     string    `json:"from_address"`
	To              []string  `json:"to"`
	Cc              []string  `json:"cc"`
	Subject         string    `json:"subject"`
	Date            time.Time `json:"date"`
	SizeBytes       int64     `json:"size_bytes"`
	IsRead          bool      `json:"is_read"`
	IsStarred       bool      `json:"is_starred"`
	SecurityState   string    `json:"security_state"`
	SignatureStatus string    `json:"signature_status"`
	HasAttachments  bool      `json:"has_attachments"`
	ReceivedAt      time.Time `json:"received_at"`
}

func handleAPIListMessages(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		folder := r.URL.Query().Get("folder")
		if folder == "" {
			folder = "inbox"
		}

		rows, err := db.Query(r.Context(), `
			SELECT id, thread_id, folder, from_address, to_addresses, cc_addresses,
			       subject, message_date, size_bytes, is_read, is_starred,
			       security_state, signature_status, has_attachments, received_at
			FROM   messages
			WHERE  user_id = $1
			  AND  folder   = $2
			ORDER  BY message_date DESC
			LIMIT  50
		`, userID, folder)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not list messages.")
			return
		}
		defer rows.Close()

		var items []messageListItem
		for rows.Next() {
			var m messageListItem
			if err := rows.Scan(
				&m.ID, &m.ThreadID, &m.Folder, &m.FromAddress, &m.To, &m.Cc,
				&m.Subject, &m.Date, &m.SizeBytes, &m.IsRead, &m.IsStarred,
				&m.SecurityState, &m.SignatureStatus, &m.HasAttachments, &m.ReceivedAt,
			); err != nil {
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not read message.")
				return
			}
			if m.To == nil {
				m.To = []string{}
			}
			if m.Cc == nil {
				m.Cc = []string{}
			}
			items = append(items, m)
		}
		if err := rows.Err(); err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not read messages.")
			return
		}
		if items == nil {
			items = []messageListItem{}
		}
		respondJSON(w, http.StatusOK, map[string]any{
			"items":       items,
			"next_cursor": nil,
		})
	}
}

// -------------------------------------------------------------------------
// GET /api/v1/messages/{id}
// -------------------------------------------------------------------------

func handleAPIGetMessage(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")

		var m messageListItem
		err := db.QueryRow(r.Context(), `
			SELECT id, thread_id, folder, from_address, to_addresses, cc_addresses,
			       subject, message_date, size_bytes, is_read, is_starred,
			       security_state, signature_status, has_attachments, received_at
			FROM   messages
			WHERE  id = $1 AND user_id = $2
		`, msgID, userID).Scan(
			&m.ID, &m.ThreadID, &m.Folder, &m.FromAddress, &m.To, &m.Cc,
			&m.Subject, &m.Date, &m.SizeBytes, &m.IsRead, &m.IsStarred,
			&m.SecurityState, &m.SignatureStatus, &m.HasAttachments, &m.ReceivedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "MESSAGE_NOT_FOUND", "No message with that ID exists in this mailbox.")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch message.")
			return
		}
		if m.To == nil {
			m.To = []string{}
		}
		if m.Cc == nil {
			m.Cc = []string{}
		}

		// Mark as read on first fetch.
		if !m.IsRead {
			_, _ = db.Exec(r.Context(),
				`UPDATE messages SET is_read = TRUE WHERE id = $1 AND user_id = $2`,
				msgID, userID)
			m.IsRead = true
		}
		respondJSON(w, http.StatusOK, m)
	}
}

// -------------------------------------------------------------------------
// GET /api/v1/messages/{id}/raw
// -------------------------------------------------------------------------
// Returns the raw RFC 5322 blob. The browser JS module fetches this to
// decrypt PGP/MIME bodies locally. The server never decrypts.

func handleAPIGetMessageRaw(db *pgxpool.Pool, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")

		var blobSHA256 string
		err := db.QueryRow(r.Context(),
			`SELECT blob_sha256 FROM messages WHERE id = $1 AND user_id = $2`,
			msgID, userID,
		).Scan(&blobSHA256)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "MESSAGE_NOT_FOUND", "No message with that ID exists in this mailbox.")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch message.")
			return
		}

		w.Header().Set("Content-Type", "message/rfc822")
		if err := st.ReadBlobInto(blobSHA256, w); err != nil {
			// Headers already sent; nothing to do but log.
			return
		}
	}
}

// -------------------------------------------------------------------------
// PATCH /api/v1/messages/{id}
// -------------------------------------------------------------------------
// Allowed fields: is_read, is_starred, folder (move between virtual views).

type patchMessageRequest struct {
	IsRead    *bool   `json:"is_read,omitempty"`
	IsStarred *bool   `json:"is_starred,omitempty"`
	Folder    *string `json:"folder,omitempty"`
}

var validFolders = map[string]bool{
	"inbox":   true,
	"sent":    true,
	"drafts":  true,
	"trash":   true,
	"bounced": true,
}

func handleAPIPatchMessage(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")

		var req patchMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}

		if req.Folder != nil && !validFolders[*req.Folder] {
			respondErrorDetail(w, http.StatusUnprocessableEntity, "INVALID_FOLDER",
				"folder must be one of: inbox, sent, drafts, trash, bounced.",
				map[string]string{"field": "folder"})
			return
		}

		// Build a dynamic UPDATE statement for the fields that were provided.
		query, args := buildPatchSet(req, userID, msgID)
		if query == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Nothing to update.")
			return
		}

		result, err := db.Exec(r.Context(), query, args...)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not update message.")
			return
		}
		if result.RowsAffected() == 0 {
			respondError(w, http.StatusNotFound, "MESSAGE_NOT_FOUND", "No message with that ID exists in this mailbox.")
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// -------------------------------------------------------------------------
// GET /api/v1/messages/{id}/attachments/{index}
// -------------------------------------------------------------------------
// Serves a single attachment from a plaintext message by re-parsing the raw
// RFC 5322 blob. Encrypted messages are not handled here — the browser
// decrypts the blob via /raw and builds Blob URLs for attachment download.

func handleAPIGetAttachment(db *pgxpool.Pool, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")
		indexStr := r.PathValue("index")

		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Attachment index must be a non-negative integer.")
			return
		}

		var blobSHA256, securityState string
		err = db.QueryRow(r.Context(),
			`SELECT blob_sha256, security_state FROM messages WHERE id = $1 AND user_id = $2`,
			msgID, userID,
		).Scan(&blobSHA256, &securityState)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Message not found.")
			return
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch message.")
			return
		}

		// Encrypted messages: the browser decrypts and renders attachment Blob URLs.
		if securityState == "pgp_encrypted" {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Use the /raw endpoint to decrypt encrypted message attachments in the browser.")
			return
		}

		// Confirm the attachment exists in the DB before reading the blob.
		var filename, contentType string
		err = db.QueryRow(r.Context(), `
			SELECT filename, content_type FROM message_attachments
			WHERE  message_id = $1 AND part_index = $2
		`, msgID, index).Scan(&filename, &contentType)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Attachment not found.")
			return
		}
		if err != nil {
			slog.Error("attachment: fetch metadata", "msg_id", msgID, "index", index, "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch attachment metadata.")
			return
		}

		raw, err := st.ReadBlob(blobSHA256)
		if err != nil {
			slog.Error("attachment: read blob", "digest", blobSHA256, "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not read message.")
			return
		}

		part, err := smtp.ReadAttachmentAt(raw, index)
		if err != nil {
			slog.Error("attachment: extract part", "index", index, "err", err)
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Could not extract attachment from message.")
			return
		}

		safeFilename := sanitizeAttachmentFilename(part.Filename)
		if safeFilename == "" {
			safeFilename = fmt.Sprintf("attachment-%d", index)
		}

		// RFC 6266: filename= is the ASCII fallback; filename*= is the authoritative
		// RFC 5987-encoded value for non-ASCII names.
		asciiName := filenameASCIIFallback(safeFilename)
		encodedName := strings.ReplaceAll(url.QueryEscape(safeFilename), "+", "%20")
		disposition := fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, asciiName, encodedName)

		w.Header().Set("Content-Type", part.ContentType)
		w.Header().Set("Content-Disposition", disposition)
		w.Header().Set("Content-Length", strconv.Itoa(len(part.Body)))
		_, _ = w.Write(part.Body)
	}
}

// sanitizeAttachmentFilename removes path separators and control characters.
func sanitizeAttachmentFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r == '/' || r == '\\' || r < ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// filenameASCIIFallback replaces non-ASCII and special characters with '_'
// for the Content-Disposition filename= (plain ASCII) fallback.
func filenameASCIIFallback(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r > 0x7E || r < 0x20 || r == '"' || r == '/' || r == '\\' {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func buildPatchSet(req patchMessageRequest, userID, msgID string) (string, []any) {
	var setClauses []string
	var args []any
	n := 1

	if req.IsRead != nil {
		setClauses = append(setClauses, "is_read = $"+strconv.Itoa(n))
		args = append(args, *req.IsRead)
		n++
	}
	if req.IsStarred != nil {
		setClauses = append(setClauses, "is_starred = $"+strconv.Itoa(n))
		args = append(args, *req.IsStarred)
		n++
	}
	if req.Folder != nil {
		setClauses = append(setClauses, "folder = $"+strconv.Itoa(n))
		args = append(args, *req.Folder)
		n++
		if *req.Folder == "trash" {
			setClauses = append(setClauses, "deleted_at = now()")
		} else {
			setClauses = append(setClauses, "deleted_at = NULL")
		}
	}
	if len(setClauses) == 0 {
		return "", nil
	}

	query := "UPDATE messages SET "
	for i, c := range setClauses {
		if i > 0 {
			query += ", "
		}
		query += c
	}
	query += " WHERE id = $" + strconv.Itoa(n) + " AND user_id = $" + strconv.Itoa(n+1)
	args = append(args, msgID, userID)
	return query, args
}

// -------------------------------------------------------------------------
// DELETE /api/v1/messages/{id}           — soft delete (move to trash)
// DELETE /api/v1/messages/{id}?permanent=1 — hard delete from trash
// -------------------------------------------------------------------------

func handleAPIDeleteMessage(db *pgxpool.Pool, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")
		permanent := r.URL.Query().Get("permanent") == "1"

		if permanent {
			// Hard delete: only allowed from trash.
			var folder, blobSHA256 string
			err := db.QueryRow(r.Context(),
				`SELECT folder, blob_sha256 FROM messages WHERE id = $1 AND user_id = $2`,
				msgID, userID,
			).Scan(&folder, &blobSHA256)
			if errors.Is(err, pgx.ErrNoRows) {
				respondError(w, http.StatusNotFound, "MESSAGE_NOT_FOUND", "No message with that ID exists in this mailbox.")
				return
			}
			if err != nil {
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not fetch message.")
				return
			}
			if folder != "trash" {
				respondError(w, http.StatusConflict, "NOT_IN_TRASH",
					"Permanent deletion is only allowed from the trash folder.")
				return
			}

			result, err := db.Exec(r.Context(),
				`DELETE FROM messages WHERE id = $1 AND user_id = $2`, msgID, userID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not delete message.")
				return
			}
			if result.RowsAffected() == 0 {
				respondError(w, http.StatusNotFound, "MESSAGE_NOT_FOUND", "No message with that ID exists.")
				return
			}
			// Blobs are shared across recipients; only remove the file when no
			// other message row references it.
			var remaining int
			_ = db.QueryRow(r.Context(),
				`SELECT COUNT(*) FROM messages WHERE blob_sha256 = $1`, blobSHA256,
			).Scan(&remaining)
			if remaining == 0 {
				if err := st.DeleteBlob(blobSHA256); err != nil {
					slog.Error("permanent delete: blob removal failed", "msg_id", msgID, "digest", blobSHA256, "err", err)
				}
			}
		} else {
			// Soft delete: move to trash.
			result, err := db.Exec(r.Context(), `
				UPDATE messages
				SET folder = 'trash', deleted_at = now()
				WHERE id = $1 AND user_id = $2 AND folder != 'trash'
			`, msgID, userID)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not move message to trash.")
				return
			}
			if result.RowsAffected() == 0 {
				respondError(w, http.StatusNotFound, "MESSAGE_NOT_FOUND", "No message with that ID exists or it is already in trash.")
				return
			}
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

