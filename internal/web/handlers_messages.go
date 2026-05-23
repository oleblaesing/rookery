package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
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
			if err := st.DeleteBlob(blobSHA256); err != nil {
				slog.Error("permanent delete: blob removal failed", "msg_id", msgID, "digest", blobSHA256, "err", err)
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

