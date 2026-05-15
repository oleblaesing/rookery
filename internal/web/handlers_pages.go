package web

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
	"rookery/internal/store"
)

// -------------------------------------------------------------------------
// GET /login — render the login page
// -------------------------------------------------------------------------

type loginPageData struct {
	InstanceName string
	Domain       string
	CSRFToken    string
	Error        string
	Address      string
	User         *userProfile
}

func handleLoginPage(ss *auth.SessionStore, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the user already has a valid session, send them straight to inbox.
		if rawToken, ok := auth.TokenFromRequest(r); ok {
			if _, err := ss.Get(r.Context(), rawToken); err == nil {
				http.Redirect(w, r, "/inbox", http.StatusSeeOther)
				return
			}
		}

		data := loginPageData{
			InstanceName: cfg.InstanceName,
			Domain:       cfg.Domain,
		}
		// Unauthenticated CSRF token: reuse the existing cookie if present so
		// that opening login in multiple tabs does not invalidate any of them.
		csrfToken, err := auth.EnsureUnauthCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		data.CSRFToken = csrfToken
		renderTemplate(w, "login.gohtml", data)
	}
}

// -------------------------------------------------------------------------
// GET /logout — renders a self-contained page that calls the logout API
// and redirects to /login client-side.
// -------------------------------------------------------------------------

func handleLogoutPage(ss *auth.SessionStore, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the user has a valid session, embed its stable CSRF token so the
		// logout POST will verify cleanly. Otherwise fall back to the unauth
		// cookie (the form is harmless without a session anyway).
		var csrfToken string
		if rawToken, ok := auth.TokenFromRequest(r); ok {
			if s, err := ss.Get(r.Context(), rawToken); err == nil {
				csrfToken = s.CSRFToken
			}
		}
		if csrfToken == "" {
			token, err := auth.EnsureUnauthCSRFCookie(w, r)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			csrfToken = token
		}
		next := r.URL.Query().Get("next")
		if !isSafeRedirect(next) {
			next = ""
		}
		renderTemplate(w, "logout.gohtml", struct {
			InstanceName string
			CSRFToken    string
			Next         string
			User         *userProfile
		}{
			InstanceName: cfg.InstanceName,
			CSRFToken:    csrfToken,
			Next:         next,
		})
	}
}

// -------------------------------------------------------------------------
// GET /invite/{token} — invite landing page
// POST /register — process registration form
// -------------------------------------------------------------------------

type invitePageData struct {
	InstanceName string
	Domain       string
	InviteToken  string
	CSRFToken    string
	Error        string
	User         *userProfile
}

func handleInvitePage(db *pgxpool.Pool, ss *auth.SessionStore, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the user already has a valid session, they must log out first.
		if rawToken, ok := auth.TokenFromRequest(r); ok {
			if _, err := ss.Get(r.Context(), rawToken); err == nil {
				http.Redirect(w, r, "/inbox", http.StatusSeeOther)
				return
			}
		}

		token := r.PathValue("token")

		// Validate the invite quickly (no lock — just check it's usable).
		var used bool
		err := db.QueryRow(r.Context(), `
			SELECT used_at IS NOT NULL FROM invites
			WHERE  token = $1 AND (expires_at IS NULL OR expires_at > now())
		`, token).Scan(&used)
		if errors.Is(err, pgx.ErrNoRows) || used {
			http.Error(w, "This invite link is invalid or has already been used.", http.StatusGone)
			return
		}
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		csrfToken, err := auth.EnsureUnauthCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		renderTemplate(w, "invite.gohtml", invitePageData{
			InstanceName: cfg.InstanceName,
			Domain:       cfg.Domain,
			InviteToken:  token,
			CSRFToken:    csrfToken,
		})
	}
}

// -------------------------------------------------------------------------
// GET /settings — account settings page
// -------------------------------------------------------------------------

type settingsPageData struct {
	InstanceName string
	User         *userProfile
	CSRFToken    string
}

func handleSettingsPage(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		renderTemplate(w, "settings.gohtml", settingsPageData{
			InstanceName: cfg.InstanceName,
			User:         user,
			CSRFToken:    auth.CSRFTokenFromContext(r.Context()),
		})
	}
}

// -------------------------------------------------------------------------
// GET /inbox — server-rendered inbox list
// -------------------------------------------------------------------------

type inboxPageData struct {
	InstanceName string
	User         *userProfile
	Messages     []messageListItem
	Folder       string
	CSRFToken    string
}

func handleInboxPage(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		folder := r.URL.Query().Get("folder")
		if folder == "" {
			folder = "inbox"
		}
		if !validFolders[folder] {
			folder = "inbox"
		}

		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		rows, err := db.Query(r.Context(), `
			SELECT id, thread_id, folder, from_address, to_addresses, cc_addresses,
			       subject, message_date, size_bytes, is_read, is_starred,
			       security_state, signature_status, has_attachments, received_at
			FROM   messages
			WHERE  user_id = $1 AND folder = $2
			ORDER  BY message_date DESC
			LIMIT  100
		`, userID, folder)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var msgs []messageListItem
		for rows.Next() {
			var m messageListItem
			if err := rows.Scan(
				&m.ID, &m.ThreadID, &m.Folder, &m.FromAddress, &m.To, &m.Cc,
				&m.Subject, &m.Date, &m.SizeBytes, &m.IsRead, &m.IsStarred,
				&m.SecurityState, &m.SignatureStatus, &m.HasAttachments, &m.ReceivedAt,
			); err != nil {
				continue
			}
			if m.To == nil {
				m.To = []string{}
			}
			if m.Cc == nil {
				m.Cc = []string{}
			}
			msgs = append(msgs, m)
		}

		renderTemplate(w, "inbox.gohtml", inboxPageData{
			InstanceName: cfg.InstanceName,
			User:         user,
			Messages:     msgs,
			Folder:       folder,
			CSRFToken:    auth.CSRFTokenFromContext(r.Context()),
		})
	}
}

// -------------------------------------------------------------------------
// GET /messages/{id} — read a single message
// -------------------------------------------------------------------------

type readPageData struct {
	InstanceName string
	User         *userProfile
	Message      messageListItem
	CSRFToken    string
}

func handleReadPage(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")

		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		var m messageListItem
		err = db.QueryRow(r.Context(), `
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
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if m.To == nil {
			m.To = []string{}
		}
		if m.Cc == nil {
			m.Cc = []string{}
		}

		// Mark as read.
		if !m.IsRead {
			_, _ = db.Exec(r.Context(),
				`UPDATE messages SET is_read = TRUE WHERE id = $1 AND user_id = $2`,
				msgID, userID)
			m.IsRead = true
		}

		renderTemplate(w, "read.gohtml", readPageData{
			InstanceName: cfg.InstanceName,
			User:         user,
			Message:      m,
			CSRFToken:    auth.CSRFTokenFromContext(r.Context()),
		})
	}
}

// -------------------------------------------------------------------------
// POST /messages/{id}/trash — move to trash (form POST from read page)
// -------------------------------------------------------------------------

func handleTrashPost(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")
		_, _ = db.Exec(r.Context(), `
			UPDATE messages SET folder = 'trash', deleted_at = now()
			WHERE  id = $1 AND user_id = $2
		`, msgID, userID)
		http.Redirect(w, r, "/inbox", http.StatusSeeOther)
	}
}

// -------------------------------------------------------------------------
// POST /messages/{id}/delete — permanently delete a trashed message
// -------------------------------------------------------------------------

func handleDeletePermanentPost(db *pgxpool.Pool, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")

		// Read blob digest and confirm the message is in trash before deleting.
		var blobSHA256 string
		err := db.QueryRow(r.Context(),
			`SELECT blob_sha256 FROM messages WHERE id = $1 AND user_id = $2 AND folder = 'trash'`,
			msgID, userID,
		).Scan(&blobSHA256)
		if err != nil {
			http.Error(w, "could not delete message", http.StatusBadRequest)
			return
		}

		// Delete the database row.
		_, err = db.Exec(r.Context(),
			`DELETE FROM messages WHERE id = $1 AND user_id = $2`, msgID, userID)
		if err != nil {
			http.Error(w, "could not delete message", http.StatusInternalServerError)
			return
		}

		// Remove the blob from disk; log but don't fail on error.
		if err := st.DeleteBlob(blobSHA256); err != nil {
			slog.Error("permanent delete: blob removal failed", "msg_id", msgID, "digest", blobSHA256, "err", err)
		}

		http.Redirect(w, r, "/inbox?folder=trash", http.StatusSeeOther)
	}
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func isSafeRedirect(url string) bool {
	// Only allow relative redirects (no scheme) to prevent open-redirect attacks.
	return len(url) > 0 && url[0] == '/' && (len(url) < 2 || url[1] != '/')
}

// messageDate is a time.Time alias so templates can call .Date.Format.
type messageDate = time.Time
