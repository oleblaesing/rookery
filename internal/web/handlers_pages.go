package web

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
	"rookery/internal/domains"
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
	Deleted      bool
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
			Deleted:      r.URL.Query().Get("deleted") == "1",
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

// settingsDomain holds the fields the settings template needs for one
// domain row, plus the pre-grouped pending-records table. PendingGroups is
// nil for verified domains. Flat fields (not an embedded domains.Domain)
// because embedding promotes a .Domain field that collides with the string
// field of the same name and breaks template resolution.
type settingsDomain struct {
	ID              string
	Name            string
	VerifiedAt      *time.Time
	PendingGroups   []recordGroup
	MTASTSMode      string     // effective: "testing", "enforce", "disabled", "" when unverified
	MTASTSEnforceAt *time.Time // non-nil only while auto-testing with time remaining
}

type settingsPageData struct {
	InstanceName  string
	User          *userProfile
	CSRFToken     string
	Domains       []settingsDomain
	PrimaryDomain string
	UnreadLast24h int
}

func handleSettingsPage(db *pgxpool.Pool, cfg *config.Config, domMgr *domains.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		domList, err := domMgr.ListForUser(r.Context(), userID)
		if err != nil {
			slog.Error("settings: list domains", "err", err)
			domList = nil
		}
		primary := cfg.Domain
		settingsDomains := make([]settingsDomain, 0, len(domList))
		for i := range domList {
			sd := settingsDomain{
				ID:         domList[i].ID,
				Name:       domList[i].Domain,
				VerifiedAt: domList[i].VerifiedAt,
			}
			if domList[i].VerifiedAt != nil {
				sd.MTASTSMode = domMgr.EffectiveMTASTSMode(&domList[i])
				// Show the auto-enforce time only while the domain is still in the 48h window.
				if domList[i].MTASTSMode == nil && domList[i].MTASTSModeChangedAt != nil {
					enforceAt := domList[i].MTASTSModeChangedAt.Add(48 * time.Hour)
					if enforceAt.After(time.Now()) {
						sd.MTASTSEnforceAt = &enforceAt
					}
				}
			}
			sd.PendingGroups = groupRecords(requiredRecords(&domList[i], primary))
			settingsDomains = append(settingsDomains, sd)
		}
		var unread int
		_ = db.QueryRow(r.Context(), `
			SELECT count(*)
			FROM   messages
			WHERE  user_id     = $1
			  AND  is_read     = FALSE
			  AND  received_at > now() - interval '24 hours'
		`, userID).Scan(&unread)

		renderTemplate(w, "settings.gohtml", settingsPageData{
			InstanceName:  cfg.InstanceName,
			User:          user,
			CSRFToken:     auth.CSRFTokenFromContext(r.Context()),
			Domains:       settingsDomains,
			PrimaryDomain: primary,
			UnreadLast24h: unread,
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

// attachmentItem is a single attachment entry for the read page template.
type attachmentItem struct {
	PartIndex   int
	Filename    string
	ContentType string
	SizeBytes   int64
}

type readPageData struct {
	InstanceName       string
	User               *userProfile
	Message            messageListItem
	CSRFToken          string
	SenderPublicKeyB64 string          // base64-encoded armored public key for signature verification
	Attachments        []attachmentItem // populated for plaintext messages only
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

		// Look up the sender's public key for client-side signature verification.
		// First try local users; fall back to the per-user known_keys cache for
		// external correspondents (e.g. keys fetched via WKD when sending to them).
		var senderKeyB64 string
		if m.FromAddress != "" {
			var armoredKey string
			err := db.QueryRow(r.Context(), `
				SELECT COALESCE(k.armored_public_key, '')
				FROM   addresses a
				JOIN   users u ON u.id = a.user_id
				JOIN   user_keys k ON k.user_id = u.id AND k.is_active = TRUE
				WHERE  a.address = $1
				LIMIT  1
			`, m.FromAddress).Scan(&armoredKey)
			if err != nil || armoredKey == "" {
				err = db.QueryRow(r.Context(), `
					SELECT armored_public_key
					FROM   known_keys
					WHERE  user_id = $1 AND address = $2
					LIMIT  1
				`, userID, m.FromAddress).Scan(&armoredKey)
			}
			if err == nil && armoredKey != "" {
				senderKeyB64 = base64.StdEncoding.EncodeToString([]byte(armoredKey))
			}
		}

		// Fetch attachment metadata for plaintext messages so the template can
		// render server-side download links. Encrypted messages have no rows —
		// the browser reconstructs the list after PGP decryption.
		var attachments []attachmentItem
		if m.HasAttachments && m.SecurityState != "pgp_encrypted" {
			aRows, aErr := db.Query(r.Context(), `
				SELECT part_index, filename, content_type, size_bytes
				FROM   message_attachments
				WHERE  message_id = $1
				ORDER  BY part_index
			`, msgID)
			if aErr == nil {
				for aRows.Next() {
					var a attachmentItem
					if err := aRows.Scan(&a.PartIndex, &a.Filename, &a.ContentType, &a.SizeBytes); err == nil {
						attachments = append(attachments, a)
					}
				}
				aRows.Close()
			}
		}

		renderTemplate(w, "read.gohtml", readPageData{
			InstanceName:       cfg.InstanceName,
			User:               user,
			Message:            m,
			CSRFToken:          auth.CSRFTokenFromContext(r.Context()),
			SenderPublicKeyB64: senderKeyB64,
			Attachments:        attachments,
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
