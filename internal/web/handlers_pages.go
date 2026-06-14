package web

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
	"rookery/internal/domains"
	"rookery/internal/store"
)

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
		// Reuse the existing unauth cookie so login open in multiple tabs doesn't
		// invalidate any of them.
		csrfToken, err := auth.EnsureUnauthCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		data.CSRFToken = csrfToken
		renderTemplate(w, "login.gohtml", data)
	}
}

func handleLogoutPage(ss *auth.SessionStore, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prefer the session's stable CSRF token so the logout POST verifies;
		// fall back to the unauth cookie (harmless without a session).
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
		if rawToken, ok := auth.TokenFromRequest(r); ok {
			if _, err := ss.Get(r.Context(), rawToken); err == nil {
				http.Redirect(w, r, "/inbox", http.StatusSeeOther)
				return
			}
		}

		token := r.PathValue("token")

		// Cheap usability check only; the real claim happens under lock at POST.
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

type migratePageData struct {
	InstanceName string
	Domain       string
	CSRFToken    string
	ArchiveURL   string
	InviteToken  string
	User         *userProfile // nil — unauthenticated page; required by base template
}

func handleMigratePage(ss *auth.SessionStore, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Migration creates a new account, so an already-logged-in user goes to
		// their inbox instead.
		if rawToken, ok := auth.TokenFromRequest(r); ok {
			if _, err := ss.Get(r.Context(), rawToken); err == nil {
				http.Redirect(w, r, "/inbox", http.StatusSeeOther)
				return
			}
		}

		csrfToken, err := auth.EnsureUnauthCSRFCookie(w, r)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		renderTemplate(w, "migrate.gohtml", migratePageData{
			InstanceName: cfg.InstanceName,
			Domain:       cfg.Domain,
			CSRFToken:    csrfToken,
			ArchiveURL:   r.URL.Query().Get("archive"),
			InviteToken:  r.URL.Query().Get("invite"),
		})
	}
}

// Must be reachable logged-out since static/app.js loads there too.
func handleJSLicensePage(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "jslicense.gohtml", struct {
			InstanceName string
			User         *userProfile // nil — unauthenticated page; required by base template
			CSRFToken    string       // empty — base template references it; no form here
		}{
			InstanceName: cfg.InstanceName,
		})
	}
}

// Flat fields rather than embedding domains.Domain: an embedded .Domain field
// would collide with the string Name and break template resolution.
type settingsDomain struct {
	ID              string
	Name            string
	VerifiedAt      *time.Time
	PendingGroups   []recordGroup
	MTASTSMode      string
	MTASTSEnforceAt *time.Time
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

const inboxPageSize = 50

type inboxPageData struct {
	InstanceName string
	User         *userProfile
	Messages     []messageListItem
	Folder       string
	CSRFToken    string

	Query      string
	Total      int
	Page       int
	TotalPages int
	HasPrev    bool
	HasNext    bool
	PrevPage   int
	NextPage   int
}

func handleInboxPage(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		folder := r.URL.Query().Get("folder")
		if folder == "" || !validFolders[folder] {
			folder = "inbox"
		}

		query := strings.TrimSpace(r.URL.Query().Get("q"))
		page := 1
		if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
			page = p
		}

		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		// Search spans from/to/subject only, never the body. args is shared by the
		// count and page queries so the positional placeholders line up.
		where := "user_id = $1 AND folder = $2"
		args := []any{userID, folder}
		if query != "" {
			args = append(args, "%"+query+"%")
			where += fmt.Sprintf(
				" AND (from_address ILIKE $%[1]d OR subject ILIKE $%[1]d"+
					" OR array_to_string(to_addresses, ' ') ILIKE $%[1]d)",
				len(args))
		}

		var total int
		if err := db.QueryRow(r.Context(),
			"SELECT count(*) FROM messages WHERE "+where, args...).Scan(&total); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		totalPages := (total + inboxPageSize - 1) / inboxPageSize
		if totalPages < 1 {
			totalPages = 1
		}
		if page > totalPages {
			page = totalPages
		}
		offset := (page - 1) * inboxPageSize

		listSQL := fmt.Sprintf(`
			SELECT id, thread_id, folder, from_address, to_addresses, cc_addresses,
			       subject, message_date, size_bytes, is_read, is_starred,
			       security_state, signature_status, has_attachments, received_at
			FROM   messages
			WHERE  %s
			ORDER  BY message_date DESC
			LIMIT  $%d OFFSET $%d
		`, where, len(args)+1, len(args)+2)
		args = append(args, inboxPageSize, offset)

		rows, err := db.Query(r.Context(), listSQL, args...)
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
			Query:        query,
			Total:        total,
			Page:         page,
			TotalPages:   totalPages,
			HasPrev:      page > 1,
			HasNext:      page < totalPages,
			PrevPage:     page - 1,
			NextPage:     page + 1,
		})
	}
}

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
	SenderPublicKeyB64 string
	Attachments        []attachmentItem
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

		if !m.IsRead {
			_, _ = db.Exec(r.Context(),
				`UPDATE messages SET is_read = TRUE WHERE id = $1 AND user_id = $2`,
				msgID, userID)
			m.IsRead = true
		}

		// Sender key for client-side signature verification: try local users
		// first, then the per-user known_keys cache for external correspondents.
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

		// Encrypted messages have no attachment rows; the browser rebuilds the
		// list after decryption.
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

func handleDeletePermanentPost(db *pgxpool.Pool, st *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		msgID := r.PathValue("id")

		var blobSHA256 string
		err := db.QueryRow(r.Context(),
			`SELECT blob_sha256 FROM messages WHERE id = $1 AND user_id = $2 AND folder = 'trash'`,
			msgID, userID,
		).Scan(&blobSHA256)
		if err != nil {
			http.Error(w, "could not delete message", http.StatusBadRequest)
			return
		}

		_, err = db.Exec(r.Context(),
			`DELETE FROM messages WHERE id = $1 AND user_id = $2`, msgID, userID)
		if err != nil {
			http.Error(w, "could not delete message", http.StatusInternalServerError)
			return
		}

		// Blobs are shared across recipients; remove the file only when no other
		// row references it.
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

func isSafeRedirect(url string) bool {
	// Relative-only (no scheme, no //) to prevent open redirects.
	return len(url) > 0 && url[0] == '/' && (len(url) < 2 || url[1] != '/')
}

// Aliases time.Time so templates can call .Date.Format.
type messageDate = time.Time
