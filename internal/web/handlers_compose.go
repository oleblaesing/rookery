package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/auth"
	"rookery/internal/config"
	"rookery/internal/discovery"
	"rookery/internal/dkim"
	"rookery/internal/smtp"
	"rookery/internal/store"
)

type composePageData struct {
	InstanceName       string
	User               *userProfile
	CSRFToken          string
	FromAddress        string
	SenderPublicKeyB64 string

	ReplyToHeader string
	ReplyToID     string
	References    string
	ToAddress     string
	Subject       string
}

func handleComposePage(db *pgxpool.Pool, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		user, err := fetchUserByID(r.Context(), db, userID)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		var fromAddress, armoredPublicKey string
		if err := db.QueryRow(r.Context(), `
			SELECT a.address, COALESCE(k.armored_public_key, '')
			FROM   users u
			JOIN   addresses a ON a.id = u.primary_address_id
			LEFT JOIN user_keys k ON k.user_id = u.id AND k.is_active = TRUE
			WHERE  u.id = $1
			ORDER  BY k.created_at DESC
			LIMIT  1
		`, userID).Scan(&fromAddress, &armoredPublicKey); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		data := composePageData{
			InstanceName:       cfg.InstanceName,
			User:               user,
			CSRFToken:          auth.CSRFTokenFromContext(r.Context()),
			FromAddress:        fromAddress,
			SenderPublicKeyB64: base64.StdEncoding.EncodeToString([]byte(armoredPublicKey)),
		}

		if replyID := r.URL.Query().Get("reply_to"); replyID != "" {
			var origFrom, origSubject, origMsgIDHeader string
			err := db.QueryRow(r.Context(), `
				SELECT from_address, subject, COALESCE(message_id_header, '')
				FROM   messages
				WHERE  id = $1 AND user_id = $2
			`, replyID, userID).Scan(&origFrom, &origSubject, &origMsgIDHeader)
			if err == nil {
				data.ReplyToHeader = origMsgIDHeader
				data.ReplyToID = replyID
				data.ToAddress = origFrom
				data.Subject = replySubject(origSubject)
				data.References = origMsgIDHeader
			}
		}

		renderTemplate(w, "compose.gohtml", data)
	}
}

func replySubject(s string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "re:") {
		return s
	}
	return "Re: " + s
}

// The armored key rides along base64-encoded in a data attribute so compose.js
// can encrypt without a second fetch.
func handleKeyStatusFragment(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		address := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("address")))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		if address == "" || !strings.Contains(address, "@") {
			fmt.Fprint(w, `<span class="key-status empty"></span>`)
			return
		}

		result, err := discovery.Discover(r.Context(), db, userID, address)
		if err != nil {
			slog.Warn("key-status: discovery error", "address", address, "err", err)
		}

		if result == nil {
			fmt.Fprintf(w, `<span class="key-status not-found" data-address="%s">⚠ no key — plaintext</span>`,
				template.HTMLEscapeString(address))
			return
		}

		fpPreview := result.Fingerprint
		if len(fpPreview) > 16 {
			fpPreview = fpPreview[:8] + "…" + fpPreview[len(fpPreview)-8:]
		}

		firstSeenNote := ""
		switch {
		case result.RotatedFrom != "":
			firstSeenNote = ` (rotated from a previously-trusted key ✓)`
		case result.Source == "known_keys" && result.FirstSeenAt != nil:
			firstSeenNote = fmt.Sprintf(` (first seen %s)`, result.FirstSeenAt.Format("2006-01-02"))
		}

		encodedKey := base64.StdEncoding.EncodeToString([]byte(result.ArmoredPublicKey))
		fmt.Fprintf(w,
			`<span class="key-status found" data-address="%s" data-fingerprint="%s" data-key-b64="%s">🔒 %s%s</span>`,
			template.HTMLEscapeString(address),
			template.HTMLEscapeString(result.Fingerprint),
			template.HTMLEscapeString(encodedKey),
			template.HTMLEscapeString(fpPreview),
			firstSeenNote,
		)
	}
}

type sendMessageRequest struct {
	// Already PGP/MIME-encrypted by the browser; the server DKIM-signs it at delivery time.
	Message string   `json:"message"`
	BCC     []string `json:"bcc"`
}

func handleAPISendMessage(db *pgxpool.Pool, st *store.Store, dk *dkim.Manager, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())

		var req sendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON body.")
			return
		}
		if req.Message == "" {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "message field is required.")
			return
		}

		rawMsg, err := base64.StdEncoding.DecodeString(req.Message)
		if err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "message must be standard base64-encoded.")
			return
		}
		if int64(len(rawMsg)) > cfg.SMTP.MaxMessageBytes {
			respondError(w, http.StatusRequestEntityTooLarge, "MESSAGE_TOO_LARGE",
				fmt.Sprintf("Message exceeds the %d byte limit.", cfg.SMTP.MaxMessageBytes))
			return
		}

		var fromAddress, domainName string
		if err := db.QueryRow(r.Context(), `
			SELECT a.address, d.domain
			FROM   users u
			JOIN   addresses a ON a.id = u.primary_address_id
			JOIN   domains d ON d.id = a.domain_id
			WHERE  u.id = $1
		`, userID).Scan(&fromAddress, &domainName); err != nil {
			slog.Error("send: load sender", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not load sender.")
			return
		}

		meta := smtp.ParseMeta(rawMsg)

		if err := checkRateLimits(r.Context(), db, userID, cfg); err != nil {
			respondError(w, http.StatusTooManyRequests, "RATE_LIMITED", err.Error())
			return
		}

		allRecipients := append([]string{}, meta.To...)
		allRecipients = append(allRecipients, meta.Cc...)
		for _, b := range req.BCC {
			b = strings.ToLower(strings.TrimSpace(b))
			if b != "" {
				allRecipients = append(allRecipients, b)
			}
		}
		if len(allRecipients) == 0 {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "No recipients.")
			return
		}

		var threadID *string
		if inReplyTo := extractHeader(rawMsg, "In-Reply-To"); inReplyTo != "" {
			var tid string
			if err := db.QueryRow(r.Context(), `
				SELECT COALESCE(thread_id::text, id::text)
				FROM   messages
				WHERE  message_id_header = $1 AND user_id = $2
				LIMIT  1
			`, inReplyTo, userID).Scan(&tid); err == nil {
				threadID = &tid
			}
		}

		msgIDHeader := extractHeader(rawMsg, "Message-ID")

		// Stored unsigned; DKIM signing happens at delivery.
		blobDigest, err := st.WriteBlob(rawMsg)
		if err != nil {
			slog.Error("send: write blob", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not store message.")
			return
		}

		var messageID string
		err = db.QueryRow(r.Context(), `
			INSERT INTO messages
			  (user_id, thread_id, folder, from_address, to_addresses, cc_addresses,
			   subject, message_date, size_bytes, blob_sha256,
			   security_state, signature_status, has_attachments,
			   message_id_header, is_read)
			VALUES ($1, $2::uuid, 'sent', $3, $4, $5,
			        $6, $7, $8, $9,
			        $10, $11, $12, $13, TRUE)
			RETURNING id
		`,
			userID, threadID, fromAddress, meta.To, meta.Cc,
			meta.Subject, meta.MessageDate, int64(len(rawMsg)), blobDigest,
			meta.SecurityState, meta.SignatureStatus, meta.HasAttachments,
			nullableStr(msgIDHeader),
		).Scan(&messageID)
		if err != nil {
			slog.Error("send: insert message", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not save message.")
			return
		}

		// nil for encrypted messages (browser lists those), so this is a no-op then.
		for _, a := range meta.Attachments {
			_, _ = db.Exec(r.Context(), `
				INSERT INTO message_attachments (message_id, part_index, filename, content_type, size_bytes)
				VALUES ($1, $2, $3, $4, $5)
			`, messageID, a.PartIndex, a.Filename, a.ContentType, a.SizeBytes)
		}

		for _, rcpt := range allRecipients {
			rcpt = strings.ToLower(strings.TrimSpace(rcpt))
			if rcpt == "" {
				continue
			}
			if _, err := db.Exec(r.Context(), `
				INSERT INTO outbound_queue (message_id, recipient)
				VALUES ($1, $2)
			`, messageID, rcpt); err != nil {
				slog.Error("send: queue delivery", "to", rcpt, "err", err)
			}
		}

		slog.Info("send: message queued", "recipients", len(allRecipients))

		respondJSON(w, http.StatusCreated, map[string]string{"id": messageID})
	}
}

type draftRequest struct {
	FromAddress   string   `json:"from_address"`
	ToAddresses   []string `json:"to"`
	CCAddresses   []string `json:"cc"`
	BCCAddresses  []string `json:"bcc"`
	Subject       string   `json:"subject"`
	BodyText      string   `json:"body_text"`
	InReplyTo     string   `json:"in_reply_to"`
	ReferencesHdr string   `json:"references"`
}

type draftResponse struct {
	ID            string    `json:"id"`
	FromAddress   string    `json:"from_address"`
	ToAddresses   []string  `json:"to"`
	CCAddresses   []string  `json:"cc"`
	BCCAddresses  []string  `json:"bcc"`
	Subject       string    `json:"subject"`
	BodyText      string    `json:"body_text"`
	InReplyTo     string    `json:"in_reply_to"`
	ReferencesHdr string    `json:"references"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func handleAPICreateDraft(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		var req draftRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON.")
			return
		}

		var d draftResponse
		err := db.QueryRow(r.Context(), `
			INSERT INTO drafts
			  (user_id, from_address, to_addresses, cc_addresses, bcc_addresses,
			   subject, body_text, in_reply_to, references_hdr)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING id, from_address, to_addresses, cc_addresses, bcc_addresses,
			          subject, body_text,
			          COALESCE(in_reply_to, ''), COALESCE(references_hdr, ''),
			          created_at, updated_at
		`, userID, req.FromAddress, normSlice(req.ToAddresses), normSlice(req.CCAddresses),
			normSlice(req.BCCAddresses), req.Subject, req.BodyText,
			nullableStr(req.InReplyTo), nullableStr(req.ReferencesHdr),
		).Scan(&d.ID, &d.FromAddress, &d.ToAddresses, &d.CCAddresses, &d.BCCAddresses,
			&d.Subject, &d.BodyText, &d.InReplyTo, &d.ReferencesHdr,
			&d.CreatedAt, &d.UpdatedAt)
		if err != nil {
			slog.Error("draft: create", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not create draft.")
			return
		}
		respondJSON(w, http.StatusCreated, d)
	}
}

func handleAPIGetDraftByID(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		draftID := r.PathValue("id")

		var d draftResponse
		err := db.QueryRow(r.Context(), `
			SELECT id, from_address, to_addresses, cc_addresses, bcc_addresses,
			       subject, body_text,
			       COALESCE(in_reply_to, ''), COALESCE(references_hdr, ''),
			       created_at, updated_at
			FROM   drafts
			WHERE  id = $1 AND user_id = $2
		`, draftID, userID).Scan(
			&d.ID, &d.FromAddress, &d.ToAddresses, &d.CCAddresses, &d.BCCAddresses,
			&d.Subject, &d.BodyText, &d.InReplyTo, &d.ReferencesHdr,
			&d.CreatedAt, &d.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Draft not found.")
			return
		}
		if err != nil {
			slog.Error("draft: get", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not load draft.")
			return
		}
		respondJSON(w, http.StatusOK, d)
	}
}

func handleAPIUpdateDraft(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		draftID := r.PathValue("id")

		var req draftRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON.")
			return
		}

		var d draftResponse
		err := db.QueryRow(r.Context(), `
			UPDATE drafts
			SET    from_address = $3, to_addresses = $4, cc_addresses = $5,
			       bcc_addresses = $6, subject = $7, body_text = $8,
			       in_reply_to = $9, references_hdr = $10, updated_at = now()
			WHERE  id = $1 AND user_id = $2
			RETURNING id, from_address, to_addresses, cc_addresses, bcc_addresses,
			          subject, body_text,
			          COALESCE(in_reply_to, ''), COALESCE(references_hdr, ''),
			          created_at, updated_at
		`, draftID, userID, req.FromAddress, normSlice(req.ToAddresses),
			normSlice(req.CCAddresses), normSlice(req.BCCAddresses),
			req.Subject, req.BodyText,
			nullableStr(req.InReplyTo), nullableStr(req.ReferencesHdr),
		).Scan(&d.ID, &d.FromAddress, &d.ToAddresses, &d.CCAddresses, &d.BCCAddresses,
			&d.Subject, &d.BodyText, &d.InReplyTo, &d.ReferencesHdr,
			&d.CreatedAt, &d.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Draft not found.")
			return
		}
		if err != nil {
			slog.Error("draft: update", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not update draft.")
			return
		}
		respondJSON(w, http.StatusOK, d)
	}
}

func handleAPIDeleteDraftByID(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := auth.UserIDFromContext(r.Context())
		draftID := r.PathValue("id")

		result, err := db.Exec(r.Context(),
			`DELETE FROM drafts WHERE id = $1 AND user_id = $2`, draftID, userID)
		if err != nil {
			slog.Error("draft: delete", "err", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL", "Could not delete draft.")
			return
		}
		if result.RowsAffected() == 0 {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "Draft not found.")
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func checkRateLimits(ctx context.Context, db *pgxpool.Pool, userID string, cfg *config.Config) error {
	if cfg.SMTP.OutboundRateLimitPerUser == 0 && cfg.SMTP.OutboundDailyLimitPerUser == 0 {
		return nil
	}
	var hourCount, dayCount int
	err := db.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE q.created_at >= now() - interval '1 hour'),
		  count(*) FILTER (WHERE q.created_at >= now() - interval '1 day')
		FROM outbound_queue q
		JOIN messages m ON m.id = q.message_id
		WHERE m.user_id = $1
		  AND q.created_at >= now() - interval '1 day'
	`, userID).Scan(&hourCount, &dayCount)
	if err != nil {
		return nil // non-fatal: allow the send if the rate check itself fails
	}
	if cfg.SMTP.OutboundRateLimitPerUser > 0 && hourCount >= cfg.SMTP.OutboundRateLimitPerUser {
		return fmt.Errorf("hourly outbound limit reached (%d messages/hour)", cfg.SMTP.OutboundRateLimitPerUser)
	}
	if cfg.SMTP.OutboundDailyLimitPerUser > 0 && dayCount >= cfg.SMTP.OutboundDailyLimitPerUser {
		return fmt.Errorf("daily outbound limit reached (%d messages/day)", cfg.SMTP.OutboundDailyLimitPerUser)
	}
	return nil
}

func extractHeader(raw []byte, name string) string {
	nameLower := strings.ToLower(name) + ":"
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(trimmed), nameLower) {
			val := strings.TrimSpace(trimmed[len(nameLower):])
			// Unfold continuation lines.
			for i+1 < len(lines) {
				next := lines[i+1]
				if len(next) == 0 || (next[0] != ' ' && next[0] != '\t') {
					break
				}
				val += " " + strings.TrimSpace(strings.TrimRight(next, "\r"))
				i++
			}
			return val
		}
	}
	return ""
}

func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func normSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
