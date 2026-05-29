// Package queue manages the outbound mail delivery queue.
//
// Design (§8 Phase 2, §11.4 of PLAN.md):
//   - One row per recipient per message in outbound_queue.
//   - A background Worker goroutine polls Postgres every 30 seconds.
//   - FOR UPDATE SKIP LOCKED prevents concurrent workers from double-delivering.
//   - Retry schedule: exponential backoff for up to 5 days; then bounce DSN.
//   - Hard SMTP failures (5xx) bounce immediately.
//   - Bounce DSNs are inserted into the sender's "bounced" folder.
package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/config"
	"rookery/internal/dkim"
	smtppkg "rookery/internal/smtp"
	"rookery/internal/store"
)

// retryDelays are the wait durations between delivery attempts.
// After all retries are exhausted the message is bounced.
var retryDelays = []time.Duration{
	0,                // attempt 1: immediate
	5 * time.Minute,  // attempt 2
	30 * time.Minute, // attempt 3
	2 * time.Hour,    // attempt 4
	8 * time.Hour,    // attempt 5
	24 * time.Hour,   // attempt 6
	48 * time.Hour,   // attempt 7 (total ~80h ≈ 3.3 days)
}

// maxDeliveryAge is the total time after which a still-pending message is bounced.
const maxDeliveryAge = 5 * 24 * time.Hour

// Worker polls outbound_queue and delivers pending messages.
type Worker struct {
	db   *pgxpool.Pool
	st   *store.Store
	dkim *dkim.Manager
	cfg  *config.Config
	// deliverFn is the direct-MX SMTP delivery function; replaceable for tests.
	deliverFn func(ctx context.Context, fromDomain, from, to string, msg []byte) error
	// signFn signs an outbound message; defaults to the DKIM manager's Sign,
	// replaceable for tests.
	signFn func(ctx context.Context, domain string, r io.Reader) (io.Reader, error)
	// smarthostFn delivers via the configured smarthost; defaults to
	// smtppkg.DeliverViaSmarthost, replaceable for tests.
	smarthostFn func(ctx context.Context, fromDomain string, sh smtppkg.Smarthost, from, to string, msg []byte) error
}

// NewWorker creates a Worker.
func NewWorker(db *pgxpool.Pool, st *store.Store, dk *dkim.Manager, cfg *config.Config,
	deliverFn func(ctx context.Context, fromDomain, from, to string, msg []byte) error,
) *Worker {
	return &Worker{
		db:          db,
		st:          st,
		dkim:        dk,
		cfg:         cfg,
		deliverFn:   deliverFn,
		signFn:      dk.Sign,
		smarthostFn: smtppkg.DeliverViaSmarthost,
	}
}

// Run starts the delivery loop and blocks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	slog.Info("queue: delivery worker started")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Process immediately on startup.
	w.drainQueue(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("queue: delivery worker stopped")
			return
		case <-ticker.C:
			w.drainQueue(ctx)
		}
	}
}

// drainQueue processes all due delivery rows.
func (w *Worker) drainQueue(ctx context.Context) {
	for {
		delivered, err := w.processOne(ctx)
		if err != nil {
			slog.Error("queue: processOne error", "err", err)
			return
		}
		if !delivered {
			return
		}
	}
}

// processOne claims one pending queue row and attempts delivery.
// Returns true if a row was processed (success or failure), false when no rows
// are due.
func (w *Worker) processOne(ctx context.Context) (bool, error) {
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("queue: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var queueID, messageID, recipient string
	var attempts int
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT q.id, q.message_id, q.recipient, q.attempts, q.created_at
		FROM   outbound_queue q
		WHERE  q.status IN ('pending', 'delivering')
		  AND  q.next_retry_at <= now()
		ORDER  BY q.next_retry_at
		LIMIT  1
		FOR UPDATE SKIP LOCKED
	`).Scan(&queueID, &messageID, &recipient, &attempts, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("queue: claim row: %w", err)
	}

	// Mark as 'delivering'.
	if _, err := tx.Exec(ctx,
		`UPDATE outbound_queue SET status = 'delivering' WHERE id = $1`,
		queueID,
	); err != nil {
		return false, fmt.Errorf("queue: mark delivering: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("queue: commit claim: %w", err)
	}

	// Load message metadata (sender, domain, blob digest).
	var fromAddress, blobDigest, domain string
	err = w.db.QueryRow(ctx, `
		SELECT m.from_address, m.blob_sha256,
		       COALESCE(d.domain, '')
		FROM   messages m
		LEFT JOIN users u ON u.id = m.user_id
		LEFT JOIN addresses a ON a.id = u.primary_address_id
		LEFT JOIN domains d ON d.domain = split_part(a.address, '@', 2)
		WHERE  m.id = $1
	`, messageID).Scan(&fromAddress, &blobDigest, &domain)
	if err != nil {
		w.markFailed(ctx, queueID, messageID, "internal: could not load message")
		return true, nil
	}

	// Read the raw blob.
	rawMsg, err := w.st.ReadBlob(blobDigest)
	if err != nil {
		w.markFailed(ctx, queueID, messageID, "internal: could not read message blob")
		return true, nil
	}

	// Determine the recipient's domain for routing.
	recipientDomain := ""
	if idx := strings.LastIndex(recipient, "@"); idx >= 0 {
		recipientDomain = recipient[idx+1:]
	}

	var deliveryErr error

	if recipientDomain == w.cfg.Domain {
		// Local delivery: write directly to the recipient's inbox in Postgres.
		// No SMTP round-trip needed — the message stays on this server.
		deliveryErr = smtppkg.DeliverLocal(ctx, w.db, w.st, w.cfg, fromAddress, recipient, rawMsg)
		if deliveryErr == nil {
			w.markDelivered(ctx, queueID)
			slog.Info("queue: locally delivered", "queue_id", queueID)
			return true, nil
		}
	} else {
		// External delivery: DKIM-sign then send via smarthost or direct MX.
		var internalErr error
		deliveryErr, internalErr = w.deliverExternal(ctx, domain, fromAddress, recipient, rawMsg)
		if internalErr != nil {
			w.markFailed(ctx, queueID, messageID, "internal: could not buffer signed message")
			return true, nil
		}

		if deliveryErr == nil {
			w.markDelivered(ctx, queueID)
			slog.Info("queue: delivered", "queue_id", queueID, "attempts", attempts+1)
			return true, nil
		}
	}

	slog.Warn("queue: delivery failed", "queue_id", queueID, "attempt", attempts+1, "err", deliveryErr)

	// ErrNoSuchUser is a hard failure — bounce immediately.
	isHard := errors.Is(deliveryErr, smtppkg.ErrNoSuchUser) || isHardFailure(deliveryErr)
	exceeded := time.Since(createdAt) >= maxDeliveryAge || attempts >= len(retryDelays)-1

	if isHard || exceeded {
		w.markBounced(ctx, queueID, messageID, fromAddress, recipient, deliveryErr.Error())
		return true, nil
	}

	nextDelay := retryDelays[attempts+1]
	w.markRetry(ctx, queueID, attempts+1, nextDelay, deliveryErr.Error())
	return true, nil
}

// deliverExternal DKIM-signs rawMsg and hands it off to the smarthost (when
// [smtp.smarthost] is enabled) or to direct MX delivery. Signing always happens
// before the branch, so the sign-then-handoff invariant (ADR-0030) holds for
// both paths. deliveryErr is the result of the delivery attempt; a non-nil
// internalErr means the signed message could not be prepared and the row should
// be failed rather than retried. This method touches no database state so it is
// unit-testable in isolation.
func (w *Worker) deliverExternal(ctx context.Context, domain, from, to string, rawMsg []byte) (deliveryErr, internalErr error) {
	signedReader, err := w.signFn(ctx, domain, bytes.NewReader(rawMsg))
	if err != nil {
		slog.Warn("queue: DKIM signing failed, delivering unsigned", "domain", domain, "err", err)
		signedReader = bytes.NewReader(rawMsg)
	}
	signedBytes := new(bytes.Buffer)
	if _, err := signedBytes.ReadFrom(signedReader); err != nil {
		return nil, fmt.Errorf("buffer signed message: %w", err)
	}

	if w.cfg.SMTP.Smarthost.Enabled {
		sh := w.cfg.SMTP.Smarthost
		return w.smarthostFn(ctx, domain, smtppkg.Smarthost{
			Host:       sh.Host,
			Port:       sh.Port,
			Username:   sh.Username,
			Password:   w.cfg.Secrets.SMTPRelayPassword,
			RequireTLS: sh.RequireTLS,
			Auth:       sh.Auth,
		}, from, to, signedBytes.Bytes()), nil
	}
	return w.deliverFn(ctx, domain, from, to, signedBytes.Bytes()), nil
}

func (w *Worker) markDelivered(ctx context.Context, queueID string) {
	_, _ = w.db.Exec(ctx, `
		UPDATE outbound_queue
		SET    status = 'delivered', delivered_at = now()
		WHERE  id = $1
	`, queueID)
}

func (w *Worker) markRetry(ctx context.Context, queueID string, attempts int, delay time.Duration, lastErr string) {
	_, _ = w.db.Exec(ctx, `
		UPDATE outbound_queue
		SET    status = 'pending', attempts = $2,
		       next_retry_at = now() + $3::interval,
		       last_error = $4
		WHERE  id = $1
	`, queueID, attempts, delay.String(), truncateErr(lastErr))
}

func (w *Worker) markFailed(ctx context.Context, queueID, messageID, reason string) {
	_, _ = w.db.Exec(ctx, `
		UPDATE outbound_queue SET status = 'failed', last_error = $2 WHERE id = $1
	`, queueID, reason)
}

func (w *Worker) markBounced(ctx context.Context, queueID, messageID, from, to, reason string) {
	_, _ = w.db.Exec(ctx, `
		UPDATE outbound_queue SET status = 'bounced', last_error = $2 WHERE id = $1
	`, queueID, truncateErr(reason))

	// Insert a DSN bounce notification into the sender's bounced folder.
	bounceDSN := buildBouceDSN(from, to, reason)
	digest, err := w.st.WriteBlob([]byte(bounceDSN))
	if err != nil {
		slog.Error("queue: could not write bounce DSN blob", "err", err)
		return
	}

	_, err = w.db.Exec(ctx, `
		INSERT INTO messages
		  (user_id, folder, from_address, to_addresses, subject,
		   message_date, size_bytes, blob_sha256, security_state, signature_status)
		SELECT u.id, 'bounced',
		       'postmaster@' || d.domain,
		       ARRAY[$2::text],
		       'Delivery failure: ' || $3,
		       now(), $4, $5, 'plaintext', 'none'
		FROM   messages m
		JOIN   users u ON u.id = m.user_id
		JOIN   addresses a ON a.id = u.primary_address_id
		JOIN   domains d ON d.domain = split_part(a.address, '@', 2)
		WHERE  m.id = $1
	`, messageID, to, to, int64(len(bounceDSN)), digest)
	if err != nil {
		slog.Error("queue: could not insert bounce DSN message", "err", err)
	}
}

// isHardFailure returns true for permanent SMTP failures (5xx codes).
func isHardFailure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// emersion/go-smtp surfaces errors as "*smtp.SMTPError" but we check the
	// string representation to stay decoupled.
	return strings.Contains(s, "5") && (strings.Contains(s, "550") ||
		strings.Contains(s, "551") || strings.Contains(s, "552") ||
		strings.Contains(s, "553") || strings.Contains(s, "554") ||
		strings.Contains(s, "5.") || strings.HasPrefix(s, "5"))
}

// buildBouceDSN returns a minimal RFC 5322 DSN message for a failed delivery.
func buildBouceDSN(from, to, reason string) string {
	return fmt.Sprintf("From: Mail Delivery System <mailer-daemon@localhost>\r\n"+
		"To: %s\r\n"+
		"Subject: Delivery failure: message to %s\r\n"+
		"Date: %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"\r\n"+
		"Your message to %s could not be delivered.\r\n\r\nReason: %s\r\n",
		from, to,
		time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700"),
		to, reason)
}

func truncateErr(s string) string {
	if len(s) > 500 {
		return s[:500]
	}
	return s
}
