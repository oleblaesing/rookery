// Package lifecycle contains cross-cutting operations that touch multiple
// storage layers (database + blob files) and need to be shared between the
// HTTP handlers and the operator admin subcommand.
package lifecycle

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/store"
)

// DeleteUser permanently removes a user and all data exclusively owned by
// them. The operation is:
//
//  1. Within a single DB transaction:
//     - Capture blob hashes exclusively owned by this user (no other recipient
//       shares the blob — deleting them would corrupt another user's mailbox).
//     - Identify custom domains where owner_user_id = userID AND no other user
//       has addresses on that domain.
//     - DELETE FROM users (cascades to addresses, user_keys, sessions,
//       messages, drafts, known_keys, outbound_queue via FK cascade).
//     - DELETE the exclusive domain rows (dkim_keys cascade from domains).
//
//  2. Post-commit: remove the exclusive blob files from disk. A failure here
//     is logged but does not roll back the DB deletion — orphaned files are
//     recoverable; a half-rolled-back DB delete is not.
//
// Shared blobs are left on disk (another user still references them). The
// outbound delivery worker uses FOR UPDATE SKIP LOCKED, so if a delivery row
// for this user is in-flight, the cascade DELETE will block until the worker
// releases the lock — one missed delivery is acceptable; we do not cancel
// in-flight work.
func DeleteUser(ctx context.Context, db *pgxpool.Pool, st *store.Store, userID string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// 1a. Blobs exclusively owned by this user.
	blobRows, err := tx.Query(ctx, `
		SELECT DISTINCT blob_sha256
		FROM   messages
		WHERE  user_id = $1
		  AND  NOT EXISTS (
		    SELECT 1 FROM messages m2
		    WHERE  m2.blob_sha256 = messages.blob_sha256
		      AND  m2.user_id    <> $1
		  )
	`, userID)
	if err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: query exclusive blobs: %w", err)
	}
	var exclusiveBlobs []string
	for blobRows.Next() {
		var h string
		if scanErr := blobRows.Scan(&h); scanErr != nil {
			blobRows.Close()
			return fmt.Errorf("lifecycle.DeleteUser: scan blob hash: %w", scanErr)
		}
		exclusiveBlobs = append(exclusiveBlobs, h)
	}
	blobRows.Close()

	// 1b. Custom domains exclusively owned by this user (no other users have
	//     addresses on the domain). These will lose all addresses when the user
	//     is deleted, so we remove the domain rows too (dkim_keys cascade).
	domainRows, err := tx.Query(ctx, `
		SELECT id FROM domains
		WHERE  owner_user_id = $1
		  AND  is_primary    = FALSE
		  AND  NOT EXISTS (
		    SELECT 1 FROM addresses a
		    WHERE  a.domain_id = domains.id
		      AND  a.user_id  <> $1
		  )
	`, userID)
	if err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: query exclusive domains: %w", err)
	}
	var exclusiveDomainIDs []string
	for domainRows.Next() {
		var id string
		if scanErr := domainRows.Scan(&id); scanErr != nil {
			domainRows.Close()
			return fmt.Errorf("lifecycle.DeleteUser: scan domain id: %w", scanErr)
		}
		exclusiveDomainIDs = append(exclusiveDomainIDs, id)
	}
	domainRows.Close()

	// 1c. Delete the user. ON DELETE CASCADE propagates to: addresses,
	//     user_keys, sessions, messages (and via further cascade:
	//     outbound_queue, message_attachments), drafts, known_keys.
	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("lifecycle.DeleteUser: user not found: %s", userID)
	}

	// 1d. Delete the exclusively-owned domain rows. The user's addresses are
	//     already gone (cascade from step 1c), so addresses.domain_id RESTRICT
	//     no longer blocks this. The domains.owner_user_id FK is DEFERRABLE
	//     INITIALLY DEFERRED, so the nullification fires at commit, not here;
	//     since we're deleting these rows, there is no constraint to satisfy.
	for _, id := range exclusiveDomainIDs {
		if _, execErr := tx.Exec(ctx, `DELETE FROM domains WHERE id = $1`, id); execErr != nil {
			return fmt.Errorf("lifecycle.DeleteUser: delete domain %s: %w", id, execErr)
		}
	}

	// 1e. Commit.
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: commit: %w", err)
	}

	// 2. Post-commit blob removal. Logged on failure but never returned as an
	//    error — orphaned files can be swept later; a rolled-back DB delete
	//    cannot be un-done.
	for _, hash := range exclusiveBlobs {
		if delErr := st.DeleteBlob(hash); delErr != nil {
			slog.Warn("lifecycle.DeleteUser: blob removal failed", "err", delErr)
		}
	}

	return nil
}
