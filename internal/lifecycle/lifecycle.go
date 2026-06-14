package lifecycle

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"rookery/internal/store"
)

func DeleteUser(ctx context.Context, db *pgxpool.Pool, st *store.Store, userID string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Blobs no other user references; deleting a shared one would corrupt
	// another mailbox.
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

	// Custom domains with no other users' addresses: they'd be orphaned, so drop
	// them too (dkim_keys cascade).
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

	tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("lifecycle.DeleteUser: user not found: %s", userID)
	}

	// Safe now that the cascade above removed the addresses that RESTRICT-blocked
	// domain deletion.
	for _, id := range exclusiveDomainIDs {
		if _, execErr := tx.Exec(ctx, `DELETE FROM domains WHERE id = $1`, id); execErr != nil {
			return fmt.Errorf("lifecycle.DeleteUser: delete domain %s: %w", id, execErr)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("lifecycle.DeleteUser: commit: %w", err)
	}

	// Blobs are removed only after commit: a failure here is logged, not returned,
	// since orphans can be swept later but a rolled-back delete can't be undone.
	for _, hash := range exclusiveBlobs {
		if delErr := st.DeleteBlob(hash); delErr != nil {
			slog.Warn("lifecycle.DeleteUser: blob removal failed", "err", delErr)
		}
	}

	return nil
}
