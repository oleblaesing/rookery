// Package store manages the Postgres connection pool and runs database
// migrations on startup. It also provides the content-addressed blob store
// for raw RFC 5322 message files.
//
// Design constraints (from §11.6 of PLAN.md):
//   - Postgres only; no SQLite alternative.
//   - golang-migrate for migrations; SQL files embedded via embed.FS.
//   - Blobs stored content-addressed on the filesystem:
//     <message_dir>/sha256/<ab>/<cd>/<full-sha256>.eml
//   - The server master key (§11.6) encrypts DKIM private keys and ACME
//     account keys at rest; message blobs are stored as-received (PGP-
//     encrypted messages are already encrypted; plaintext messages match
//     every other mail server's storage model).
package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store holds the database pool and blob storage root.
type Store struct {
	DB         *pgxpool.Pool
	MessageDir string
}

// Open connects to Postgres, runs pending migrations, and returns a Store.
// It blocks until the connection is established or ctx is cancelled.
func Open(ctx context.Context, dbURL, messageDir string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return nil, fmt.Errorf("store: open pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	if err := runMigrations(dbURL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}

	if err := os.MkdirAll(messageDir, 0o750); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: create message_dir %s: %w", messageDir, err)
	}

	slog.Info("store: connected and migrated", "message_dir", messageDir)
	return &Store{DB: pool, MessageDir: messageDir}, nil
}

// Close releases the database pool.
func (s *Store) Close() {
	s.DB.Close()
}

// runMigrations applies any pending up-migrations from the embedded SQL files.
func runMigrations(dbURL string) error {
	srcDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("migrations source: %w", err)
	}

	// golang-migrate expects a pgx5 DSN for the pgx/v5 driver.
	// The pgx/v5 driver prefix is "pgx5".
	m, err := migrate.NewWithSourceInstance("iofs", srcDriver, "pgx5://"+dbURL[len("postgres://"):])
	if err != nil {
		return fmt.Errorf("migrate new: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}

	v, dirty, _ := m.Version()
	slog.Info("store: migrations applied", "version", v, "dirty", dirty)
	return nil
}

// BlobPath returns the filesystem path for a given sha256 hex digest.
// The path follows the content-addressed layout:
//
//	<message_dir>/sha256/<ab>/<cd>/<full-digest>.eml
func (s *Store) BlobPath(digest string) string {
	if len(digest) < 4 {
		return filepath.Join(s.MessageDir, "sha256", digest+".eml")
	}
	return filepath.Join(s.MessageDir, "sha256", digest[:2], digest[2:4], digest+".eml")
}

// WriteBlob writes data to the content-addressed blob store. It returns the
// SHA-256 hex digest of the written data. Writing the same data twice is
// idempotent — the file is only written if it does not already exist.
func (s *Store) WriteBlob(data []byte) (digest string, err error) {
	sum := sha256.Sum256(data)
	digest = hex.EncodeToString(sum[:])
	path := s.BlobPath(digest)

	if _, err := os.Stat(path); err == nil {
		return digest, nil // already exists
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("store: blob mkdir: %w", err)
	}

	// Write to a temp file then rename so partial writes are never visible.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return "", fmt.Errorf("store: blob write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("store: blob rename: %w", err)
	}
	return digest, nil
}

// ReadBlob reads the raw blob for a given SHA-256 hex digest.
func (s *Store) ReadBlob(digest string) ([]byte, error) {
	data, err := os.ReadFile(s.BlobPath(digest))
	if err != nil {
		return nil, fmt.Errorf("store: read blob %s: %w", digest, err)
	}
	return data, nil
}

// ReadBlobInto copies the raw blob for digest into w.
func (s *Store) ReadBlobInto(digest string, w io.Writer) error {
	f, err := os.Open(s.BlobPath(digest))
	if err != nil {
		return fmt.Errorf("store: open blob %s: %w", digest, err)
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// DeleteBlob removes the content-addressed blob file for digest from disk.
// It is a no-op (returns nil) if the file does not exist.
func (s *Store) DeleteBlob(digest string) error {
	err := os.Remove(s.BlobPath(digest))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("store: delete blob %s: %w", digest, err)
	}
	return nil
}
