// Package auth implements session management, CSRF protection, and the HTTP
// authentication middleware for rookery.
//
// Authentication model (§11.2 / ADR-0015):
//   - Login is challenge/response: the server issues a nonce, the client signs
//     it with their PGP private key, the server verifies the signature against
//     the stored public key. No passphrase or passphrase hash is held server-side.
//   - Sessions are server-side rows in Postgres; the cookie holds only a
//     random token whose SHA-256 hash is stored in the sessions table.
//   - No IP address or user-agent is stored per session (pseudonymity default).
//   - CSRF: synchronizer token pattern — a per-session token written into
//     every HTML form, verified on every state-changing request.
//   - SameSite=Lax on the session cookie provides CSRF protection for
//     top-level navigations; the synchronizer token covers form POSTs.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SHA256Hex returns the lowercase hex SHA-256 digest of data.
// Used to hash session tokens before storage.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// GenerateToken returns n random bytes encoded as lowercase hex.
func GenerateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
