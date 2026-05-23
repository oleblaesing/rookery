package domains

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math"
	"time"
)

const certExpiryWarnDays = 14

// CheckCertExpiry dials mta-sts.<domain>:443 for each verified custom domain
// and logs a WARN if the leaf certificate expires within certExpiryWarnDays.
// Called by the daily background worker.
func (m *Manager) CheckCertExpiry(ctx context.Context) error {
	rows, err := m.db.Query(ctx, `
		SELECT domain FROM domains
		WHERE is_primary = FALSE AND verified_at IS NOT NULL
	`)
	if err != nil {
		return fmt.Errorf("certcheck: query domains: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, name := range names {
		host := "mta-sts." + name + ":443"
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		rawConn, err := (&tls.Dialer{
			Config: &tls.Config{InsecureSkipVerify: false}, //nolint:gosec // we want the real cert
		}).DialContext(dialCtx, "tcp", host)
		cancel()
		if err != nil {
			slog.Debug("certcheck: dial failed (cert not yet issued or domain unreachable)",
				"event_key", "mta_sts_cert_check_failed",
				"domain", name, "err", err)
			continue
		}
		tlsConn := rawConn.(*tls.Conn)
		certs := tlsConn.ConnectionState().PeerCertificates
		tlsConn.Close()
		if len(certs) == 0 {
			continue
		}
		leaf := certs[0]
		daysLeft := int(math.Floor(time.Until(leaf.NotAfter).Hours() / 24))
		if daysLeft <= certExpiryWarnDays {
			slog.Warn("MTA-STS cert expiry approaching",
				"event_key", "mta_sts_cert_expiry_warning",
				"domain", name,
				"expires_at", leaf.NotAfter,
				"days_remaining", daysLeft,
			)
		}
	}
	return nil
}
