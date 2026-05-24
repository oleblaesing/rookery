package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Deliver delivers a single RFC 5322 message to one recipient via direct MX
// delivery. It performs MX lookup, tries each MX host in preference order, and
// uses opportunistic STARTTLS (not enforced; MTA-STS enforcement is Phase 4).
//
// fromDomain is used in the EHLO greeting.
// from is the envelope MAIL FROM address.
// to is the envelope RCPT TO address (single recipient).
// message is the complete signed RFC 5322 message bytes.
func Deliver(ctx context.Context, fromDomain, from, to string, message []byte) error {
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("outbound: invalid recipient address %q", to)
	}
	recipientDomain := parts[1]

	mxs, err := net.DefaultResolver.LookupMX(ctx, recipientDomain)
	if err != nil || len(mxs) == 0 {
		return fmt.Errorf("outbound: MX lookup for %s failed: %w", recipientDomain, err)
	}

	// Sort by preference (LookupMX returns them sorted, but be defensive).
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })

	var lastErr error
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		addr := net.JoinHostPort(host, "25")
		if err := tryDeliver(ctx, fromDomain, addr, host, from, to, message); err != nil {
			slog.Debug("outbound: MX attempt failed", "mx", host, "err", err)
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("outbound: all MX hosts for %s failed: %w", recipientDomain, lastErr)
}

// DeliverViaRelay sends a message through a configured SMTP relay instead of
// doing direct MX lookup. Used when [smtp] relay_host is set in config
// (e.g. point to mailpit on port 1025 in development).
func DeliverViaRelay(ctx context.Context, relayHost string, relayPort int, from, to string, message []byte) error {
	if relayPort <= 0 {
		relayPort = 25
	}
	addr := net.JoinHostPort(relayHost, strconv.Itoa(relayPort))
	slog.Debug("outbound: delivering via relay", "relay", addr)
	return tryDeliver(ctx, relayHost, addr, relayHost, from, to, message)
}

// tryDeliver attempts delivery to a single MX host.
func tryDeliver(ctx context.Context, fromDomain, addr, serverName, from, to string, message []byte) error {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	c, err := smtp.NewClient(conn, serverName)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Quit() //nolint:errcheck

	// EHLO.
	if err := c.Hello(fromDomain); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	// Opportunistic STARTTLS.
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			// Non-fatal: continue unencrypted. MTA-STS enforcement is Phase 4.
			slog.Debug("outbound: STARTTLS failed, continuing plaintext", "mx", serverName, "err", err)
		}
	}

	// MAIL FROM.
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}

	// RCPT TO.
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	// DATA.
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA cmd: %w", err)
	}
	if _, err := wc.Write(message); err != nil {
		wc.Close()
		return fmt.Errorf("DATA write: %w", err)
	}
	return wc.Close()
}
