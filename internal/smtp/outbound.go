package smtp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

// smarthostRootCAs overrides the trusted roots for the smarthost TLS handshake.
// nil (the production value) means the system root pool. Tests set it to trust a
// throwaway server certificate.
var smarthostRootCAs *x509.CertPool

// Smarthost carries the resolved [smtp.smarthost] settings for one delivery.
// See config.SmarthostConfig and ADR-0030.
type Smarthost struct {
	Host       string
	Port       int
	Username   string
	Password   string
	RequireTLS bool
	Auth       bool
}

// DeliverViaSmarthost sends a message through the configured smarthost — a
// trusted upstream SMTP submission endpoint (commercial relay, relay rookery,
// or dev mailpit) — instead of doing direct MX lookup. The message has already
// been DKIM-signed by the caller; the smarthost is opaque transport (ADR-0030).
//
// Unlike MX delivery, TLS is enforced when sh.RequireTLS: a smarthost session
// carries AUTH credentials, so if TLS cannot be established the attempt fails
// rather than falling back to plaintext.
//
// Port 465 uses implicit TLS; any other port (587 by default) dials plaintext
// and upgrades via STARTTLS.
func DeliverViaSmarthost(ctx context.Context, fromDomain string, sh Smarthost, from, to string, message []byte) error {
	port := sh.Port
	if port <= 0 {
		port = 587
	}
	addr := net.JoinHostPort(sh.Host, strconv.Itoa(port))
	slog.Debug("outbound: delivering via smarthost", "smarthost", addr, "require_tls", sh.RequireTLS, "auth", sh.Auth)

	tlsCfg := &tls.Config{ServerName: sh.Host, MinVersion: tls.VersionTLS12, RootCAs: smarthostRootCAs}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	implicitTLS := port == 465

	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial smarthost %s: %w", addr, err)
	}

	c, err := smtp.NewClient(conn, sh.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Quit() //nolint:errcheck

	if err := c.Hello(fromDomain); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	// STARTTLS for non-implicit-TLS ports. Mandatory when RequireTLS: a missing
	// STARTTLS offer is a hard failure, never a plaintext fallback.
	if !implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		} else if sh.RequireTLS {
			return fmt.Errorf("smarthost %s does not offer STARTTLS but require_tls is set", sh.Host)
		}
	}

	// Never send credentials or mail in the clear when TLS is required.
	if sh.RequireTLS {
		if _, ok := c.TLSConnectionState(); !ok {
			return fmt.Errorf("smarthost %s: TLS required but not established", sh.Host)
		}
	}

	if sh.Auth {
		auth, err := smarthostAuth(c, sh.Host, sh.Username, sh.Password)
		if err != nil {
			return err
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("AUTH: %w", err)
		}
	}

	return sendMessage(c, from, to, message)
}

// smarthostAuth picks an AUTH mechanism the server advertises, preferring PLAIN
// and falling back to the widely-supported (non-standard) LOGIN.
func smarthostAuth(c *smtp.Client, host, username, password string) (smtp.Auth, error) {
	ok, mechs := c.Extension("AUTH")
	if !ok {
		return nil, fmt.Errorf("smarthost %s does not offer AUTH", host)
	}
	switch {
	case strings.Contains(mechs, "PLAIN"):
		return smtp.PlainAuth("", username, password, host), nil
	case strings.Contains(mechs, "LOGIN"):
		return &loginAuth{username: username, password: password}, nil
	default:
		return nil, fmt.Errorf("smarthost %s offers no supported AUTH mechanism (advertised: %q)", host, mechs)
	}
}

// loginAuth implements the non-standard but widely deployed SMTP AUTH LOGIN
// mechanism. stdlib net/smtp ships only PLAIN and CRAM-MD5. Like PlainAuth, it
// refuses to transmit credentials over an unencrypted connection.
type loginAuth struct {
	username, password string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("loginAuth: refusing to send credentials over unencrypted connection")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:":
		return []byte(a.username), nil
	case "password:":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("loginAuth: unexpected server challenge %q", fromServer)
	}
}

// tryDeliver attempts delivery to a single MX host with opportunistic STARTTLS.
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

	return sendMessage(c, from, to, message)
}

// sendMessage runs the MAIL FROM / RCPT TO / DATA exchange on an established
// (and, where applicable, authenticated) SMTP client. Shared by direct MX
// delivery and smarthost delivery.
func sendMessage(c *smtp.Client, from, to string, message []byte) error {
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
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
