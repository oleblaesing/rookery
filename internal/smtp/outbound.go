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

func Deliver(ctx context.Context, cache PolicyCache, fromDomain, from, to string, message []byte) error {
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("outbound: invalid recipient address %q", to)
	}
	recipientDomain := parts[1]

	// Resolve the recipient's MTA-STS policy once; nil means none is published
	// and delivery stays opportunistic. A discovery error here is transient, so
	// don't deliver against a policy we couldn't read in enforce-capable mode —
	// fall back to opportunistic rather than fail the whole message.
	policy, err := ResolvePolicy(ctx, cache, recipientDomain)
	if err != nil {
		slog.Warn("outbound: MTA-STS policy lookup failed, proceeding opportunistically", "domain", recipientDomain, "err", err)
		policy = nil
	}

	mxs, err := net.DefaultResolver.LookupMX(ctx, recipientDomain)
	if err != nil || len(mxs) == 0 {
		return fmt.Errorf("outbound: MX lookup for %s failed: %w", recipientDomain, err)
	}

	// LookupMX sorts already, but be defensive.
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })

	var lastErr error
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		addr := net.JoinHostPort(host, "25")
		if err := tryDeliver(ctx, policy, fromDomain, addr, host, from, to, message); err != nil {
			slog.Debug("outbound: MX attempt failed", "mx", host, "err", err)
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("outbound: all MX hosts for %s failed: %w", recipientDomain, lastErr)
}

// nil means the system pool; tests set it to trust a throwaway certificate.
var smarthostRootCAs *x509.CertPool

type Smarthost struct {
	Host       string
	Port       int
	Username   string
	Password   string
	RequireTLS bool
	Auth       bool
}

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

	// On RequireTLS, a missing STARTTLS offer is a hard failure, not a fallback.
	if !implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		} else if sh.RequireTLS {
			return fmt.Errorf("smarthost %s does not offer STARTTLS but require_tls is set", sh.Host)
		}
	}

	// Guard against sending credentials or mail in the clear.
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

// Implements SMTP AUTH LOGIN, which stdlib net/smtp omits.
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

// nil means the system pool; tests set it to trust a throwaway MX certificate.
var directMXRootCAs *x509.CertPool

func tryDeliver(ctx context.Context, policy *STSPolicy, fromDomain, addr, serverName, from, to string, message []byte) error {
	enforce := policy != nil && policy.Mode == "enforce"

	// In enforce mode the MX host must be named by the policy, otherwise it must
	// not be used at all (RFC 8461 §4.1).
	if enforce && !policyAllowsMX(policy, serverName) {
		return fmt.Errorf("mta-sts: enforce mode, MX %q not authorized by policy", serverName)
	}

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

	if err := c.Hello(fromDomain); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	tlsCfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		RootCAs:    directMXRootCAs,
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(tlsCfg); err != nil {
			if enforce {
				// No plaintext fallback: a verified TLS channel is mandatory.
				return fmt.Errorf("mta-sts: enforce mode, STARTTLS to %q failed: %w", serverName, err)
			}
			slog.Warn("outbound: STARTTLS failed, continuing plaintext", "mx", serverName, "err", err)
		}
	} else if enforce {
		return fmt.Errorf("mta-sts: enforce mode, MX %q does not offer STARTTLS", serverName)
	}

	if enforce {
		if _, ok := c.TLSConnectionState(); !ok {
			return fmt.Errorf("mta-sts: enforce mode, TLS not established with %q", serverName)
		}
	}

	return sendMessage(c, from, to, message)
}

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
