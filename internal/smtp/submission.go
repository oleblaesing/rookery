// Submission listener — the relay-rookery ingress (ADR-0030 §3, Phase B).
//
// This is rookery's only *authenticated* SMTP listener, distinct from the
// inbound MX listener on port 25 (which never offers AUTH). It accepts mail from
// whitelisted downstream operators (rows in relay_clients) over an authenticated
// TLS session and relays it to the internet on their behalf, absorbing the
// IP-reputation cost.
//
// Two deliberate properties:
//   - AUTH is offered only over TLS (AllowInsecureAuth = false); an
//     unauthenticated session can never relay. This listener is never an open relay.
//   - Relayed mail is opaque transport: it is enqueued into the existing
//     outbound_queue WITHOUT re-signing DKIM. The downstream already signed it,
//     and that signature is what receivers verify (ADR-0030 invariant).
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"rookery/internal/config"
	"rookery/internal/store"
)

// ErrNoSuchRelayClient is returned by RelayClientStore.LookupRelayClient when no
// row matches the SASL username.
var ErrNoSuchRelayClient = errors.New("no such relay client")

// RelayClient is the subset of a relay_clients row needed to authenticate and
// rate-limit a submission session.
type RelayClient struct {
	ID          string
	SecretHash  string
	Enabled     bool
	RatePerHour int
}

// RelayClientStore is the database surface the submission backend needs. It is
// an interface so the listener can be tested without a live Postgres.
type RelayClientStore interface {
	// LookupRelayClient returns the relay client for a SASL username, or
	// ErrNoSuchRelayClient if none exists.
	LookupRelayClient(ctx context.Context, username string) (RelayClient, error)
	// TouchRelayClient records that the client authenticated successfully.
	TouchRelayClient(ctx context.Context, id string) error
	// CountRelayQueuedSince counts queue rows enqueued for a client since t,
	// for per-client rate limiting.
	CountRelayQueuedSince(ctx context.Context, id string, t time.Time) (int, error)
	// EnqueueRelayed inserts one outbound_queue row per recipient for an
	// already-signed relayed message stored at blobSHA.
	EnqueueRelayed(ctx context.Context, relayClientID, mailFrom, blobSHA string, recipients []string) error
}

// blobWriter is the blob-store surface the submission backend needs.
// *store.Store satisfies it.
type blobWriter interface {
	WriteBlob(data []byte) (string, error)
}

// SubmissionServer runs the authenticated submission listeners (587 STARTTLS and
// 465 implicit TLS) that share one backend.
type SubmissionServer struct {
	listeners []submissionListener
}

// submissionListener pairs a go-smtp server with its TLS mode (587 STARTTLS vs
// 465 implicit TLS), since that choice selects ListenAndServe vs ListenAndServeTLS.
type submissionListener struct {
	srv         *smtp.Server
	implicitTLS bool
}

// NewSubmissionServer constructs (but does not start) the submission listeners.
// tlsCfg must be non-nil — the submission listener never runs without TLS.
func NewSubmissionServer(cfg *config.Config, db *pgxpool.Pool, st *store.Store, tlsCfg *tls.Config) *SubmissionServer {
	return newSubmissionServer(cfg, &pgRelayStore{db: db}, st, tlsCfg)
}

// newSubmissionServer is the testable constructor: it takes the store
// interfaces directly so tests can supply fakes.
func newSubmissionServer(cfg *config.Config, rs RelayClientStore, bw blobWriter, tlsCfg *tls.Config) *SubmissionServer {
	be := &submissionBackend{cfg: cfg, relays: rs, blobs: bw}

	mk := func(addr string, implicitTLS bool) submissionListener {
		srv := smtp.NewServer(be)
		srv.Addr = addr
		srv.Domain = cfg.Domain
		srv.ReadTimeout = 5 * time.Minute
		srv.WriteTimeout = 5 * time.Minute
		srv.MaxMessageBytes = cfg.SMTP.MaxMessageBytes
		srv.MaxRecipients = 100
		srv.TLSConfig = tlsCfg
		// AUTH is offered only over TLS. On 587 that means after STARTTLS; on
		// 465 the whole session is already TLS.
		srv.AllowInsecureAuth = false
		return submissionListener{srv: srv, implicitTLS: implicitTLS}
	}

	return &SubmissionServer{listeners: []submissionListener{
		mk(net.JoinHostPort("0.0.0.0", "587"), false),
		mk(net.JoinHostPort("0.0.0.0", "465"), true),
	}}
}

// ListenAndServe starts every submission listener and blocks until ctx is
// cancelled or a listener fails.
func (s *SubmissionServer) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, len(s.listeners))
	for _, l := range s.listeners {
		l := l
		go func() {
			slog.Info("smtp: submission listener starting", "addr", l.srv.Addr, "implicit_tls", l.implicitTLS)
			var err error
			if l.implicitTLS {
				err = l.srv.ListenAndServeTLS()
			} else {
				err = l.srv.ListenAndServe()
			}
			if err != nil {
				errCh <- fmt.Errorf("submission listener %s: %w", l.srv.Addr, err)
			}
		}()
	}

	closeAll := func() {
		for _, l := range s.listeners {
			_ = l.srv.Close()
		}
	}

	select {
	case <-ctx.Done():
		closeAll()
		return nil
	case err := <-errCh:
		closeAll()
		return err
	}
}

// -------------------------------------------------------------------------
// go-smtp backend
// -------------------------------------------------------------------------

type submissionBackend struct {
	cfg    *config.Config
	relays RelayClientStore
	blobs  blobWriter
}

func (b *submissionBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &submissionSession{backend: b}
	if b.cfg.Policy.LogConnectingIPs && c != nil {
		if conn := c.Conn(); conn != nil {
			s.remoteAddr = conn.RemoteAddr().String()
		}
	}
	return s, nil
}

type submissionSession struct {
	backend    *submissionBackend
	remoteAddr string

	client     *RelayClient // set once authenticated
	from       string
	recipients []string
}

// AuthMechanisms advertises only PLAIN. go-smtp offers AUTH solely over TLS
// (AllowInsecureAuth = false), so credentials never cross an unencrypted link.
func (s *submissionSession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// Auth verifies a relay client's SASL credentials against the relay_clients
// whitelist. All failure modes return the same opaque error so an attacker
// cannot distinguish "unknown username" from "wrong secret" or "disabled".
func (s *submissionSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, username, password string) error {
		ctx := context.Background()
		rc, err := s.backend.relays.LookupRelayClient(ctx, username)
		if err != nil {
			if !errors.Is(err, ErrNoSuchRelayClient) {
				slog.Error("submission: relay client lookup failed", "err", err)
			}
			return smtp.ErrAuthFailed
		}
		if !rc.Enabled {
			return smtp.ErrAuthFailed
		}
		if bcrypt.CompareHashAndPassword([]byte(rc.SecretHash), []byte(password)) != nil {
			return smtp.ErrAuthFailed
		}
		s.client = &rc
		if err := s.backend.relays.TouchRelayClient(ctx, rc.ID); err != nil {
			slog.Debug("submission: touch last_used_at failed", "err", err)
		}
		slog.Info("submission: relay client authenticated", "username", username, "remote", s.remoteAddr)
		return nil
	}), nil
}

func (s *submissionSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.client == nil {
		return smtp.ErrAuthRequired
	}
	s.from = strings.ToLower(strings.TrimSpace(from))
	return nil
}

func (s *submissionSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.client == nil {
		return smtp.ErrAuthRequired
	}
	to = strings.ToLower(strings.TrimSpace(to))
	if len(s.recipients) >= 100 {
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3},
			Message: "Too many recipients"}
	}
	s.recipients = append(s.recipients, to)
	return nil
}

func (s *submissionSession) Data(r io.Reader) error {
	if s.client == nil {
		return smtp.ErrAuthRequired
	}
	if len(s.recipients) == 0 {
		return errors.New("no recipients")
	}

	ctx := context.Background()

	// Per-client hourly rate limit. Over-limit returns 4xx so the downstream's
	// queue retries later rather than dropping the mail (ADR-0030 §3).
	if cap := s.client.RatePerHour; cap > 0 {
		n, err := s.backend.relays.CountRelayQueuedSince(ctx, s.client.ID, time.Now().Add(-time.Hour))
		if err != nil {
			slog.Warn("submission: rate-limit count failed, allowing", "err", err)
		} else if n+len(s.recipients) > cap {
			slog.Info("submission: relay client over rate limit", "client", s.client.ID, "count", n, "cap", cap)
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 0},
				Message: "Rate limit exceeded, retry later"}
		}
	}

	rawMsg, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("submission: read data: %w", err)
	}

	// Store the already-signed message once; all recipients share the blob.
	blobSHA, err := s.backend.blobs.WriteBlob(rawMsg)
	if err != nil {
		slog.Error("submission: write blob", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message: "Temporary storage error"}
	}

	// Enqueue into the shared outbound queue. No DKIM re-signing: opaque transport.
	if err := s.backend.relays.EnqueueRelayed(ctx, s.client.ID, s.from, blobSHA, s.recipients); err != nil {
		slog.Error("submission: enqueue relayed message", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message: "Temporary queue error"}
	}
	slog.Info("submission: relayed message queued", "client", s.client.ID, "recipients", len(s.recipients), "blob", blobSHA)
	return nil
}

func (s *submissionSession) Reset() {
	s.from = ""
	s.recipients = nil
}

func (s *submissionSession) Logout() error { return nil }

// -------------------------------------------------------------------------
// Postgres-backed RelayClientStore
// -------------------------------------------------------------------------

type pgRelayStore struct{ db *pgxpool.Pool }

func (p *pgRelayStore) LookupRelayClient(ctx context.Context, username string) (RelayClient, error) {
	var rc RelayClient
	err := p.db.QueryRow(ctx, `
		SELECT id, secret_hash, enabled, rate_per_hour
		FROM   relay_clients
		WHERE  username = $1
	`, username).Scan(&rc.ID, &rc.SecretHash, &rc.Enabled, &rc.RatePerHour)
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayClient{}, ErrNoSuchRelayClient
	}
	if err != nil {
		return RelayClient{}, err
	}
	return rc, nil
}

func (p *pgRelayStore) TouchRelayClient(ctx context.Context, id string) error {
	_, err := p.db.Exec(ctx, `UPDATE relay_clients SET last_used_at = now() WHERE id = $1`, id)
	return err
}

func (p *pgRelayStore) CountRelayQueuedSince(ctx context.Context, id string, t time.Time) (int, error) {
	var n int
	err := p.db.QueryRow(ctx, `
		SELECT count(*) FROM outbound_queue
		WHERE relay_client_id = $1 AND created_at >= $2
	`, id, t).Scan(&n)
	return n, err
}

func (p *pgRelayStore) EnqueueRelayed(ctx context.Context, relayClientID, mailFrom, blobSHA string, recipients []string) error {
	batch := &pgx.Batch{}
	for _, to := range recipients {
		batch.Queue(`
			INSERT INTO outbound_queue (recipient, relay_client_id, mail_from, blob_sha256)
			VALUES ($1, $2, $3, $4)
		`, to, relayClientID, mailFrom, blobSHA)
	}
	br := p.db.SendBatch(ctx, batch)
	defer br.Close()
	for range recipients {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}
