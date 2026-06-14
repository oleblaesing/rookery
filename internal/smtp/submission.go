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

var ErrNoSuchRelayClient = errors.New("no such relay client")

type RelayClient struct {
	ID          string
	SecretHash  string
	Enabled     bool
	RatePerHour int
}

// An interface so the listener can be tested without Postgres.
type RelayClientStore interface {
	LookupRelayClient(ctx context.Context, username string) (RelayClient, error)
	TouchRelayClient(ctx context.Context, id string) error
	CountRelayQueuedSince(ctx context.Context, id string, t time.Time) (int, error)
	EnqueueRelayed(ctx context.Context, relayClientID, mailFrom, blobSHA string, recipients []string) error
}

type blobWriter interface {
	WriteBlob(data []byte) (string, error)
}

type SubmissionServer struct {
	listeners []submissionListener
}

// Carries the TLS mode because it selects ListenAndServe vs ListenAndServeTLS
// (587 STARTTLS vs 465 implicit TLS).
type submissionListener struct {
	srv         *smtp.Server
	implicitTLS bool
}

// tlsCfg must be non-nil — submission never runs without TLS.
func NewSubmissionServer(cfg *config.Config, db *pgxpool.Pool, st *store.Store, tlsCfg *tls.Config) *SubmissionServer {
	return newSubmissionServer(cfg, &pgRelayStore{db: db}, st, tlsCfg)
}

// Takes the store interfaces directly so tests can fake them.
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
		srv.AllowInsecureAuth = false // AUTH only after STARTTLS (587) or inside TLS (465)
		return submissionListener{srv: srv, implicitTLS: implicitTLS}
	}

	return &SubmissionServer{listeners: []submissionListener{
		mk(net.JoinHostPort("0.0.0.0", "587"), false),
		mk(net.JoinHostPort("0.0.0.0", "465"), true),
	}}
}

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

	client     *RelayClient
	from       string
	recipients []string
}

func (s *submissionSession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// Returns the same opaque error for every failure mode so an attacker can't
// tell unknown-username from wrong-secret from disabled.
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

	// Over-limit returns 4xx so the downstream's queue retries rather than
	// dropping the mail.
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

	// One blob shared by every recipient.
	blobSHA, err := s.backend.blobs.WriteBlob(rawMsg)
	if err != nil {
		slog.Error("submission: write blob", "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0},
			Message: "Temporary storage error"}
	}

	// Opaque transport: no DKIM re-signing.
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
