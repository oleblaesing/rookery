package smtp

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"golang.org/x/crypto/bcrypt"

	"rookery/internal/config"
)

// fakeRelayStore is an in-memory RelayClientStore for submission tests.
type fakeRelayStore struct {
	clients   map[string]RelayClient // keyed by username
	hourCount int                    // value returned by CountRelayQueuedSince
	enqueued  []enqueuedRelay
	touched   []string
}

type enqueuedRelay struct {
	clientID, from, blob string
	recipients           []string
}

func (f *fakeRelayStore) LookupRelayClient(_ context.Context, username string) (RelayClient, error) {
	rc, ok := f.clients[username]
	if !ok {
		return RelayClient{}, ErrNoSuchRelayClient
	}
	return rc, nil
}

func (f *fakeRelayStore) TouchRelayClient(_ context.Context, id string) error {
	f.touched = append(f.touched, id)
	return nil
}

func (f *fakeRelayStore) CountRelayQueuedSince(_ context.Context, _ string, _ time.Time) (int, error) {
	return f.hourCount, nil
}

func (f *fakeRelayStore) EnqueueRelayed(_ context.Context, clientID, from, blob string, recipients []string) error {
	f.enqueued = append(f.enqueued, enqueuedRelay{clientID, from, blob, recipients})
	return nil
}

type fakeBlobs struct{ last []byte }

func (f *fakeBlobs) WriteBlob(b []byte) (string, error) {
	f.last = b
	return "fakeblobsha", nil
}

// startSubmissionServer starts a STARTTLS go-smtp server backed by be on a
// random loopback port. AUTH is offered only after STARTTLS.
func startSubmissionServer(t *testing.T, be *submissionBackend, tlsCfg *tls.Config) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := gosmtp.NewServer(be)
	srv.Domain = "127.0.0.1"
	srv.AllowInsecureAuth = false
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.TLSConfig = tlsCfg
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

func newTestBackend(t *testing.T, clients map[string]RelayClient) (*submissionBackend, *fakeRelayStore, *fakeBlobs) {
	t.Helper()
	rs := &fakeRelayStore{clients: clients}
	bw := &fakeBlobs{}
	be := &submissionBackend{
		cfg:    &config.Config{Domain: "127.0.0.1", SMTP: config.SMTPConfig{MaxMessageBytes: 1 << 20}},
		relays: rs,
		blobs:  bw,
	}
	return be, rs, bw
}

// hashed returns a bcrypt hash of secret at minimum cost (tests stay fast).
func hashed(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// trustServerCert points the smarthost client's root pool at the test server's
// self-signed cert so DeliverViaSmarthost (used here as a submission client)
// completes the TLS handshake.
func trustServerCert(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	cert, pool := selfSignedCert(t)
	prev := smarthostRootCAs
	smarthostRootCAs = pool
	t.Cleanup(func() { smarthostRootCAs = prev })
	return cert, &tls.Config{Certificates: []tls.Certificate{cert}}
}

func TestSubmission_ValidClientEnqueues(t *testing.T) {
	be, rs, bw := newTestBackend(t, map[string]RelayClient{
		"relay-x": {ID: "id1", SecretHash: hashed(t, "topsecret"), Enabled: true, RatePerHour: 200},
	})
	_, srvTLS := trustServerCert(t)
	host, port := startSubmissionServer(t, be, srvTLS)

	msg := []byte("Subject: hi\r\n\r\nbody\r\n")
	err := DeliverViaSmarthost(context.Background(), "client.example", Smarthost{
		Host: host, Port: port, Username: "relay-x", Password: "topsecret",
		RequireTLS: true, Auth: true,
	}, "sender@client.example", "rcpt@far.example", msg)
	if err != nil {
		t.Fatalf("DeliverViaSmarthost: %v", err)
	}

	if len(rs.enqueued) != 1 {
		t.Fatalf("expected 1 enqueued message, got %d", len(rs.enqueued))
	}
	e := rs.enqueued[0]
	if e.clientID != "id1" || e.from != "sender@client.example" || e.blob != "fakeblobsha" {
		t.Errorf("enqueued mismatch: %+v", e)
	}
	if len(e.recipients) != 1 || e.recipients[0] != "rcpt@far.example" {
		t.Errorf("recipients mismatch: %v", e.recipients)
	}
	if string(bw.last) != string(msg) {
		t.Errorf("stored blob mismatch: %q", bw.last)
	}
	if len(rs.touched) != 1 {
		t.Errorf("expected last_used_at touch, got %d", len(rs.touched))
	}
}

func TestSubmission_RejectsUnknownAndDisabledAndWrongSecret(t *testing.T) {
	be, rs, _ := newTestBackend(t, map[string]RelayClient{
		"good":     {ID: "id1", SecretHash: hashed(t, "rightpass"), Enabled: true, RatePerHour: 200},
		"disabled": {ID: "id2", SecretHash: hashed(t, "rightpass"), Enabled: false, RatePerHour: 200},
	})
	_, srvTLS := trustServerCert(t)
	host, port := startSubmissionServer(t, be, srvTLS)

	cases := []struct{ name, user, pass string }{
		{"unknown user", "nope", "whatever"},
		{"disabled client", "disabled", "rightpass"},
		{"wrong secret", "good", "wrongpass"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := DeliverViaSmarthost(context.Background(), "client.example", Smarthost{
				Host: host, Port: port, Username: tc.user, Password: tc.pass,
				RequireTLS: true, Auth: true,
			}, "sender@client.example", "rcpt@far.example", []byte("Subject: x\r\n\r\nb\r\n"))
			if err == nil {
				t.Fatal("expected authentication failure, got nil")
			}
		})
	}
	if len(rs.enqueued) != 0 {
		t.Errorf("no message should have been enqueued, got %d", len(rs.enqueued))
	}
}

func TestSubmission_RateLimitTempFails(t *testing.T) {
	be, rs, _ := newTestBackend(t, map[string]RelayClient{
		"relay-x": {ID: "id1", SecretHash: hashed(t, "s"), Enabled: true, RatePerHour: 10},
	})
	rs.hourCount = 10 // already at the cap
	_, srvTLS := trustServerCert(t)
	host, port := startSubmissionServer(t, be, srvTLS)

	err := DeliverViaSmarthost(context.Background(), "client.example", Smarthost{
		Host: host, Port: port, Username: "relay-x", Password: "s",
		RequireTLS: true, Auth: true,
	}, "sender@client.example", "rcpt@far.example", []byte("Subject: x\r\n\r\nb\r\n"))
	if err == nil {
		t.Fatal("expected a temporary failure at the rate cap")
	}
	if len(rs.enqueued) != 0 {
		t.Errorf("over-limit message must not be enqueued, got %d", len(rs.enqueued))
	}
}

func TestSubmission_NoAuthOfferedWithoutTLS(t *testing.T) {
	be, rs, _ := newTestBackend(t, map[string]RelayClient{
		"relay-x": {ID: "id1", SecretHash: hashed(t, "s"), Enabled: true, RatePerHour: 200},
	})
	// Start a server with NO TLS config: AllowInsecureAuth=false means AUTH is
	// never advertised, so a client cannot authenticate.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := gosmtp.NewServer(be)
	srv.Domain = "127.0.0.1"
	srv.AllowInsecureAuth = false
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)

	// require_tls=false so the client proceeds far enough to discover AUTH is
	// not on offer (the server-side property we are asserting).
	err = DeliverViaSmarthost(context.Background(), "client.example", Smarthost{
		Host: h, Port: port, Username: "relay-x", Password: "s",
		RequireTLS: false, Auth: true,
	}, "sender@client.example", "rcpt@far.example", []byte("Subject: x\r\n\r\nb\r\n"))
	if err == nil {
		t.Fatal("expected failure: AUTH must not be offered without TLS")
	}
	if len(rs.enqueued) != 0 {
		t.Errorf("nothing should be enqueued, got %d", len(rs.enqueued))
	}
}
