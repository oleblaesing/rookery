package smtp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
)

// captureBackend is a go-smtp backend that records the authenticated credentials
// and the delivered message for assertions. requireAuth controls whether MAIL is
// rejected until a successful AUTH.
type captureBackend struct {
	requireAuth bool
	wantUser    string
	wantPass    string

	mu       sync.Mutex
	authed   bool
	gotUser  string
	gotData  []byte
	gotRcpt  string
	mailSeen bool
}

func (b *captureBackend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &captureSession{b: b}, nil
}

type captureSession struct {
	b    *captureBackend
	auth bool
}

func (s *captureSession) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *captureSession) Auth(_ string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, username, password string) error {
		if username != s.b.wantUser || password != s.b.wantPass {
			return errors.New("invalid credentials")
		}
		s.auth = true
		s.b.mu.Lock()
		s.b.authed = true
		s.b.gotUser = username
		s.b.mu.Unlock()
		return nil
	}), nil
}

func (s *captureSession) Mail(_ string, _ *gosmtp.MailOptions) error {
	if s.b.requireAuth && !s.auth {
		return gosmtp.ErrAuthRequired
	}
	s.b.mu.Lock()
	s.b.mailSeen = true
	s.b.mu.Unlock()
	return nil
}

func (s *captureSession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	s.b.mu.Lock()
	s.b.gotRcpt = to
	s.b.mu.Unlock()
	return nil
}

func (s *captureSession) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.b.mu.Lock()
	s.b.gotData = data
	s.b.mu.Unlock()
	return nil
}

func (s *captureSession) Reset()        {}
func (s *captureSession) Logout() error { return nil }

// selfSignedCert generates an ECDSA cert valid for 127.0.0.1 and returns the
// tls.Certificate plus a cert pool trusting it (for the client side).
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// startServer starts a go-smtp server on a random loopback port and returns its
// host, port, and the backend for assertions. starttls toggles whether the
// server advertises STARTTLS.
func startServer(t *testing.T, be *captureBackend, tlsCfg *tls.Config, enableSTARTTLS bool) (host string, port int) {
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
	if enableSTARTTLS {
		srv.TLSConfig = tlsCfg
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

func TestDeliverViaSmarthost_STARTTLSAndAuth(t *testing.T) {
	cert, pool := selfSignedCert(t)
	prev := smarthostRootCAs
	smarthostRootCAs = pool
	t.Cleanup(func() { smarthostRootCAs = prev })

	be := &captureBackend{requireAuth: true, wantUser: "relay-user", wantPass: "s3cret"}
	host, port := startServer(t, be, &tls.Config{Certificates: []tls.Certificate{cert}}, true)

	msg := []byte("Subject: hi\r\n\r\nbody\r\n")
	err := DeliverViaSmarthost(context.Background(), "rookery.example", Smarthost{
		Host:       host,
		Port:       port,
		Username:   "relay-user",
		Password:   "s3cret",
		RequireTLS: true,
		Auth:       true,
	}, "from@rookery.example", "rcpt@elsewhere.example", msg)
	if err != nil {
		t.Fatalf("DeliverViaSmarthost: %v", err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if !be.authed {
		t.Error("server did not see a successful AUTH")
	}
	if be.gotUser != "relay-user" {
		t.Errorf("authenticated user = %q, want relay-user", be.gotUser)
	}
	if be.gotRcpt != "rcpt@elsewhere.example" {
		t.Errorf("RCPT = %q, want rcpt@elsewhere.example", be.gotRcpt)
	}
	if string(be.gotData) != string(msg) {
		t.Errorf("delivered data = %q, want %q", be.gotData, msg)
	}
}

func TestDeliverViaSmarthost_RequireTLSNoSTARTTLS(t *testing.T) {
	// Server does not advertise STARTTLS. With RequireTLS the attempt must fail
	// and must never transmit MAIL/DATA in the clear.
	be := &captureBackend{requireAuth: false, wantUser: "u", wantPass: "p"}
	host, port := startServer(t, be, nil, false)

	err := DeliverViaSmarthost(context.Background(), "rookery.example", Smarthost{
		Host:       host,
		Port:       port,
		RequireTLS: true,
		Auth:       false,
	}, "from@rookery.example", "rcpt@elsewhere.example", []byte("Subject: x\r\n\r\nx\r\n"))
	if err == nil {
		t.Fatal("expected hard failure when require_tls and no STARTTLS, got nil")
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if be.mailSeen {
		t.Error("MAIL FROM was sent in the clear despite require_tls — plaintext leak")
	}
	if be.gotData != nil {
		t.Error("message DATA was sent in the clear despite require_tls — plaintext leak")
	}
}

func TestDeliverViaSmarthost_NoTLSNoAuth(t *testing.T) {
	// The dev/mailpit shape: require_tls=false, auth=false, plaintext delivery.
	be := &captureBackend{requireAuth: false}
	host, port := startServer(t, be, nil, false)

	msg := []byte("Subject: hi\r\n\r\nbody\r\n")
	err := DeliverViaSmarthost(context.Background(), "rookery.example", Smarthost{
		Host:       host,
		Port:       port,
		RequireTLS: false,
		Auth:       false,
	}, "from@rookery.example", "rcpt@elsewhere.example", msg)
	if err != nil {
		t.Fatalf("DeliverViaSmarthost (plaintext): %v", err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if string(be.gotData) != string(msg) {
		t.Errorf("delivered data = %q, want %q", be.gotData, msg)
	}
}
