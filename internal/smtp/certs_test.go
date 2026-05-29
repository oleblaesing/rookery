package smtp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCertPair writes a self-signed cert/key PEM pair to dir as <name>.crt and
// <name>.key and returns the cert path.
func writeCertPair(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	certPEM, _ := os.Create(certPath)
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPEM.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM, _ := os.Create(keyPath)
	pem.Encode(keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyPEM.Close()

	return certPath
}

func TestLoadSubmissionTLS_CaddyLayoutGlob(t *testing.T) {
	root := t.TempDir()
	host := "relay.example"
	// Mimic Caddy's <certsDir>/<ca>/<host>/<host>.{crt,key} layout.
	caDir := filepath.Join(root, "acme-v02.api.letsencrypt.org-directory", host)
	writeCertPair(t, caDir, host)

	cfg, err := LoadSubmissionTLS(root, host, "", "")
	if err != nil {
		t.Fatalf("LoadSubmissionTLS: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

func TestLoadSubmissionTLS_ExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	certPath := writeCertPair(t, dir, "explicit")
	keyPath := certPath[:len(certPath)-len(".crt")] + ".key"

	// certsDir is intentionally bogus: explicit paths must win.
	cfg, err := LoadSubmissionTLS("/nonexistent", "ignored", certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadSubmissionTLS explicit: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

func TestLoadSubmissionTLS_NoCertIsError(t *testing.T) {
	if _, err := LoadSubmissionTLS(t.TempDir(), "absent.example", "", ""); err == nil {
		t.Fatal("expected an error when no certificate exists")
	}
}
