package smtp

import (
	"crypto/tls"
	"fmt"
	"path/filepath"
)

// Loaded once at startup, so renewals are picked up only on restart.
func LoadSubmissionTLS(certsDir, host, certFile, keyFile string) (*tls.Config, error) {
	cert, key, err := resolveCertPaths(certsDir, host, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, fmt.Errorf("submission TLS: load key pair (%s, %s): %w", cert, key, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func resolveCertPaths(certsDir, host, certFile, keyFile string) (cert, key string, err error) {
	if certFile != "" && keyFile != "" {
		return certFile, keyFile, nil
	}

	// Caddy stores certs at <certsDir>/<ca>/<host>/<host>.crt|.key; the <ca>
	// segment varies (Let's Encrypt vs ZeroSSL), so glob it.
	pattern := filepath.Join(certsDir, "*", host, host+".crt")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", "", fmt.Errorf("submission TLS: glob %s: %w", pattern, err)
	}
	if len(matches) == 0 {
		return "", "", fmt.Errorf("submission TLS: no readable certificate for %q under %s (looked for %s). "+
			"Caddy has likely not issued one yet — confirm the prod profile is running and that Caddy has provisioned a cert for this host. "+
			"See docs/ops/spam-runbook.md, \"Acting as a relay rookery\"",
			host, certsDir, pattern)
	}
	cert = matches[0]
	key = cert[:len(cert)-len(".crt")] + ".key"
	return cert, key, nil
}
