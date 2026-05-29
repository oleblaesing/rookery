package smtp

import (
	"crypto/tls"
	"fmt"
	"path/filepath"
)

// LoadSubmissionTLS builds the TLS config for the relay-rookery submission
// listener. It reuses the certificate Caddy already provisions for the instance
// hostname rather than running a second ACME client (ADR-0030 §4).
//
// When certFile and keyFile are both set, they are loaded directly (the
// operator-supplied escape hatch). Otherwise the loader looks under certsDir for
// the Caddy layout <certsDir>/<ca>/<host>/<host>.{crt,key}; the <ca> path segment
// (e.g. acme-v02.api.letsencrypt.org-directory) is matched by glob so the loader
// does not need to know which CA issued the cert.
//
// Certs are loaded once at startup; ACME renewals (~60-day events) are picked up
// on the next restart (ADR-0030, out of scope: cert hot-reload).
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

// resolveCertPaths returns the cert and key file paths to load, either the
// explicit operator-supplied pair or the Caddy-provisioned pair discovered by
// globbing certsDir for the instance host.
func resolveCertPaths(certsDir, host, certFile, keyFile string) (cert, key string, err error) {
	if certFile != "" && keyFile != "" {
		return certFile, keyFile, nil
	}

	// Caddy stores certs at <certsDir>/<ca>/<host>/<host>.crt|.key. The <ca>
	// segment varies (Let's Encrypt vs ZeroSSL fallback), so glob it.
	pattern := filepath.Join(certsDir, "*", host, host+".crt")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", "", fmt.Errorf("submission TLS: glob %s: %w", pattern, err)
	}
	if len(matches) == 0 {
		return "", "", fmt.Errorf("submission TLS: no readable certificate for %q under %s (looked for %s). "+
			"Either Caddy has not issued one yet, or — more likely — rookery runs as a non-root user and cannot read Caddy's root-owned 0600 certs. "+
			"See docs/ops/spam-runbook.md, \"Acting as a relay rookery\", for the CADDY_UID/CADDY_GID fix",
			host, certsDir, pattern)
	}
	cert = matches[0]
	key = cert[:len(cert)-len(".crt")] + ".key"
	return cert, key, nil
}
