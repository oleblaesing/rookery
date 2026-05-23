package discovery

import "crypto/sha1" //nolint:gosec // SHA-1 is required by the WKD spec, not used for security

func sha1Digest(data []byte) [20]byte {
	return sha1.Sum(data) //nolint:gosec
}
