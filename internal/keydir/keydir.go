// Package keydir manages the local key directory:
//   - Parsing and validating uploaded OpenPGP public keys.
//   - Serving keys via the WKD Advanced Method endpoint.
//   - The z-base-32 encoding of SHA-1 hashes of local-parts required by WKD.
//
// Only the public key is ever stored here. The private key never leaves the
// browser; see §11.1 and ADR-0010.
//
// WKD reference: draft-koch-openpgp-webkey-service (Advanced Method, §11.7).
// The instance serves WKD under the openpgpkey.<domain> virtual host, which
// is pointed at this instance via CNAME in the user's DNS.
package keydir

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by the WKD spec, not used for security
	"encoding/binary"
	"fmt"
	"strings"

	pgpcrypto "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ParsePublicKey parses an ASCII-armored OpenPGP public key and returns its
// fingerprint (hex, uppercase) and a short algorithm string.
//
// Only Curve25519 (ed25519 + cv25519) primary keys are accepted for new
// registrations. RSA-4096 is accepted only as a legacy import path per
// ADR-0011. All other algorithms are rejected.
func ParsePublicKey(armored string) (fingerprint, algorithm string, err error) {
	block, err := armor.Decode(strings.NewReader(armored))
	if err != nil {
		return "", "", fmt.Errorf("keydir: parse armor: %w", err)
	}
	if block.Type != "PGP PUBLIC KEY BLOCK" {
		return "", "", fmt.Errorf("keydir: expected PUBLIC KEY BLOCK, got %q", block.Type)
	}

	entities, err := pgpcrypto.ReadKeyRing(block.Body)
	if err != nil {
		return "", "", fmt.Errorf("keydir: read key ring: %w", err)
	}
	if len(entities) == 0 {
		return "", "", fmt.Errorf("keydir: no keys found in armored block")
	}
	if len(entities) > 1 {
		return "", "", fmt.Errorf("keydir: armored block must contain exactly one key, got %d", len(entities))
	}

	entity := entities[0]
	if entity.PrivateKey != nil {
		return "", "", fmt.Errorf("keydir: refusing to store a private key")
	}
	primaryKey := entity.PrimaryKey
	if primaryKey == nil {
		return "", "", fmt.Errorf("keydir: key has no primary key packet")
	}

	algo, err := algorithmString(primaryKey)
	if err != nil {
		return "", "", err
	}

	fp := fmt.Sprintf("%X", primaryKey.Fingerprint)
	return fp, algo, nil
}

// algorithmString returns a short human-readable algorithm tag and validates
// that the key algorithm is accepted (Curve25519 or RSA-4096 legacy).
func algorithmString(pk *packet.PublicKey) (string, error) {
	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoEdDSA:
		return "cv25519+ed25519", nil
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		bits, err := pk.BitLength()
		if err != nil {
			return "", fmt.Errorf("keydir: could not determine RSA key size: %w", err)
		}
		if int(bits) < 3072 {
			return "", fmt.Errorf("keydir: RSA keys must be at least 3072 bits (got %d); generate a new Curve25519 key instead", bits)
		}
		return fmt.Sprintf("rsa%d", bits), nil
	default:
		return "", fmt.Errorf("keydir: unsupported algorithm %d; use Curve25519 (ed25519+cv25519)", pk.PubKeyAlgo)
	}
}

// BinaryPublicKey returns the binary (non-armored) representation of an
// ASCII-armored public key. WKD serves binary keys, not ASCII armor.
func BinaryPublicKey(armoredKey string) ([]byte, error) {
	block, err := armor.Decode(strings.NewReader(armoredKey))
	if err != nil {
		return nil, fmt.Errorf("keydir: decode armor: %w", err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(block.Body); err != nil {
		return nil, fmt.Errorf("keydir: read key body: %w", err)
	}
	return buf.Bytes(), nil
}

// WKDHash computes the z-base-32 encoded SHA-1 hash of a lower-cased
// local-part, as required by the WKD Advanced Method spec.
//
// The WKD spec (§3.1) defines:
//
//	hash = z-base-32(SHA-1(lower-case(local-part)))
//
// z-base-32 is the human-oriented variant defined in ZB32 by Phillip
// Hallam-Baker, used by WKD and GnuPG.
func WKDHash(localPart string) string {
	sum := sha1.Sum([]byte(strings.ToLower(localPart))) //nolint:gosec
	return zBase32Encode(sum[:])
}

// zBase32Alphabet is the z-base-32 alphabet (RFC-like but distinct from
// standard base32; used by GnuPG and the WKD spec).
const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// zBase32Encode encodes src using the z-base-32 alphabet.
// This is a 5-bit-per-character encoding of arbitrary byte slices.
func zBase32Encode(src []byte) string {
	// Pad to a multiple of 5 bytes so we can process in 5-byte (40-bit) groups.
	padded := make([]byte, (len(src)+4)/5*5)
	copy(padded, src)

	out := make([]byte, 0, len(padded)/5*8)
	for i := 0; i < len(padded); i += 5 {
		// Read 5 bytes as a 40-bit big-endian integer.
		n := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, padded[i:i+5]...))
		for j := 7; j >= 0; j-- {
			out = append(out, zBase32Alphabet[(n>>(uint(j)*5))&0x1F])
		}
	}

	// The output length for a 20-byte (160-bit SHA-1) input is 32 chars.
	// Trim any padding characters that correspond to the zero-padded bytes.
	outputLen := (len(src)*8 + 4) / 5
	return string(out[:outputLen])
}
