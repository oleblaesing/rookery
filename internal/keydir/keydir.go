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

// WKD serves binary, not armor.
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

func WKDHash(localPart string) string {
	sum := sha1.Sum([]byte(strings.ToLower(localPart))) //nolint:gosec
	return zBase32Encode(sum[:])
}

const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

func zBase32Encode(src []byte) string {
	padded := make([]byte, (len(src)+4)/5*5)
	copy(padded, src)

	out := make([]byte, 0, len(padded)/5*8)
	for i := 0; i < len(padded); i += 5 {
		n := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, padded[i:i+5]...))
		for j := 7; j >= 0; j-- {
			out = append(out, zBase32Alphabet[(n>>(uint(j)*5))&0x1F])
		}
	}

	// Trim the chars produced by the zero padding back to the true bit length.
	outputLen := (len(src)*8 + 4) / 5
	return string(out[:outputLen])
}
