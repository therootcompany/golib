package passphrase

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"strings"

	"github.com/therootcompany/golib/encoding/base2048"
)

var (
	ErrInvalidWordCount   = errors.New("passphrase must contain 12, 15, 18, 21 or 24 words")
	ErrInvalidEntropyBits = errors.New("entropy must be 128, 160, 192, 224 or 256 bits (16-32 bytes)")
)

const (
	MagicString = "mnemonic"
)

// Generate creates a new passphrase with the specified entropy bits (128, 160, 192, 224, or 256)
// If the bit size doesn't match a known size it returns the phrase and ErrInvalidEntropyBits.
func Generate(bits int) (string, error) {
	var err error
	var byteLen int
	switch bits {
	case 128:
		byteLen = 16
	case 160:
		byteLen = 20
	case 192:
		byteLen = 24
	case 224:
		byteLen = 28
	case 256:
		byteLen = 32
	default:
		byteLen = bits / 8
		if bits%8 != 0 {
			byteLen += 1
		}
		err = ErrInvalidEntropyBits
	}

	entropy := make([]byte, byteLen)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}

	return base2048.EncodeToString(entropy), err
}

// SeedFrom converts a base2048 passphrase into a 512-bit seed (as per BIP-39)
// using PBKDF2-HMAC-SHA512 with 2048 iterations with an optional passphrase for salt.
// If the input doesn't pass verification, it returns the seed bytes and base2048.ErrChecksumMismatch.
// If the number of words isn't 12, 15, 18, 21 or 24, it returns the seed bytes and ErrInvalidWordCount.
// strings.Fields() is used to split on runs of whitespace.
// Non-ASCII text SHOULD first be normalized with norm.NFKD.String(s)
func SeedFrom(recoveryPhrase, saltWord string) ([]byte, error) {
	salt := []byte(MagicString + saltWord)
	recoveryWords := strings.Fields(recoveryPhrase)

	iterations := 2048
	keySize := 64
	seed, err := pbkdf2.Key(sha512.New, recoveryPhrase, salt, iterations, keySize)
	if err == nil {
		_, err = base2048.DecodeWords(recoveryWords)
		if err == nil {
			switch len(recoveryWords) {
			case 12, 15, 18, 21, 24:
				// great
			default:
				err = ErrInvalidWordCount
			}
		}
	}
	return seed, err
}
