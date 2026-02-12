package base2048

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	ErrUnknownWord      = errors.New("unknown word in mnemonic")
	ErrChecksumMismatch = errors.New("checksum does not match")
)

// EncodeToString returns the base2048 encoding of src.
func EncodeToString(src []byte) string {
	words := EncodeToWords(src)

	return strings.Join(words, " ")
}

// EncodeToWords returns the base2048 slice of src.
func EncodeToWords(src []byte) []string {
	bits := len(src) * 8
	checkBits := bits % 11
	if checkBits != 0 {
		checkBits = 11 - checkBits
	}

	hash := sha256.Sum256(src)

	// Always prepare 16 bits worth of material (high byte first)
	checkMaterial := (uint16(hash[0]) << 8) | uint16(hash[1])

	// Shift right so the top checkBits bits become the low bits
	shift := 16 - uint16(checkBits)
	check := checkMaterial >> shift

	// src<<checkBits | check
	bi := new(big.Int).SetBytes(src)
	bi.Lsh(bi, uint(checkBits))
	bi.Or(bi, big.NewInt(int64(check)))

	// Extract 11-bit words from LSB
	numWords := (bits + checkBits) / 11
	words := make([]string, numWords)
	mask := big.NewInt(2047) // 2^11 - 1

	for i := numWords - 1; i >= 0; i-- {
		var wordIdx big.Int
		wordIdx.And(bi, mask)
		words[i] = wordList[wordIdx.Uint64()]
		bi.Rsh(bi, 11)
	}

	return words
}

// DecodeString returns the bytes represented by the base2048 string of words.
// If the input doesn't pass verification, it returns the decoded data and ErrChecksumMismatch.
// strings.Fields() is used to split on runs of whitespace.
func DecodeString(phrase string) ([]byte, error) {
	words := strings.Fields(phrase)
	return DecodeWords(words)
}

// DecodeWords returns the bytes represented by the base2048 word slice.
// If the input doesn't pass verification, it returns the decoded data and ErrChecksumMismatch.
func DecodeWords(words []string) ([]byte, error) {
	numWords := len(words)

	// Build big.Int from bits (MSB first)
	bi := big.NewInt(0)
	for _, word := range words {
		bits, ok := wordMap[word]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownWord, word)
		}
		bi.Lsh(bi, 11)
		bi.Or(bi, big.NewInt(int64(bits)))
	}

	// Calculate bit lengths
	checkBits := numWords / 3
	entBits := numWords*11 - checkBits
	entLen := entBits / 8

	// Extract entropy
	entBi := new(big.Int).Rsh(bi, uint(checkBits))
	entropy := make([]byte, entLen)
	entBi.FillBytes(entropy)

	h := sha256.Sum256(entropy)
	expCheck := uint64(h[0]) >> (8 - uint(checkBits))

	var mask big.Int
	mask.Lsh(big.NewInt(1), uint(checkBits))
	mask.Sub(&mask, big.NewInt(1))

	gotCheck := new(big.Int).And(bi, &mask).Uint64()

	if gotCheck != expCheck {
		return entropy, ErrChecksumMismatch
	}
	return entropy, nil
}
