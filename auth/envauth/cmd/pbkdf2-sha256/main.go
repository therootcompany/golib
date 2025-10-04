package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var version = "v1.0.0"
var help = "pbkdf2-sha256 [password=random] [salt=random] [iterations=1000] [keySize=16]"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "version", "-version", "--version":
			fmt.Println(version)
			return
		case "help", "-help", "--help":
			fmt.Println("Usage:", help)
			os.Exit(0)
			return
		}
	}

	var password string
	var salt []byte
	var iterations int
	var keySize int
	var err error

	// Default values
	iterations = 1000
	keySize = 16

	// Parse arguments
	args := os.Args[1:]
	if len(args) > 4 {
		fmt.Fprintf(os.Stderr, "USAGE\n\t%s\n", help)
		return
	}

	// Password
	if len(args) > 0 && args[0] != "" {
		password = args[0]
	} else {
		fmt.Fprintf(os.Stderr, "\nUSAGE\n\t%s\n\n", help)
		rnd := make([]byte, 8)
		_, _ = rand.Read(rnd)
		hexPass := hex.EncodeToString(rnd)
		password = fmt.Sprintf("%s-%s-%s-%s", hexPass[:4], hexPass[4:8], hexPass[8:12], hexPass[12:])
		fmt.Printf("password   : %s\n", password)
	}

	// Salt
	if len(args) > 1 && args[1] != "" {
		saltStr := args[1]
		salt, err = parseHexOrBase64(saltStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding salt: %v\n", err)
			return
		}
	} else {
		salt = make([]byte, 16)
		_, _ = rand.Read(salt)
		fmt.Printf("salt       : %s\n", base64.RawURLEncoding.EncodeToString(salt))
	}

	// Iterations
	if len(args) > 2 && args[2] != "0" && args[2] != "" {
		iterations, err = parseInt(args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing iterations: %v\n", err)
			return
		}
	} else {
		fmt.Printf("iterations : %d\n", iterations)
	}

	// Key size
	if len(args) > 3 && args[3] != "0" && args[3] != "" {
		keySize, err = parseInt(args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing key size: %v\n", err)
			return
		}
	} else {
		fmt.Printf("key-size   : %d\n", keySize)
	}

	// Generate PBKDF2 key
	derivedKey, err := pbkdf2.Key(sha256.New, password, salt, iterations, keySize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing key size: %v\n", err)
		return
	}
	fmt.Printf("derived-key: %s\n\n", hex.EncodeToString(derivedKey))
}

func parseHexOrBase64(data string) ([]byte, error) {
	var b []byte

	// Check if salt is hex (all uppercase or lowercase, valid hex chars)
	isHex := true
	for _, c := range data {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			isHex = false
			break
		}
	}
	// Check for mixed case
	hasUpper := strings.ContainsAny(data, "ABCDEF")
	hasLower := strings.ContainsAny(data, "abcdef")
	if isHex && !(hasUpper && hasLower) {
		var err error
		b, err = hex.DecodeString(data)
		if err != nil {
			return nil, err
		}
	} else {
		// Assume URL-safe base64, convert to RFC base64
		rfcData := strings.ReplaceAll(data, "-", "+")
		rfcData = strings.ReplaceAll(rfcData, "_", "/")
		rfcData = strings.ReplaceAll(rfcData, "=", "")
		var err error
		b, err = base64.RawStdEncoding.DecodeString(rfcData)
		if err != nil {
			return nil, err
		}
	}

	return b, nil
}

func parseInt(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("value must be positive")
	}
	return n, nil
}
