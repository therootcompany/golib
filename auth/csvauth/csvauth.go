package csvauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

var ErrNotFound = errors.New("not found")
var ErrUnauthorized = errors.New("unauthorized")
var ErrUnknownAlgorithm = errors.New("unknown algorithm")
var ErrLockedCredential = errors.New("credential is locked")

const (
	defaultIters      = 1000 // original 2000 recommendation
	defaultSize       = 16   // 128-bit
	defaultHash       = "SHA-256"
	defaultBcryptCost = 12
	gcmNonceSize      = 12 // RFC spec
)

// NamedReadCloser provides Name() for debugging of file-like ReadClosers, such as http responses
type NamedReadCloser interface {
	io.ReadCloser
	Name() string
}

type readNamer struct {
	io.ReadCloser
	name string
}

// Name returns the name given to the wrapped ReadCloser to f8ulfill NamedReadCloser
func (r *readNamer) Name() string {
	return r.name
}

// NewNamedReadCloser wraps a ReadCloser with a name which can be referenced when debugging
func NewNamedReadCloser(r io.ReadCloser, name string) NamedReadCloser {
	return &readNamer{
		ReadCloser: r,
		name:       name,
	}
}

// Auth holds user the encryption key and both login and service account credentials
type Auth struct {
	aes128key           [16]byte
	credentials         map[Name]Credential
	tokens              map[string]Credential
	serviceAccounts     map[Purpose]Credential
	mux                 sync.Mutex
	BasicAuthTokenNames []string
}

// New initializes an Auth with an encryption key
func New(aes128key []byte) *Auth {
	var aes128Arr [16]byte
	copy(aes128Arr[:], aes128key)

	return &Auth{
		aes128key:           aes128Arr,
		credentials:         map[Name]Credential{},
		tokens:              map[string]Credential{},
		serviceAccounts:     map[Purpose]Credential{},
		BasicAuthTokenNames: []string{"", "api", "apikey"},
	}
}

// Load reads a credentials CSV from the given NamedReadCloser (e.g. file, wrapped http request)
func (a *Auth) LoadCSV(f NamedReadCloser, comma rune) error {
	csvr := csv.NewReader(f)
	csvr.Comma = comma
	csvr.Comment = '#'
	csvr.FieldsPerRecord = -1 // ignore short rows
	_, _ = csvr.Read()        // strip header row
	for {
		record, err := csvr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) == 0 {
			continue
		}

		if len(record) == 1 {
			if len(record[0]) == 0 {
				continue
			}
		}

		if len(record) < 5 {
			return fmt.Errorf("invalid %q format: %#v (%d)", f.Name(), record, len(record))
		}

		credential, err := FromRecord(record)
		if err != nil {
			return err
		}

		switch credential.Purpose {
		case "", PurposeDefault, PurposeToken:
			name := credential.Name
			if credential.Purpose == PurposeToken {
				name += hashIDSep + credential.hashID
			}

			if _, ok := a.credentials[name]; ok {
				fmt.Fprintf(os.Stderr, "overwriting cache of previous value for %s: %s\n", credential.Purpose, credential.Name)
			}
			a.credentials[name] = credential
			if credential.Purpose == PurposeToken {
				if _, ok := a.tokens[credential.hashID]; ok {
					fmt.Fprintf(os.Stderr, "overwriting cache of previous value for %s: %s\n", credential.Purpose, credential.Name)
				}
				a.tokens[credential.hashID] = credential
			}
		default:
			if _, ok := a.serviceAccounts[credential.Purpose]; ok {
				fmt.Fprintf(os.Stderr, "overwriting cache of previous value for %s: %s\n", credential.Purpose, credential.Name)
			}
			a.serviceAccounts[credential.Purpose] = credential
		}
	}

	return nil
}

// NewCredential derives the hashed, encrypted, or raw value from the given secret and sets additional required and provided parameters
func (a *Auth) NewCredential(purpose, name, secret string, params []string, roles []string, extra string) *Credential {
	c := &Credential{
		Purpose: purpose,
		Name:    name,
		//plain: secret,
		Params: params,
		//Salt: ...
		//Derived: ...
		Roles: roles,
		Extra: extra,
	}

	if purpose == PurposeToken {
		c.hashID = a.tokenCacheID(secret)
	}

	switch c.Params[0] {
	case "plain":
		if len(params) != 1 {
			fmt.Fprintf(os.Stderr, "invalid plain algorithm format: %q\n", strings.Join(params, " "))
			os.Exit(1)
		}
		c.plain = secretValue(secret)

		c.Params = []string{"plain"}
		h := sha256.Sum256([]byte(secret))
		c.Derived = h[:]
	case "aes-128-gcm":
		if len(params) != 1 {
			fmt.Fprintf(os.Stderr, "invalid aes-128-gcm algorithm format: %q\n", strings.Join(params, " "))
			os.Exit(1)
		}

		c.Params = []string{"aes-128-gcm"}
		nonce := make([]byte, gcmNonceSize)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			panic(err)
		}
		c.Salt = nonce

		var err error
		var salt [12]byte
		copy(salt[:], c.Salt)
		c.plain = secretValue(secret)
		c.Derived, err = gcmEncrypt(a.aes128key, salt, secret)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not aes-128-gcm encrypt secret: %v\n", err)
			os.Exit(1)
		}
	case "pbkdf2":
		if len(params) > 4 {
			fmt.Fprintf(os.Stderr, "invalid pbkdf2 algorithm format: %q\n", strings.Join(params, " "))
			os.Exit(1)
		}
		iters := defaultIters
		if len(params) > 1 {
			var err error
			iters, err = strconv.Atoi(params[1])
			if err != nil || iters <= 0 {
				fmt.Fprintf(os.Stderr, "invalid iterations %q in %q\n", params[1], strings.Join(params, " "))
				os.Exit(1)
			}
		}
		size := defaultSize
		if len(params) > 2 {
			var err error
			size, err = strconv.Atoi(params[2])
			if err != nil || size < 8 || size > 32 {
				fmt.Fprintf(os.Stderr, "invalid size %q in %q\n", params[2], strings.Join(params, " "))
				os.Exit(1)
			}
		}
		hashName := defaultHash
		if len(params) > 3 {
			if !slices.Contains([]string{"SHA-256", "SHA-1"}, params[3]) {
				fmt.Fprintf(os.Stderr, "invalid hash %q in %q\n", params[3], strings.Join(params, " "))
				os.Exit(1)
			}
			hashName = params[3]
		}
		c.Params = []string{"pbkdf2", strconv.Itoa(iters), strconv.Itoa(size), hashName}
		saltBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, saltBytes); err != nil {
			panic(err)
		}
		c.Salt = saltBytes
		var hasher func() hash.Hash
		hashNameUpper := strings.ToUpper(hashName)
		switch hashNameUpper {
		case "SHA-1", "SHA1":
			hashName = "SHA-1"
			hasher = sha1.New
		case "SHA-256", "SHA256":
			hashName = "SHA-256"
			hasher = sha256.New
		default:
			fmt.Fprintf(os.Stderr, "invalid hash %q (expected SHA-1 or SHA-256)\n", hashName)
			os.Exit(1)
		}
		var err error
		c.Derived, err = pbkdf2.Key(hasher, secret, saltBytes, iters, size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid pbkdf2 parameters: %v\n", err)
			os.Exit(1)
		}
	case "bcrypt":
		if len(params) > 2 {
			fmt.Fprintf(os.Stderr, "invalid bcrypt algorithm format: %q\n", strings.Join(params, " "))
			os.Exit(1)
		}
		cost := defaultBcryptCost
		if len(params) > 1 {
			var err error
			cost, err = strconv.Atoi(params[1])
			if err != nil || cost < 4 || cost > 31 {
				fmt.Fprintf(os.Stderr, "invalid bcrypt cost %q in %q\n", params[1], strings.Join(params, " "))
				os.Exit(1)
			}
		}
		c.Params = []string{"bcrypt"} // cost is included in the digest
		derived, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating bcrypt hash: %v\n", err)
			os.Exit(1)
		}
		c.Derived = derived
	default:
		fmt.Fprintf(os.Stderr, "invalid algorithm %q\n", params[0])
		os.Exit(1)
	}

	return c
}

func gcmEncrypt(aes128key [16]byte, gcmNonce [12]byte, secret string) ([]byte, error) {
	block, err := aes.NewCipher(aes128key[:])
	if err != nil {
		return nil, fmt.Errorf("new aes (encrypt) cipher failed: %v", err)
	}

	// nonceSize := len(gcmNonce) // should always be 12
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm (encrypt) failed: %v", err)
	}

	plaintext := []byte(secret)
	ciphertext := gcm.Seal(nil, gcmNonce[:], plaintext, nil)
	return ciphertext, nil
}

func (a *Auth) maybeDecryptCredential(c Credential) (secretValue, error) {
	switch c.Params[0] {
	case "aes-128-gcm":
		var salt [12]byte
		copy(salt[:], c.Salt)
		plain, err := a.gcmDecrypt(a.aes128key, salt, c.Derived)
		return secretValue(plain), err
	default:
		break
	}

	return c.plain, nil
}

func (a *Auth) gcmDecrypt(aes128key [16]byte, gcmNonce [12]byte, derived []byte) (string, error) {
	block, err := aes.NewCipher(aes128key[:])
	if err != nil {
		return "", fmt.Errorf("new aes (decrypt) cipher failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new gcm failed: %v", err)
	}

	plaintext, err := gcm.Open(nil, gcmNonce[:], derived, nil)
	if err != nil {
		return "", fmt.Errorf("gcm open (decryption) failed: %v", err)
	}

	return string(plaintext), nil
}

// Verify checks Basic Auth credentials, i.e. as decoded from Authorization Basic <base64(user:pass)>.
// It also supports tokens. In short:
//   - if <user>:<pass> and 'user' is found, then "login" credentials
//   - if <token>:"" or <allowed-token-name>:<token>, then "token" credentials
//
// With a little more nuance and clarity:
//   - if 'user' is found in the "login" credential store, token is NEVER tried
//   - either 'user' or 'pass' may be used as the token
//     (because 'pass' is swapped with 'user' when 'pass' is empty)
//   - the resulting 'user' must match BasicAuthTokenNames ("", "api", and "apikey" are the defaults)
//   - then the token is (timing-safe) hashed to check if it exists, and then verified by its algorithm
func (a *Auth) Verify(name, secret string) error {
	a.mux.Lock()
	defer a.mux.Unlock()
	c, ok := a.credentials[name]
	if ok {
		return c.Verify(name, secret)
	}

	if secret == "" {
		secret, name = name, secret
	}
	if slices.Contains(a.BasicAuthTokenNames, name) {
		// this still returns ErrNotFound first
		return a.VerifyToken(secret)
	}

	return ErrNotFound
}

// Verify checks Basic Auth credentials
// (name is ignored, as it is assumed to have been used for lookup)
func (c Credential) Verify(_, secret string) error {
	known := c.Derived
	var derived []byte
	switch c.Params[0] {
	case "aes-128-gcm":
		// we hash because encrypted comparisons are NOT timing safe
		if c.plain == "" {
			return ErrLockedCredential
		}
		knownHash := sha256.Sum256([]byte(c.plain))
		known = knownHash[:]

		h := sha256.Sum256([]byte(secret))
		derived = h[:]
	case "plain":
		h := sha256.Sum256([]byte(secret))
		derived = h[:]
	case "pbkdf2":
		// these are checked on load
		iters, _ := strconv.Atoi(c.Params[1])
		size, _ := strconv.Atoi(c.Params[2])
		var hasher func() hash.Hash
		switch c.Params[3] {
		case "SHA-1":
			hasher = sha1.New
		case "SHA-256":
			hasher = sha256.New
		default:
			panic(fmt.Errorf("invalid hash %q", c.Params[3]))
		}
		derived, _ = pbkdf2.Key(hasher, secret, c.Salt, iters, size)
	case "bcrypt":
		err := bcrypt.CompareHashAndPassword(c.Derived, []byte(secret))
		if err == nil {
			return nil
		}
		return ErrUnauthorized
	default:
		return ErrUnknownAlgorithm
	}

	// all values MUST be hashed before comparing, for timing safety
	if bytes.Equal(known, derived) {
		return nil
	}
	return ErrUnauthorized
}
