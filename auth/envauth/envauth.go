package envauth

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
)

var ErrUnauthorized = errors.New("unauthorized")

type BasicAuthVerifier interface {
	Verify(string, string) error
}

// BasicCredentials holds user credentials
type BasicCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Returns true if username and password match.
// Uses SHA-256 and constant-time techniques to avoid revealing whether the username or password matches through timing attacks.
func (c BasicCredentials) Verify(username string, password string) error {
	if len(password) == 0 {
		return ErrUnauthorized
	}

	equal := 1

	// We hash rather than completely relying on subtle.ConstantTimeCompare([]byte(c.Username), []byte(username))
	// out of an abundance of caution since optimizations have caused similar methods to fail in other languages.
	// (we also use it because it gives back 1 rather than true, which we can use in the next step)
	knownUsernameHash := sha256.Sum256([]byte(c.Username))
	usernameHash := sha256.Sum256([]byte(username))
	v := subtle.ConstantTimeCompare(knownUsernameHash[:], usernameHash[:]) // 1 if same
	equal = subtle.ConstantTimeSelect(v, equal, 0)                         // v ? x : y

	knownPasswordHash := sha256.Sum256([]byte(c.Password))
	passwordHash := sha256.Sum256([]byte(password))
	v = subtle.ConstantTimeCompare(knownPasswordHash[:], passwordHash[:]) // 1 if same
	equal = subtle.ConstantTimeSelect(v, equal, 0)                        // v ? x : y

	if equal == 1 {
		return nil
	}
	return ErrUnauthorized
}

// PBKDF2Credentials holds user credentials
type PBKDF2Credentials struct {
	Username   string `json:"username"`
	DerivedKey []byte `json:"derived_key"`
	Salt       []byte `json:"salt"` // should be at least 8 bytes
	Iterations int    `json:"iterations"`
}

// Returns true if username and password match.
// Uses PBKDF2 and constant-time techniques to avoid revealing whether the username or password matches through timing attacks.
func (c PBKDF2Credentials) Verify(username string, password string) error {
	keyLen := len(c.DerivedKey)
	dkKnownUser, err := pbkdf2.Key(sha256.New, c.Username, c.Salt, c.Iterations, keyLen)
	if err != nil {
		return err
	}

	if len(password) == 0 {
		return ErrUnauthorized
	}

	dkUser, err := pbkdf2.Key(sha256.New, username, c.Salt, c.Iterations, keyLen)
	if err != nil {
		return err
	}
	dkPass, err := pbkdf2.Key(sha256.New, password, c.Salt, c.Iterations, keyLen)
	if err != nil {
		return err
	}

	equal := 1

	v := subtle.ConstantTimeCompare(dkUser, dkKnownUser) // 1 if same
	equal = subtle.ConstantTimeSelect(v, equal, 0)       // v ? x : y

	v = subtle.ConstantTimeCompare(dkPass, c.DerivedKey) // 1 if same
	equal = subtle.ConstantTimeSelect(v, equal, 0)       // v ? x : y

	if equal == 1 {
		return nil
	}
	return ErrUnauthorized

}

func (c PBKDF2Credentials) DeriveKey(username string, password string, keyLen int) ([]byte, error) {
	if keyLen == 0 {
		keyLen = len(c.DerivedKey)
	}
	return pbkdf2.Key(sha256.New, password, c.Salt, c.Iterations, keyLen)
}

var _ BasicAuthVerifier = (*BasicCredentials)(nil)
var _ BasicAuthVerifier = (*PBKDF2Credentials)(nil)
