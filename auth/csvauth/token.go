package csvauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Provided for consistency. Often better to use Authenticate("", token)
func (a *Auth) LoadToken(secret string) (Credential, error) {
	var credential Credential
	c, err := a.loadAndVerifyToken(secret)
	if c != nil {
		credential = *c
	}
	return credential, err
}

// VerifyToken uses a shortened, but timing-safe HMAC to find the token,
// and then verifies it according to the chosen algorithm
func (a *Auth) VerifyToken(secret string) error {
	_, err := a.loadAndVerifyToken(secret)
	return err
}

func (a *Auth) loadAndVerifyToken(secret string) (*Credential, error) {
	hashID := a.tokenCacheID(secret)

	a.mux.Lock()
	c, ok := a.tokens[hashID]
	a.mux.Unlock()

	if !ok {
		return nil, ErrNotFound
	}

	if c.plain == "" {
		var err error
		if c.plain, err = a.maybeDecryptCredential(c); err != nil {
			return nil, err
		}
	}

	if err := c.Verify("", secret); err != nil {
		return nil, err
	}

	return &c, nil
}

func (a *Auth) tokenCacheID(secret string) string {
	key := a.aes128key[:]
	mac := hmac.New(sha256.New, key)
	message := []byte(secret)
	mac.Write(message)
	// attack collisions are possible, but will still fail to pass HMAC
	// practical collisions are not possible for the CSV use case
	nameBytes := mac.Sum(nil)[:6]

	name := base64.RawURLEncoding.EncodeToString(nameBytes)
	return name
}
