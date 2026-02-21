package csvauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func (a *Auth) LoadToken(secret string) (Credential, error) {
	hashID := a.tokenCacheID(secret)

	a.mux.Lock()
	c, ok := a.tokens[hashID]
	a.mux.Unlock()

	if !ok {
		return Credential{}, ErrNotFound
	}

	if c.plain == "" {
		var err error
		if c.plain, err = a.maybeDecryptCredential(c); err != nil {
			return Credential{}, err
		}
	}

	if err := c.Verify("", secret); err != nil {
		return Credential{}, err
	}

	return c, nil
}

// VerifyToken uses a short, but timing-safe hash to find the token,
// and then verifies it with HMAC
func (a *Auth) VerifyToken(secret string) error {
	_, err := a.LoadToken(secret)
	return err
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
