package csvauth

const tokenHashLen = 6

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
	return a.cacheID(secret, tokenHashLen)
}
