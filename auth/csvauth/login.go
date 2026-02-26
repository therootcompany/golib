package csvauth

import (
	"iter"
	"maps"
)

const nameHashLen = 16

// CredentialKeys returns the names that serve as IDs for each of the login credentials
func (a *Auth) CredentialKeys() iter.Seq[Name] {
	a.mux.Lock()
	defer a.mux.Unlock()
	return maps.Keys(a.credentials)
}

func (a *Auth) LoadCredential(name Name) (Credential, error) {
	nameID := a.nameCacheID(name)

	a.mux.Lock()
	c, ok := a.hashedCredentials[nameID]
	a.mux.Unlock()
	if !ok {
		return c, ErrNotFound
	}

	var err error
	if c.plain, err = a.maybeDecryptCredential(c); err != nil {
		return c, err
	}

	return c, nil
}

func (a *Auth) CacheCredential(c Credential) error {
	name := c.Name
	if c.Purpose == PurposeToken {
		name += hashIDSep + c.hashID
	}
	nameID := a.nameCacheID(name)

	a.mux.Lock()
	defer a.mux.Unlock()
	a.credentials[name] = c
	if c.Purpose == PurposeToken {
		a.tokens[c.hashID] = c
	} else {
		a.hashedCredentials[nameID] = c
	}

	return nil
}

func (a *Auth) nameCacheID(name string) string {
	return a.cacheID(name, nameHashLen)
}
