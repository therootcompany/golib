package csvauth

import (
	"iter"
	"maps"
)

// CredentialKeys returns the names that serve as IDs for each of the login credentials
func (a *Auth) CredentialKeys() iter.Seq[Name] {
	a.mux.Lock()
	defer a.mux.Unlock()
	return maps.Keys(a.credentials)
}

func (a *Auth) LoadCredential(name Name) (Credential, error) {
	a.mux.Lock()
	c, ok := a.credentials[name]
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
	a.mux.Lock()
	defer a.mux.Unlock()

	name := c.Name
	if c.Purpose == PurposeToken {
		name += hashIDSep + c.hashID
	}
	a.credentials[name] = c

	if c.Purpose == PurposeToken {
		a.tokens[c.hashID] = c
	}
	return nil
}
