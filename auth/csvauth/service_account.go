package csvauth

import (
	"iter"
	"maps"
)

// CredentialKeys returns the names that serve as IDs for each of the login credentials
func (a *Auth) ServiceAccountKeys() iter.Seq[Purpose] {
	a.mux.Lock()
	defer a.mux.Unlock()
	return maps.Keys(a.serviceAccounts)
}

func (a *Auth) LoadServiceAccount(purpose Purpose) (Credential, error) {
	a.mux.Lock()
	c, ok := a.serviceAccounts[purpose]
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

func (a *Auth) CacheServiceAccount(c Credential) error {
	a.mux.Lock()
	defer a.mux.Unlock()
	a.serviceAccounts[c.Purpose] = c
	return nil
}
