package auth_test

import (
	"fmt"
	"net/http"

	"github.com/therootcompany/golib/auth"
)

// exampleCredentialStore is a toy BasicAuthenticator used only in the example below.
type exampleCredentialStore struct{}

func (exampleCredentialStore) Authenticate(username, password string) (auth.BasicPrinciple, error) {
	return nil, fmt.Errorf("not implemented")
}

// ExampleBasicRequestAuthenticator shows the typical usage pattern.
// Build a BasicRequestAuthenticator once (at startup), attach your credential
// store as the Authenticator, then call Authenticate in each handler.
// Set the WWW-Authenticate header before writing a 401 to instruct the browser
// to prompt for Username and Password on failure.
func ExampleBasicRequestAuthenticator() {
	ra := auth.NewBasicRequestAuthenticator()
	ra.Authenticator = exampleCredentialStore{} // swap in your real credential store

	http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		principle, err := ra.Authenticate(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", ra.BasicRealm)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "hello %s", principle.ID())
	})
}
