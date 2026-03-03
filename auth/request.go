// BasicRequestAuthenticator - Authenticate HTTP requests by the most common methods
//
// Authored in 2026 by AJ ONeal <aj@therootcompany.com>, assisted by GitHub Copilot (Claude).
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package auth

import (
	"errors"
	"net/http"
	"slices"
	"strings"
)

// ErrNoCredentials is returned by BasicRequestAuthenticator.Authenticate when the
// request contains no recognizable form of credentials.
var ErrNoCredentials = errors.New("no credentials provided")

// BasicRequestAuthenticator extracts credentials from an HTTP request and delegates
// verification to a BasicAuthenticator. It supports Basic Auth, Authorization
// header tokens, custom token headers, and query-parameter tokens.
//
// Use NewBasicRequestAuthenticator for sane defaults.
type BasicRequestAuthenticator struct {
	// Authenticator is the credential verifier called with the extracted
	// username/password or token. Must be set before calling Authenticate.
	Authenticator BasicAuthenticator

	// BasicAuth enables HTTP Basic Auth (Authorization: Basic …).
	BasicAuth bool

	// BasicRealm is the suggested value for the WWW-Authenticate response
	// header. Set it on the response before writing a 401 Unauthorized so that
	// clients know which auth scheme to use. An empty string means no header.
	// NewBasicRequestAuthenticator sets this to "Basic".
	//
	// Example:
	//
	//	if _, err := ra.Authenticate(r); err != nil {
	//		w.Header().Set("WWW-Authenticate", ra.BasicRealm)
	//		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	//		return
	//	}
	BasicRealm string

	// AuthorizationSchemes lists accepted schemes for "Authorization: <scheme> <token>".
	// nil or an empty slice skips the Authorization header entirely;
	// ["*"] accepts any scheme; ["Bearer", "Token"] restricts to those schemes.
	AuthorizationSchemes []string

	// TokenHeaders lists header names checked for bearer tokens,
	// e.g. []string{"X-API-Key"}.
	TokenHeaders []string

	// TokenQueryParams lists query parameter names checked for tokens,
	// e.g. []string{"access_token", "token"}.
	TokenQueryParams []string
}

// NewBasicRequestAuthenticator returns a BasicRequestAuthenticator with sane defaults:
// Basic Auth enabled, Bearer/Token Authorization schemes, common API-key
// headers, access_token/token query params, and BasicRealm "Basic".
//
// Example:
//
//	cred, err := ra.Authenticate(r)
//	if err != nil {
//		w.Header().Set("WWW-Authenticate", ra.BasicRealm)
//		http.Error(w, "Unauthorized", http.StatusUnauthorized)
//		return
//	}
func NewBasicRequestAuthenticator(auth BasicAuthenticator) *BasicRequestAuthenticator {
	return &BasicRequestAuthenticator{
		Authenticator:        auth,
		BasicAuth:            true,
		BasicRealm:           "Basic",
		AuthorizationSchemes: []string{"Bearer", "Token"},
		TokenHeaders:         []string{"X-API-Key"},
		TokenQueryParams:     []string{"access_token", "token"},
	}
}

// Authenticate extracts credentials from r in this order:
//  1. Basic Auth (Authorization: Basic …)
//  2. Authorization: <scheme> <token> (filtered by AuthorizationSchemes)
//  3. Token headers (TokenHeaders)
//  4. Query parameters (TokenQueryParams)
//
// Returns ErrNoCredentials if no credential form is present in the request.
func (ra *BasicRequestAuthenticator) Authenticate(r *http.Request) (BasicPrinciple, error) {
	a := ra.Authenticator

	// 1. Basic Auth
	if ra.BasicAuth {
		if username, password, ok := r.BasicAuth(); ok {
			return a.Authenticate(username, password)
		}
	}

	// 2. Authorization: <scheme> <token>
	// AuthorizationSchemes must be non-empty to check the Authorization header;
	// nil or empty skips it entirely.
	if len(ra.AuthorizationSchemes) > 0 {
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 {
				scheme, token := parts[0], strings.TrimSpace(parts[1])
				if ra.AuthorizationSchemes[0] == "*" ||
					slices.Contains(ra.AuthorizationSchemes, scheme) {
					return a.Authenticate("", token)
				}
			}
			return nil, ErrNoCredentials
		}
	}

	// 3. Token headers
	for _, h := range ra.TokenHeaders {
		if token := r.Header.Get(h); token != "" {
			return a.Authenticate("", token)
		}
	}

	// 4. Query parameters
	for _, p := range ra.TokenQueryParams {
		if token := r.URL.Query().Get(p); token != "" {
			return a.Authenticate("", token)
		}
	}

	return nil, ErrNoCredentials
}
