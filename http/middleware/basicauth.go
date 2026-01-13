package middleware

import (
	"context"
	"net/http"
)

type BasicAuthVerifier interface {
	Verify(string, string) bool
}

type usernameKeyType struct{}

var UsernameKey usernameKeyType

func BasicAuth(v BasicAuthVerifier) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok || !v.Verify(username, password) {
				// s.jsonError(w, http.StatusUnauthorized, "unauthorized", "Unauthorized", "Invalid credentials")
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, UsernameKey, username)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
