// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example http-middleware demonstrates the common pattern of verifying a JWT
// in HTTP middleware, stashing the claims in the request context, and
// extracting them in a downstream handler.
//
// The context accessor pair (WithClaims / ClaimsFromContext) is defined
// here to show how simple it is - no library support needed.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// AppClaims embeds TokenClaims and adds application-specific fields.
type AppClaims struct {
	jwt.TokenClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// --- Context accessors ---
// Two lines of code - no library support required.

type contextKey string

const claimsKey contextKey = "claims"

// WithClaims returns a new context carrying the given claims.
func WithClaims(ctx context.Context, c *AppClaims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

// ClaimsFromContext extracts claims from the context.
func ClaimsFromContext(ctx context.Context) (*AppClaims, bool) {
	c, ok := ctx.Value(claimsKey).(*AppClaims)
	return c, ok
}

func main() {
	// --- Setup: create a signer + verifier for demonstration ---
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		log.Fatal(err)
	}
	verifier := signer.Verifier()
	validator := jwt.NewIDTokenValidator(
		[]string{"https://example.com"},
		[]string{"myapp"},
		nil, // azp
		0,   // grace period (0 = default 2s)
	)

	// --- Middleware: verify + validate + stash ---
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimPrefix(auth, "Bearer ")

			jws, err := jwt.Decode(tokenStr)
			if err != nil {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			if err := verifier.Verify(jws); err != nil {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}

			var claims AppClaims
			if err := jws.UnmarshalClaims(&claims); err != nil {
				http.Error(w, "bad claims", http.StatusUnauthorized)
				return
			}
			hdr := jws.GetHeader()
			var errs []error
			errs = hdr.IsAllowedTyp(errs, []string{"JWT"})
			if err := validator.Validate(errs, &claims, time.Now()); err != nil {
				http.Error(w, "invalid claims", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), &claims)))
		})
	}

	// --- Handler: extract claims from context ---
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "hello %s (%s)\n", claims.Sub, claims.Email)
	})

	mux := http.NewServeMux()
	mux.Handle("/api/me", authMiddleware(handler))

	// Mint a token so we can demonstrate the round trip.
	claims := &AppClaims{
		TokenClaims: jwt.TokenClaims{
			Iss:      "https://example.com",
			Sub:      "user-42",
			Aud:      jwt.Listish{"myapp"},
			Exp:      time.Now().Add(time.Hour).Unix(),
			IAt:      time.Now().Unix(),
			AuthTime: time.Now().Unix(),
		},
		Email: "user@example.com",
		Roles: []string{"admin"},
	}
	token, err := signer.SignToString(claims)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token[:40]+"...")
	fmt.Println("curl -H 'Authorization: Bearer <token>' http://localhost:8080/api/me")

	log.Fatal(http.ListenAndServe(":8080", mux))
}
