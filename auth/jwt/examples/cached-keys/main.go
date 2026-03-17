// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example cached-keys demonstrates persisting JWKS keys to disk so that a
// service can start verifying tokens immediately on restart without blocking
// on a network fetch.
//
// On startup, keys are loaded from a local file (if it exists) and passed
// as InitialKeys. After each Verifier() call, RefreshedAt is checked to
// detect updates, and keys are saved only when the sorted KIDs differ.
package main

import (
	"fmt"
	"log"
	"os"
	"slices"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/keyfetch"
	"github.com/therootcompany/golib/auth/jwt/keyfile"
)

const (
	jwksURL   = "https://accounts.example.com/.well-known/jwks.json"
	cacheFile = "jwks-cache.json"
)

func main() {
	// Load cached keys from disk (if any).
	initialKeys, err := loadCachedKeys(cacheFile)
	if err != nil {
		log.Printf("no cached keys: %v", err)
	}

	fetcher := &keyfetch.KeyFetcher{
		URL:            jwksURL,
		RefreshTimeout: 10 * time.Second,
		InitialKeys:    initialKeys,
	}

	// Track when we last saved so we can detect refreshes.
	cachedKIDs := sortedKIDs(initialKeys)
	lastSaved := time.Time{}

	verifier, err := fetcher.Verifier()
	if err != nil {
		log.Fatalf("failed to get verifier: %v", err)
	}

	// Save if keys were refreshed and KIDs changed.
	if fetcher.RefreshedAt().After(lastSaved) {
		lastSaved = fetcher.RefreshedAt()
		kids := sortedKIDs(verifier.PublicKeys())
		if !slices.Equal(kids, cachedKIDs) {
			if err := keyfile.SavePublicJWKs(cacheFile, verifier.PublicKeys()); err != nil {
				log.Printf("save cached keys: %v", err)
			} else {
				cachedKIDs = kids
				log.Printf("saved %d keys to %s", len(verifier.PublicKeys()), cacheFile)
			}
		}
	}

	fmt.Printf("verifier ready with %d keys\n", len(verifier.PublicKeys()))
}

// loadCachedKeys reads a JWKS file and returns the keys. Returns nil
// (not an error) if the file doesn't exist.
func loadCachedKeys(path string) ([]jwt.PublicKey, error) {
	jwks, err := keyfile.LoadWellKnownJWKs(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return jwks.Keys, nil
}

// sortedKIDs returns the KIDs from keys in sorted order.
func sortedKIDs(keys []jwt.PublicKey) []string {
	kids := make([]string, len(keys))
	for i := range keys {
		kids[i] = keys[i].KID
	}
	slices.Sort(kids)
	return kids
}
