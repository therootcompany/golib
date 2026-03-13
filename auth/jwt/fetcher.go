// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// cachedIssuer bundles an [*Issuer] with its freshness window.
// Stored atomically in [JWKsFetcher]; immutable after creation.
type cachedIssuer struct {
	iss       *Issuer
	fetchedAt time.Time
	expiresAt time.Time // fetchedAt + MaxAge; fresh until this point
}

// JWKsFetcher lazily fetches and caches JWKS keys from a remote URL,
// returning a fresh [*Issuer] on demand.
//
// Each call to [JWKsFetcher.Issuer] checks freshness and either returns the
// cached Issuer immediately or fetches a new one. There is no background
// goroutine — refresh only happens when a caller requests an Issuer.
//
// Fields must be set before the first call to [JWKsFetcher.Issuer]; do not
// modify them concurrently.
//
// Typical usage:
//
//	fetcher := &jwt.JWKsFetcher{
//	    URL:         "https://accounts.example.com/.well-known/jwks.json",
//	    MaxAge:      time.Hour,
//	    StaleAge:    30 * time.Minute,
//	    KeepOnError: true,
//	}
//	iss, err := fetcher.Issuer(ctx)
type JWKsFetcher struct {
	// URL is the JWKS endpoint to fetch keys from.
	URL string

	// MaxAge is how long fetched keys are considered fresh. After MaxAge,
	// the next call to Issuer triggers a refresh. Defaults to 1 hour.
	MaxAge time.Duration

	// StaleAge is additional time beyond MaxAge during which the old Issuer
	// may be returned when a refresh fails. For example, MaxAge=1h and
	// StaleAge=30m means keys will be served up to 90 minutes after the last
	// successful fetch, if KeepOnError is true and fetches keep failing.
	// Defaults to 0 (no stale window).
	StaleAge time.Duration

	// KeepOnError causes the previous Issuer to be returned (with an error)
	// when a refresh fails, as long as the result is within the stale window
	// (expiresAt + StaleAge). If false, any fetch error after MaxAge returns
	// (nil, err).
	KeepOnError bool

	mu     sync.Mutex
	cached atomic.Pointer[cachedIssuer]
}

// Issuer returns a current [*Issuer] for verifying tokens.
//
// If the cached Issuer is still fresh (within MaxAge), it is returned without
// a network call. If it has expired, a new fetch is performed. On fetch
// failure with KeepOnError=true and within StaleAge, the old Issuer is
// returned alongside a non-nil error; callers may choose to accept it.
func (f *JWKsFetcher) Issuer(ctx context.Context) (*Issuer, error) {
	now := time.Now()

	// Fast path: check cached value without locking.
	if ci := f.cached.Load(); ci != nil && now.Before(ci.expiresAt) {
		return ci.iss, nil
	}

	// Slow path: refresh needed. Serialize to avoid stampeding.
	f.mu.Lock()
	defer f.mu.Unlock()

	// Recapture time after acquiring lock — the fast-path timestamp may be stale
	// if there was contention and another goroutine held the lock for a while.
	now = time.Now()

	// Re-check after acquiring lock — another goroutine may have refreshed.
	if ci := f.cached.Load(); ci != nil && now.Before(ci.expiresAt) {
		return ci.iss, nil
	}

	keys, err := jwk.FetchURL(ctx, f.URL)
	if err != nil {
		// On error, serve stale keys within the stale window.
		if ci := f.cached.Load(); ci != nil && f.KeepOnError {
			staleDeadline := ci.expiresAt.Add(f.StaleAge)
			if now.Before(staleDeadline) {
				return ci.iss, fmt.Errorf("JWKS refresh failed (serving cached keys): %w", err)
			}
		}
		return nil, fmt.Errorf("fetch JWKS from %s: %w", f.URL, err)
	}

	maxAge := f.MaxAge
	if maxAge <= 0 {
		maxAge = time.Hour
	}

	ci := &cachedIssuer{
		iss:       New(keys),
		fetchedAt: now,
		expiresAt: now.Add(maxAge),
	}
	f.cached.Store(ci)
	return ci.iss, nil
}
