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
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// cachedVerifier bundles a [*Verifier] with its freshness window.
// Stored atomically in [KeyFetcher]; immutable after creation.
type cachedVerifier struct {
	iss       *Verifier
	fetchedAt time.Time
	expiresAt time.Time // fetchedAt + MaxAge
}

// KeyFetcher lazily fetches and caches JWKS keys from a remote URL,
// returning a [*Verifier] on demand.
//
// When cached keys are still fresh (within MaxAge), [KeyFetcher.Verifier]
// returns immediately with no network call. When they have expired but are
// within the stale window (MaxAge + StaleAge, KeepOnError=true), the stale
// keys are returned immediately alongside any error from the most recent
// failed background refresh, and a new background refresh is started if one
// is not already running. Only when there are no cached keys at all does
// [KeyFetcher.Verifier] block until the first successful fetch.
//
// InitialKeys, if set, pre-populate the cache as immediately stale on the
// first call to [KeyFetcher.Verifier]. Combined with KeepOnError=true and a
// positive StaleAge, they are served immediately while a background refresh
// fetches fresh keys - useful for bootstrapping auth without a blocking fetch
// at startup.
//
// There is no persistent background goroutine: refreshes are started on
// demand and run until the HTTP client's timeout fires or the fetch succeeds.
//
// Fields must be set before the first call to [KeyFetcher.Verifier]; do not
// modify them concurrently.
//
// Typical usage:
//
//	fetcher := &jwt.KeyFetcher{
//	    URL:         "https://accounts.example.com/.well-known/jwks.json",
//	    MaxAge:      time.Hour,
//	    StaleAge:    30 * time.Minute,
//	    KeepOnError: true,
//	}
//	iss, err := fetcher.Verifier()
type KeyFetcher struct {
	// URL is the JWKS endpoint to fetch keys from.
	URL string

	// MaxAge is how long fetched keys are considered fresh. After MaxAge,
	// the next call to Verifier triggers a background refresh. Defaults to 1 hour.
	MaxAge time.Duration

	// StaleAge is additional time beyond MaxAge during which the cached Verifier
	// may be returned immediately while a background refresh runs. For example,
	// MaxAge=1h and StaleAge=30m means the stale Verifier is served for up to
	// 90 minutes after the last successful fetch. Defaults to 0 (no stale window).
	StaleAge time.Duration

	// KeepOnError causes the cached Verifier to be returned immediately (with
	// a background refresh) when keys have expired but are within the stale
	// window. If false, the blocking path is used even for expired keys.
	KeepOnError bool

	// HTTPClient is the HTTP client used for all JWKS fetches. If nil, a
	// default client with a 30s timeout is used. Providing a reusable client
	// enables TCP connection pooling across refreshes.
	//
	// The client's Timeout controls how long a refresh may run. A long value
	// (e.g. 120s) is appropriate - JWKS fetching is not tied to individual
	// request lifetimes and should be allowed to eventually succeed.
	HTTPClient *http.Client

	// InitialKeys pre-populate the cache as immediately stale on the first call
	// to Verifier. Combined with KeepOnError=true and a positive StaleAge, they
	// are served immediately while a background refresh fetches fresh keys.
	InitialKeys []jwk.PublicKey

	fetchMu    sync.Mutex                   // held during HTTP fetch
	ctrlMu     sync.Mutex                   // held briefly for refreshing/lastErr
	cached     atomic.Pointer[cachedVerifier]
	initOnce   sync.Once
	refreshing bool  // true while a background refresh goroutine is running
	lastErr    error // last background refresh error; cleared on success
}

// Verifier returns a [*Verifier] for verifying tokens.
//
// Fresh (within MaxAge): returned immediately, no network call.
//
// Stale (past MaxAge, within MaxAge+StaleAge, KeepOnError=true): the cached
// Verifier is returned immediately alongside any error from the most recent
// failed background refresh. A background refresh is started if one is not
// already running. The stale path never blocks on an in-progress HTTP fetch.
//
// No cache: blocks until the first fetch completes.
func (f *KeyFetcher) Verifier() (*Verifier, error) {
	f.maybeInit()

	now := time.Now()
	ci := f.cached.Load()

	// Fast path: fresh keys.
	if ci != nil && now.Before(ci.expiresAt) {
		return ci.iss, nil
	}

	// Stale path: return immediately and refresh in the background.
	// ctrlMu is held only briefly - it never blocks on an in-progress HTTP fetch.
	if ci != nil && f.KeepOnError && now.Before(ci.expiresAt.Add(f.StaleAge)) {
		f.ctrlMu.Lock()
		if !f.refreshing {
			f.refreshing = true
			go f.backgroundRefresh()
		}
		lastErr := f.lastErr
		f.ctrlMu.Unlock()
		return ci.iss, lastErr
	}

	// Blocking path: no usable cache - wait for a fetch.
	// fetchMu serializes concurrent blocking callers; the re-check prevents
	// a redundant fetch if another goroutine already refreshed.
	f.fetchMu.Lock()
	defer f.fetchMu.Unlock()

	// Re-check after acquiring lock - another goroutine may have refreshed.
	now = time.Now()
	if ci := f.cached.Load(); ci != nil && now.Before(ci.expiresAt) {
		return ci.iss, nil
	}

	return f.fetch()
}

// backgroundRefresh fetches fresh keys without blocking callers.
// It acquires fetchMu for the duration of the HTTP request so that any
// concurrent blocking callers wait for this fetch rather than issuing
// a redundant request.
func (f *KeyFetcher) backgroundRefresh() {
	f.fetchMu.Lock()
	defer f.fetchMu.Unlock()

	// Re-check: a blocking caller may have already refreshed while we
	// were waiting to acquire the lock.
	now := time.Now()
	if ci := f.cached.Load(); ci != nil && now.Before(ci.expiresAt) {
		f.ctrlMu.Lock()
		f.refreshing = false
		f.ctrlMu.Unlock()
		return
	}

	_, err := f.fetch()
	f.ctrlMu.Lock()
	f.refreshing = false
	if err != nil {
		f.lastErr = err
	} else {
		f.lastErr = nil
	}
	f.ctrlMu.Unlock()
}

// maybeInit seeds the cache with InitialKeys on the first call, if set.
// The seeded verifier is immediately expired so it is served as stale,
// triggering a background refresh while being available immediately.
func (f *KeyFetcher) maybeInit() {
	if len(f.InitialKeys) == 0 {
		return
	}
	f.initOnce.Do(func() {
		now := time.Now()
		ci := &cachedVerifier{
			iss:       New(f.InitialKeys),
			fetchedAt: now,
			expiresAt: now, // immediately expired - served as stale, triggers background refresh
		}
		f.cached.Store(ci)
	})
}

// fetch performs the HTTP request and stores the result. Must be called with fetchMu held.
//
// The cache TTL is the server's Cache-Control max-age, clamped to MaxAge.
// If the server sends no Cache-Control header, MaxAge is used directly.
func (f *KeyFetcher) fetch() (*Verifier, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout(f.HTTPClient))
	defer cancel()

	keys, serverMaxAge, err := jwk.FetchURL(ctx, f.URL, f.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", f.URL, err)
	}

	maxAge := f.MaxAge
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	// Honor the server's Cache-Control max-age, clamped to our MaxAge ceiling.
	if serverMaxAge > 0 && serverMaxAge < maxAge {
		maxAge = serverMaxAge
	}

	now := time.Now()
	ci := &cachedVerifier{
		iss:       New(keys),
		fetchedAt: now,
		expiresAt: now.Add(maxAge),
	}
	f.cached.Store(ci)
	return ci.iss, nil
}

// clientTimeout returns client.Timeout, or 30s if the client is nil or has no timeout set.
func clientTimeout(client *http.Client) time.Duration {
	if client != nil && client.Timeout > 0 {
		return client.Timeout
	}
	return 30 * time.Second
}
