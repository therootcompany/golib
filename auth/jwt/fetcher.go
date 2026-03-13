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
	// (e.g. 120s) is appropriate — JWKS fetching is not tied to individual
	// request lifetimes and should be allowed to eventually succeed.
	HTTPClient *http.Client

	mu         sync.Mutex
	cached     atomic.Pointer[cachedVerifier]
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
// already running.
//
// No cache: blocks until the first fetch completes.
func (f *KeyFetcher) Verifier() (*Verifier, error) {
	now := time.Now()
	ci := f.cached.Load()

	// Fast path: fresh keys.
	if ci != nil && now.Before(ci.expiresAt) {
		return ci.iss, nil
	}

	// Stale path: return immediately and refresh in the background.
	if ci != nil && f.KeepOnError && now.Before(ci.expiresAt.Add(f.StaleAge)) {
		f.mu.Lock()
		if !f.refreshing {
			f.refreshing = true
			go f.backgroundRefresh()
		}
		lastErr := f.lastErr
		f.mu.Unlock()
		return ci.iss, lastErr
	}

	// Blocking path: no usable cache — wait for a fetch.
	// Holds f.mu for the duration of the HTTP request so concurrent callers
	// queue behind it rather than issuing redundant requests.
	f.mu.Lock()
	defer f.mu.Unlock()

	// Re-check after acquiring lock — another goroutine may have refreshed.
	now = time.Now()
	if ci := f.cached.Load(); ci != nil && now.Before(ci.expiresAt) {
		return ci.iss, nil
	}

	return f.fetch()
}

// backgroundRefresh fetches fresh keys without blocking callers.
// It acquires f.mu for the duration of the HTTP request so that any
// concurrent blocking callers wait for this fetch rather than issuing
// a redundant request.
func (f *KeyFetcher) backgroundRefresh() {
	f.mu.Lock()
	defer func() {
		f.refreshing = false
		f.mu.Unlock()
	}()

	// Re-check: a blocking caller may have already refreshed while we
	// were waiting to acquire the lock.
	now := time.Now()
	if ci := f.cached.Load(); ci != nil && now.Before(ci.expiresAt) {
		return
	}

	if _, err := f.fetch(); err != nil {
		f.lastErr = err
	} else {
		f.lastErr = nil
	}
}

// fetch performs the HTTP request and stores the result. Must be called with f.mu held.
func (f *KeyFetcher) fetch() (*Verifier, error) {
	client := f.HTTPClient
	timeout := clientTimeout(client)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	keys, err := jwk.FetchURL(ctx, f.URL, client)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", f.URL, err)
	}

	maxAge := f.MaxAge
	if maxAge <= 0 {
		maxAge = time.Hour
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
