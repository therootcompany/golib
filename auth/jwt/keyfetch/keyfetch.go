// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package keyfetch lazily fetches and caches JWKS keys from remote URLs.
//
// [KeyFetcher] returns a [jwt.Verifier] on demand, refreshing keys in the
// background when they expire. For one-shot fetches without caching, use
// [FetchURL], [FetchOIDC], or [FetchOAuth2].
package keyfetch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// cachedVerifier bundles a [*jwt.Verifier] with its freshness window.
// Stored atomically in [KeyFetcher]; immutable after creation.
type cachedVerifier struct {
	verifier    *jwt.Verifier
	staleAt     time.Time // background refresh should start
	hardExp     time.Time // do not serve after this time
	refreshedAt time.Time // when this verifier was fetched
}

// KeyFetcher lazily fetches and caches JWKS keys from a remote URL,
// returning a [*jwt.Verifier] on demand.
//
// Cache timing is derived from the server's Cache-Control headers with
// sane defaults: 15m when absent, floored at 2m, capped at 24h. The
// "stale" point (3/4 of expiry) triggers a background refresh while
// serving cached keys. See [cacheTimings] for the full policy.
//
// When cached keys are fresh (before stale time), [KeyFetcher.Verifier]
// returns immediately with no network call. When stale but not expired,
// the cached Verifier is returned immediately and a background refresh
// is started. Only when there are no cached keys does [KeyFetcher.Verifier]
// block until the first successful fetch.
//
// When keys are past their hard expiry, RefreshTimeout controls the
// behavior: if zero (default), Verifier blocks until the refresh completes.
// If positive, Verifier waits up to that duration and returns the expired
// keys if the refresh hasn't finished.
//
// InitialKeys, if set, pre-populate the cache as immediately expired on
// the first call to [KeyFetcher.Verifier]. Combined with a positive
// RefreshTimeout, they are served immediately while a background refresh
// fetches fresh keys - useful for bootstrapping auth without a blocking
// fetch at startup.
//
// There is no persistent background goroutine: refreshes are started on
// demand and run until the HTTP client's timeout fires or the fetch succeeds.
//
// Use [KeyFetcher.RefreshedAt] to detect when keys have been updated
// (e.g. to persist them to disk for faster restarts).
//
// Use [NewKeyFetcher] to validate the URL upfront. Fields must be set
// before the first call to [KeyFetcher.Verifier]; do not modify them
// concurrently.
//
// KeyFetcher is safe for concurrent use. Multiple goroutines may call
// [KeyFetcher.Verifier] simultaneously without additional synchronization.
//
// Typical usage:
//
//	fetcher, err := keyfetch.NewKeyFetcher("https://accounts.example.com/.well-known/jwks.json")
//	// ...
//	v, err := fetcher.Verifier()
type KeyFetcher struct {
	// URL is the JWKS endpoint to fetch keys from.
	URL string

	// RefreshTimeout controls how long Verifier waits for a refresh when
	// cached keys are past their hard expiry. If zero (default), Verifier
	// blocks until the fetch completes. If positive, Verifier waits up to
	// this duration and returns expired keys if the fetch hasn't finished.
	//
	// Has no effect when keys are stale but not expired (Verifier always
	// returns immediately in that case) or when no cached keys exist
	// (the first fetch always blocks).
	RefreshTimeout time.Duration

	// HTTPClient is the HTTP client used for all JWKS fetches. If nil, a
	// default client with a 30s timeout is used. Providing a reusable client
	// enables TCP connection pooling across refreshes.
	//
	// The client's Timeout controls how long a refresh may run. A long value
	// (e.g. 120s) is appropriate - JWKS fetching is not tied to individual
	// request lifetimes and should be allowed to eventually succeed.
	HTTPClient *http.Client

	// MinTTL is the minimum cache duration. Server values below this are raised.
	// The floor case uses MinTTL as the stale time and MinTTL*2 as expiry.
	// Defaults to 1 minute.
	MinTTL time.Duration

	// MaxTTL is the maximum cache duration. Server values above this are clamped.
	// Defaults to 24 hours.
	MaxTTL time.Duration

	// TTL is the cache duration used when the server provides no Cache-Control
	// max-age header. Defaults to 15 minutes.
	TTL time.Duration

	// InitialKeys pre-populate the cache as immediately expired on the first
	// call to Verifier. Combined with a positive RefreshTimeout, they are
	// served while a background refresh fetches fresh keys.
	InitialKeys []jwt.PublicKey

	fetchMu     sync.Mutex // held during HTTP fetch
	ctrlMu      sync.Mutex // held briefly for refreshing/lastErr
	cached      atomic.Pointer[cachedVerifier]
	lastAsset   *asset // previous fetch result for conditional requests; guarded by fetchMu
	initOnce    sync.Once
	initErr     error         // stored by initOnce for subsequent callers
	refreshing  bool          // true while a background refresh goroutine is running
	refreshDone chan struct{} // closed when the current refresh completes
	lastErr     error         // last background refresh error; cleared on success
}

// NewKeyFetcher creates a [KeyFetcher] with the given JWKS endpoint URL.
// Returns an error if the URL is not a valid absolute URL.
func NewKeyFetcher(jwksURL string) (*KeyFetcher, error) {
	u, err := url.Parse(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("keyfetch: invalid URL: %w", err)
	}
	if !u.IsAbs() {
		return nil, fmt.Errorf("keyfetch: URL must be absolute: %q", jwksURL)
	}
	return &KeyFetcher{URL: jwksURL}, nil
}

// RefreshedAt returns the time the cached keys were last successfully
// fetched. Returns the zero time if no fetch has completed yet.
//
// Use this to detect when keys have changed - for example, to persist
// them to disk only when they've been updated.
func (f *KeyFetcher) RefreshedAt() time.Time {
	ci := f.cached.Load()
	if ci == nil {
		return time.Time{}
	}
	return ci.refreshedAt
}

// Verifier returns a [*jwt.Verifier] for verifying tokens.
//
// Verifier intentionally does not take a [context.Context]: the background
// JWKS refresh must not be canceled when a single client request finishes
// or times out. The HTTP client's own Timeout (or a 30s default) bounds
// the fetch duration instead.
//
// Cache staleness and expiry are determined by the wall clock (time.Now).
// This is intentional: cache management is runtime infrastructure, not
// claim validation. For testable time-based claim checks, see
// [jwt.Validator.Validate] which accepts a caller-supplied time.
//
// Fresh (before stale time): returned immediately, no network call.
//
// Stale (past stale time, before hard expiry): returned immediately.
// A background refresh is started if one is not already running.
//
// Expired (past hard expiry, RefreshTimeout > 0): a refresh is started
// and Verifier waits up to RefreshTimeout. If the refresh completes in
// time, fresh keys are returned. Otherwise, expired keys are returned.
//
// No cache or expired with RefreshTimeout=0: blocks until a fetch completes.
func (f *KeyFetcher) Verifier() (*jwt.Verifier, error) {
	if len(f.InitialKeys) > 0 {
		f.initOnce.Do(func() {
			v, err := jwt.NewVerifier(f.InitialKeys)
			if err != nil {
				f.initErr = err
				return
			}
			now := time.Now()
			ci := &cachedVerifier{
				verifier: v,
				staleAt:  now, // immediately expired - triggers refresh
				hardExp:  now,
			}
			f.cached.Store(ci)
		})
		f.ctrlMu.Lock()
		if f.initErr != nil {
			err := f.initErr
			f.initErr = nil // allow subsequent calls to fall through to fetch
			f.ctrlMu.Unlock()
			return nil, fmt.Errorf("InitialKeys: %w", err)
		}
		f.ctrlMu.Unlock()
	}

	now := time.Now()
	ci := f.cached.Load()

	// Fast path: fresh keys (before stale time).
	if ci != nil && now.Before(ci.staleAt) {
		return ci.verifier, nil
	}

	// Stale path: keys still valid, return immediately and refresh in
	// the background. No lock contention - ensureRefreshing holds ctrlMu
	// only briefly.
	if ci != nil && now.Before(ci.hardExp) {
		f.ensureRefreshing()
		return ci.verifier, nil
	}

	// Expired with timeout: wait for the refresh, fall back to expired keys.
	if ci != nil && f.RefreshTimeout > 0 {
		done := f.ensureRefreshing()
		timer := time.NewTimer(f.RefreshTimeout)
		defer timer.Stop()
		select {
		case <-done:
			if newCI := f.cached.Load(); newCI != nil && time.Now().Before(newCI.staleAt) {
				return newCI.verifier, nil
			}
		case <-timer.C:
		}
		// Timeout or refresh failed - return expired keys with error.
		f.ctrlMu.Lock()
		lastErr := f.lastErr
		f.ctrlMu.Unlock()
		if lastErr != nil {
			return ci.verifier, errors.Join(ErrKeysExpired, lastErr)
		}
		return ci.verifier, ErrKeysExpired
	}

	// Blocking path: no usable cache - wait for a fetch.
	// fetchMu serializes concurrent blocking callers; the re-check prevents
	// a redundant fetch if another goroutine already refreshed.
	f.fetchMu.Lock()
	defer f.fetchMu.Unlock()

	// Re-check after acquiring lock - another goroutine may have refreshed.
	now = time.Now()
	if ci := f.cached.Load(); ci != nil && now.Before(ci.staleAt) {
		return ci.verifier, nil
	}

	return f.fetch()
}

// ensureRefreshing starts a background refresh if one is not already running.
// Returns a channel that is closed when the current refresh completes.
func (f *KeyFetcher) ensureRefreshing() <-chan struct{} {
	f.ctrlMu.Lock()
	defer f.ctrlMu.Unlock()
	if !f.refreshing {
		f.refreshing = true
		f.refreshDone = make(chan struct{})
		go f.backgroundRefresh()
	}
	return f.refreshDone
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
	if ci := f.cached.Load(); ci != nil && now.Before(ci.staleAt) {
		f.ctrlMu.Lock()
		f.refreshing = false
		close(f.refreshDone)
		f.ctrlMu.Unlock()
		return
	}

	_, err := f.fetch()
	f.ctrlMu.Lock()
	f.refreshing = false
	close(f.refreshDone)
	if err != nil {
		f.lastErr = err
	} else {
		f.lastErr = nil
	}
	f.ctrlMu.Unlock()
}

// policy returns a cachePolicy from the fetcher's fields, falling back
// to package defaults for zero values.
func (f *KeyFetcher) policy() cachePolicy {
	p := defaultPolicy()
	if f.MinTTL > 0 {
		p.minTTL = f.MinTTL
	}
	if f.MaxTTL > 0 {
		p.maxTTL = f.MaxTTL
	}
	if f.TTL > 0 {
		p.defaultTTL = f.TTL
	}
	return p
}

// fetch performs the HTTP request and stores the result. Must be called with fetchMu held.
func (f *KeyFetcher) fetch() (*jwt.Verifier, error) {
	// Apply a context timeout only when no HTTPClient timeout is set,
	// avoiding a redundant double-timeout.
	ctx := context.Background()
	if f.HTTPClient == nil || f.HTTPClient.Timeout <= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	a, keys, err := fetchJWKS(ctx, f.URL, f.HTTPClient, f.policy(), f.lastAsset)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", f.URL, err)
	}
	f.lastAsset = a

	v, err := jwt.NewVerifier(keys)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", f.URL, err)
	}

	ci := &cachedVerifier{
		verifier:    v,
		staleAt:     a.stale,
		hardExp:     a.expiry,
		refreshedAt: time.Now(),
	}
	f.cached.Store(ci)
	return ci.verifier, nil
}
