package httpcache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sync/singleflight"
)

// Sentinel errors returned by Fetch; wrap with errors.Is to branch on the
// failure mode. The wrapped error always includes the URL or Path context.
var (
	// ErrUnexpectedStatus is returned when the server replies with a
	// non-200, non-304 response.
	ErrUnexpectedStatus = errors.New("unexpected response status")

	// ErrEmptyResponse is returned when a 200 response body is zero bytes.
	ErrEmptyResponse = errors.New("empty response body")

	// ErrSaveMeta is returned when the .meta sidecar cannot be written
	// after a successful body download (updated is still true).
	ErrSaveMeta = errors.New("save meta sidecar")

	// ErrBodyTooLarge is returned when the response body exceeds MaxBytes.
	ErrBodyTooLarge = errors.New("response body exceeds MaxBytes")

	// ErrPeerFetching is returned when another process holds the .tmp
	// download file (O_EXCL conflict). The returned `updated` is true if
	// the peer has installed a different version since our last known
	// state — callers can reload Path from disk and skip their own fetch.
	ErrPeerFetching = errors.New("another process is fetching")
)

const (
	defaultConnTimeout = 5 * time.Second // TCP connect + TLS handshake
	defaultTimeout     = 5 * time.Minute // overall including body read
)

// Cacher fetches a URL to a local file, using ETag/Last-Modified to skip
// unchanged responses.
//
// Rate limiting — two independent gates, both checked before any HTTP:
//   - MaxAge: skips if the local file's mtime is within this duration.
//     Useful when the remote preserves meaningful timestamps (e.g. MaxMind
//     encodes the database release date as the tar entry mtime).
//   - MinInterval: skips if Fetch was called within this duration (in-memory).
//     Guards against tight poll loops hammering a rate-limited API.
//
// Caching — ETag and Last-Modified values are persisted to a <path>.meta
// sidecar file so conditional GETs survive process restarts.
//
// Header — any values in Header are sent on every request. The stdlib
// http.Client strips Authorization, WWW-Authenticate, and Cookie on
// cross-host redirects; custom-named credential headers (X-API-Key,
// PRIVATE-TOKEN, …) are forwarded. If you set those, supply your own
// *http.Client with a CheckRedirect that strips them.
//
// MaxBytes — caps the response body. A hostile or compromised upstream
// (or a redirect target on another origin) can otherwise stream until the
// disk fills, since the overall Timeout still allows multi-GB transfers.
// 0 disables the cap.
type Cacher struct {
	URL         string
	Path        string
	MaxAge      time.Duration // 0 disables; skip HTTP if file mtime is within this
	MinInterval time.Duration // 0 disables; skip HTTP if last Fetch attempt was within this
	MaxBytes    int64         // 0 disables; cap on body bytes read per Fetch (defends against fill-disk)
	Header      http.Header   // headers sent on every request

	sf          singleflight.Group
	etag        string
	lastMod     string
	lastChecked time.Time
	metaLoaded  bool
	client      *http.Client // set by New/NewWith; reuses connections across Fetch calls
}

// cacheMeta is the sidecar format persisted alongside the downloaded file.
type cacheMeta struct {
	ETag    string `json:"etag,omitempty"`
	LastMod string `json:"last_modified,omitempty"`
}

func (c *Cacher) metaPath() string { return c.Path + ".meta" }

// safeURL returns c.URL with any userinfo (user:password@) stripped, so
// errors and logs don't leak credentials embedded in the URL. Falls back
// to "<unparseable URL>" rather than echoing the raw value if parsing
// fails (defensive — a URL we can't parse may itself be a credential).
func (c *Cacher) safeURL() string {
	u, err := url.Parse(c.URL)
	if err != nil {
		return "<unparseable URL>"
	}
	u.User = nil
	return u.String()
}

// loadMeta reads etag/lastMod from the sidecar file. A missing sidecar is
// not an error (just means a full download next time); read or parse errors
// propagate so the caller can decide whether to abort or proceed.
func (c *Cacher) loadMeta() error {
	data, err := os.ReadFile(c.metaPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var m cacheMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse %s: %w", c.metaPath(), err)
	}
	c.etag = m.ETag
	c.lastMod = m.LastMod
	return nil
}

// saveMeta writes etag/lastMod to the sidecar file atomically.
func (c *Cacher) saveMeta() error {
	m := cacheMeta{ETag: c.etag, LastMod: c.lastMod}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := c.metaPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.metaPath()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// New creates a Cacher with a default *http.Client (5s connect, 5m overall).
// Equivalent to NewWith(url, path, nil). Header is read live on every request,
// so it may be set or modified after New.
func New(url, path string) *Cacher {
	return NewWith(url, path, nil)
}

// NewWith creates a Cacher backed by the given *http.Client; pass nil for
// defaults. The client is used as-is — its Timeout, Transport, Jar, and
// CheckRedirect are all the caller's responsibility.
func NewWith(url, path string, client *http.Client) *Cacher {
	if client == nil {
		client = &http.Client{
			Timeout: defaultTimeout,
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: defaultConnTimeout}).DialContext,
				TLSHandshakeTimeout: defaultConnTimeout,
			},
		}
	}
	return &Cacher{URL: url, Path: path, client: client}
}

// Fetch sends a conditional GET and writes new content to Path if the server
// responds with 200. Returns whether the file was updated.
//
// Both MaxAge and MinInterval are checked before making any HTTP request.
// ctx cancels the in-flight request and any blocking body read.
//
// Safe to call concurrently — concurrent callers share a single in-flight
// fetch (via singleflight) and all receive the same result.
func (c *Cacher) Fetch(ctx context.Context) (updated bool, err error) {
	// MaxAge: file-mtime gate (no lock needed — just a stat).
	if c.MaxAge > 0 {
		if info, err := os.Stat(c.Path); err == nil {
			if time.Since(info.ModTime()) < c.MaxAge {
				return false, nil
			}
		}
	}

	type result struct {
		updated bool
		err     error
	}
	v, _, _ := c.sf.Do("fetch", func() (any, error) {
		u, err := c.fetch(ctx)
		return result{u, err}, nil
	})
	r := v.(result)
	return r.updated, r.err
}

// fetch is the inner serialized work. singleflight ensures only one runs at
// a time, so the etag/lastMod/lastChecked/metaLoaded fields don't need a mutex.
func (c *Cacher) fetch(ctx context.Context) (bool, error) {
	// Load sidecar once so conditional GETs work after a process restart.
	if !c.metaLoaded {
		if err := c.loadMeta(); err != nil {
			return false, err
		}
		c.metaLoaded = true
	}

	// MinInterval: in-memory last-checked gate.
	if c.MinInterval > 0 && !c.lastChecked.IsZero() {
		if time.Since(c.lastChecked) < c.MinInterval {
			return false, nil
		}
	}
	c.lastChecked = time.Now()

	// Reserve .tmp before any HTTP — O_EXCL gives us cross-process
	// exclusion (singleflight only covers the in-process case). A peer
	// holding .tmp means another process is mid-download; return early
	// without hitting the wire.
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return false, err
	}
	tmp := c.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Peer holds .tmp. Re-read sidecar; if peer has installed a
			// different version, signal updated=true so the caller can
			// reload Path from disk.
			prevETag, prevLM := c.etag, c.lastMod
			if err := c.loadMeta(); err != nil {
				return false, err
			}
			updated := c.etag != prevETag || c.lastMod != prevLM
			return updated, fmt.Errorf("%w for %s", ErrPeerFetching, c.safeURL())
		}
		return false, err
	}
	// Any non-success path from here must remove tmp so peers aren't blocked.
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			os.Remove(tmp)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		f.Close()
		return false, err
	}

	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	} else if c.lastMod != "" {
		req.Header.Set("If-Modified-Since", c.lastMod)
	}

	for k, vs := range c.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		f.Close()
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		f.Close()
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		f.Close()
		return false, fmt.Errorf("%w %d fetching %s", ErrUnexpectedStatus, resp.StatusCode, c.safeURL())
	}

	body := io.Reader(resp.Body)
	if c.MaxBytes > 0 {
		// +1 so n>MaxBytes signals "exceeded" without an extra Read.
		body = io.LimitReader(resp.Body, c.MaxBytes+1)
	}
	n, err := io.Copy(f, body)
	f.Close()
	if err != nil {
		return false, err
	}
	if c.MaxBytes > 0 && n > c.MaxBytes {
		return false, fmt.Errorf("%w (%d > %d) from %s", ErrBodyTooLarge, n, c.MaxBytes, c.safeURL())
	}
	if n == 0 {
		return false, fmt.Errorf("%w from %s", ErrEmptyResponse, c.safeURL())
	}
	if err := os.Rename(tmp, c.Path); err != nil {
		return false, err
	}
	cleanupTmp = false // rename consumed it

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.etag = etag
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		c.lastMod = lm
	}
	if err := c.saveMeta(); err != nil {
		return true, fmt.Errorf("%w for %s: %w", ErrSaveMeta, c.Path, err)
	}

	return true, nil
}
