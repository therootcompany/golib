package httpcache

import (
	"context"
	"encoding/base64"
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
	"strconv"
	"strings"
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
//   - FailureBackoff: skips if the last fetch failure was within this duration.
//     0 follows MaxAge; negative disables local failure backoff. A valid
//     Retry-After response always takes precedence.
//   - MinInterval: skips if Fetch was called within this duration (in-memory).
//     Guards against tight poll loops hammering a rate-limited API.
//
// Caching — ETag, Last-Modified, and failure retry times are persisted to a
// <path>.meta sidecar file so conditional GETs and backoff survive restarts.
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
	URL            string
	Path           string
	MaxAge         time.Duration // 0 disables; skip HTTP if file mtime is within this
	FailureBackoff time.Duration // 0 follows MaxAge; <0 disables local failure backoff
	MinInterval    time.Duration // 0 disables; skip HTTP if last Fetch attempt was within this
	MaxBytes       int64         // 0 disables; cap on body bytes read per Fetch (defends against fill-disk)
	Header         http.Header   // headers sent on every request

	sf          singleflight.Group
	cacheMeta   // embedded: etag/lastMod persisted to sidecar
	lastChecked time.Time
	metaLoaded  bool
	client      *http.Client // set by New/NewWith; reuses connections across Fetch calls
}

// cacheMeta is the sidecar format persisted alongside the downloaded file.
type cacheMeta struct {
	ETag        string     `json:"etag,omitempty"`
	LastMod     string     `json:"last_modified,omitempty"`
	LastFailure *time.Time `json:"last_failure,omitempty"`
	RetryAt     *time.Time `json:"retry_at,omitempty"`
}

func (c *Cacher) metaPath() string { return c.Path + ".meta" }

// BasicAuth returns an HTTP Basic Authorization header value.
func BasicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// Bearer returns a Bearer Authorization header value.
func Bearer(token string) string {
	return "Bearer " + token
}

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
	if err := json.Unmarshal(data, &c.cacheMeta); err != nil {
		return fmt.Errorf("parse %s: %w", c.metaPath(), err)
	}
	return nil
}

// saveMeta writes etag/lastMod to the sidecar file atomically.
func (c *Cacher) saveMeta() error {
	data, err := json.Marshal(c.cacheMeta)
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
// MaxAge, FailureBackoff, and MinInterval are checked before making any HTTP request.
// ctx cancels the in-flight request and any blocking body read.
//
// Safe to call concurrently — concurrent callers share a single in-flight
// fetch (via singleflight) and all receive the same result.
func (c *Cacher) Fetch(ctx context.Context) (updated bool, err error) {
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
// a time, so the cacheMeta/lastChecked/metaLoaded fields don't need a mutex.
func (c *Cacher) fetch(ctx context.Context) (updated bool, err error) {
	// Load sidecar once so conditional GETs and failure backoff work after a
	// process restart.
	if !c.metaLoaded {
		if err := c.loadMeta(); err != nil {
			return false, err
		}
		c.metaLoaded = true
	}

	// MaxAge: file-mtime gate.
	if c.MaxAge > 0 {
		if info, statErr := os.Stat(c.Path); statErr == nil && time.Since(info.ModTime()) < c.MaxAge {
			return false, nil
		}
	}
	// FailureBackoff: persisted failure gate. This prevents a stale file from
	// causing a tight retry loop against a rate-limited server.
	if c.RetryAt != nil {
		if time.Now().Before(*c.RetryAt) {
			return false, nil
		}
	} else {
		failureBackoff := c.FailureBackoff
		if failureBackoff == 0 {
			failureBackoff = c.MaxAge
		}
		if failureBackoff > 0 && c.LastFailure != nil && time.Since(*c.LastFailure) < failureBackoff {
			return false, nil
		}
	}

	// MinInterval: in-memory last-checked gate.
	if c.MinInterval > 0 && !c.lastChecked.IsZero() {
		if time.Since(c.lastChecked) < c.MinInterval {
			return false, nil
		}
	}
	c.lastChecked = time.Now()
	var retryAt *time.Time
	defer func() {
		if err != nil {
			err = c.recordFailure(err, retryAt)
		}
	}()

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
			prevETag, prevLM := c.ETag, c.LastMod
			if err := c.loadMeta(); err != nil {
				return false, err
			}
			updated := c.ETag != prevETag || c.LastMod != prevLM
			return updated, fmt.Errorf("%w for %s", ErrPeerFetching, c.safeURL())
		}
		return false, err
	}
	// Any non-success path from here must remove tmp so peers aren't blocked.
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return false, err
	}

	if c.ETag != "" {
		req.Header.Set("If-None-Match", c.ETag)
	} else if c.LastMod != "" {
		req.Header.Set("If-Modified-Since", c.LastMod)
	}

	for k, vs := range c.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		c.LastFailure = nil
		c.RetryAt = nil
		if err := c.saveMeta(); err != nil {
			return false, fmt.Errorf("%w for %s: %w", ErrSaveMeta, c.Path, err)
		}
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		retryAt = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		return false, fmt.Errorf("%w %d fetching %s", ErrUnexpectedStatus, resp.StatusCode, c.safeURL())
	}

	body := io.Reader(resp.Body)
	if c.MaxBytes > 0 {
		// +1 so n>MaxBytes signals "exceeded" without an extra Read.
		body = io.LimitReader(resp.Body, c.MaxBytes+1)
	}
	n, err := io.Copy(f, body)
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

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.ETag = etag
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		c.LastMod = lm
	}
	c.LastFailure = nil
	c.RetryAt = nil
	if err := c.saveMeta(); err != nil {
		return true, fmt.Errorf("%w for %s: %w", ErrSaveMeta, c.Path, err)
	}

	return true, nil
}

func (c *Cacher) recordFailure(err error, retryAt *time.Time) error {
	if errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrPeerFetching) {
		return err
	}
	now := time.Now()
	c.LastFailure = &now
	c.RetryAt = retryAt
	if saveErr := c.saveMeta(); saveErr != nil {
		return errors.Join(err, fmt.Errorf("%w for %s: %w", ErrSaveMeta, c.Path, saveErr))
	}
	return err
}

func parseRetryAfter(value string, now time.Time) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 {
		t := now.Add(time.Duration(seconds) * time.Second)
		return &t
	}
	if t, err := http.ParseTime(value); err == nil {
		return &t
	}
	return nil
}
