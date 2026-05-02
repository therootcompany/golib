package httpcache

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
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
)

// BasicAuth returns an HTTP Basic Authorization header value:
// "Basic " + base64(user:pass). Pair with the "Authorization" header in
// Cacher.Header.
func BasicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// Bearer returns a Bearer Authorization header value: "Bearer " + token.
// Pair with the "Authorization" header in Cacher.Header.
func Bearer(token string) string {
	return "Bearer " + token
}

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
// Header — any values in Header are sent on every request. Every header
// in Header is stripped before following redirects (so credential-bearing
// names like Authorization, X-API-Key, PRIVATE-TOKEN never reach a
// presigned S3/R2 URL or other third-party origin). The BasicAuth and
// Bearer helpers produce Authorization values for the common cases.
//
// MaxBytes — caps the response body. A hostile or compromised upstream
// (or a redirect target on another origin) can otherwise stream until the
// disk fills, since the overall Timeout still allows multi-GB transfers.
// 0 disables the cap.
type Cacher struct {
	URL         string
	Path        string
	ConnTimeout time.Duration // 0 uses 5s;  caps TCP connect + TLS handshake
	Timeout     time.Duration // 0 uses 5m;  caps overall request including body read
	MaxAge      time.Duration // 0 disables; skip HTTP if file mtime is within this
	MinInterval time.Duration // 0 disables; skip HTTP if last Fetch attempt was within this
	MaxBytes    int64         // 0 disables; cap on body bytes read per Fetch (defends against fill-disk)
	Header      http.Header   // headers sent on every request (Authorization is stripped on redirect)

	mu          sync.Mutex
	etag        string
	lastMod     string
	lastChecked time.Time
	metaLoaded  bool
	client      *http.Client // built by New; reuses connections across Fetch calls
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

// loadMeta reads etag/lastMod from the sidecar file. Errors are silently
// ignored — a missing or corrupt sidecar just means a full download next time.
func (c *Cacher) loadMeta() {
	data, err := os.ReadFile(c.metaPath())
	if err != nil {
		return
	}
	var m cacheMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return
	}
	c.etag = m.ETag
	c.lastMod = m.LastMod
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

// New creates a Cacher that fetches URL and writes it to path. The
// underlying *http.Client is built here; ConnTimeout and Timeout are
// resolved at this point, so set them on the struct (or use NewWith)
// before further use. Header is read live on every request, so it may
// be set or modified after New.
func New(url, path string) *Cacher {
	c := &Cacher{URL: url, Path: path}
	c.client = newClient(c, defaultConnTimeout, defaultTimeout)
	return c
}

// NewWith creates a Cacher with explicit timeouts so the client is built
// once with caller-chosen values. Pass 0 to accept the default for either.
func NewWith(url, path string, connTimeout, timeout time.Duration) *Cacher {
	if connTimeout == 0 {
		connTimeout = defaultConnTimeout
	}
	if timeout == 0 {
		timeout = defaultTimeout
	}
	c := &Cacher{
		URL:         url,
		Path:        path,
		ConnTimeout: connTimeout,
		Timeout:     timeout,
	}
	c.client = newClient(c, connTimeout, timeout)
	return c
}

// newClient builds the *http.Client used for every Fetch. The CheckRedirect
// closure captures c, so c.Header changes after construction are picked up
// on each request.
func newClient(c *Cacher, connTimeout, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: connTimeout}).DialContext,
			TLSHandshakeTimeout: connTimeout,
		},
		// Strip every key in c.Header (Authorization, X-API-Key, …)
		// before following any redirect — redirect targets must not
		// receive our credentials. Also bound the redirect chain.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			for k := range c.Header {
				req.Header.Del(k)
			}
			return nil
		},
	}
}

// Fetch sends a conditional GET and writes new content to Path if the server
// responds with 200. Returns whether the file was updated.
//
// Both MaxAge and MinInterval are checked before making any HTTP request.
// ctx cancels the in-flight request and any blocking body read.
func (c *Cacher) Fetch(ctx context.Context) (updated bool, err error) {
	// MaxAge: file-mtime gate (no lock needed — just a stat).
	if c.MaxAge > 0 {
		if info, err := os.Stat(c.Path); err == nil {
			if time.Since(info.ModTime()) < c.MaxAge {
				return false, nil
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Load sidecar once so conditional GETs work after a process restart.
	if !c.metaLoaded {
		c.loadMeta()
		c.metaLoaded = true
	}

	// MinInterval: in-memory last-checked gate.
	if c.MinInterval > 0 && !c.lastChecked.IsZero() {
		if time.Since(c.lastChecked) < c.MinInterval {
			return false, nil
		}
	}
	c.lastChecked = time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
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
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%w %d fetching %s", ErrUnexpectedStatus, resp.StatusCode, c.safeURL())
	}

	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return false, err
	}
	tmp := c.Path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return false, err
	}
	body := io.Reader(resp.Body)
	if c.MaxBytes > 0 {
		// +1 so n>MaxBytes signals "exceeded" without an extra Read.
		body = io.LimitReader(resp.Body, c.MaxBytes+1)
	}
	n, err := io.Copy(f, body)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return false, err
	}
	if c.MaxBytes > 0 && n > c.MaxBytes {
		os.Remove(tmp)
		return false, fmt.Errorf("%w (%d > %d) from %s", ErrBodyTooLarge, n, c.MaxBytes, c.safeURL())
	}
	if n == 0 {
		os.Remove(tmp)
		return false, fmt.Errorf("%w from %s", ErrEmptyResponse, c.safeURL())
	}
	if err := os.Rename(tmp, c.Path); err != nil {
		os.Remove(tmp)
		return false, err
	}

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
