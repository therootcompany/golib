package httpcache

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	defaultConnTimeout = 5 * time.Second // TCP connect + TLS handshake
	defaultTimeout     = 5 * time.Minute // overall including body read
)

// Syncer is implemented by any value that can fetch a remote resource and
// report whether it changed. Both *Cacher and *gitshallow.Repo satisfy this.
type Syncer interface {
	Fetch() (updated bool, err error)
}

// NopSyncer is a Syncer that always reports no update and no error.
// Use for datasets backed by local files managed externally (no download).
type NopSyncer struct{}

func (NopSyncer) Fetch() (bool, error) { return false, nil }

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
// Auth — AuthHeader/AuthValue set a request header on every attempt. Auth is
// stripped before following redirects so presigned targets (e.g. S3/R2 URLs)
// never receive credentials. Use any scheme: "Authorization"/"Bearer token",
// "X-API-Key"/"secret", "Authorization"/"Basic base64(user:pass)", etc.
//
// Transform — if set, called with the response body instead of the default
// atomic file copy. The func is responsible for writing to path atomically.
// Use this for archives (e.g. extracting a .mmdb from a MaxMind tar.gz).
type Cacher struct {
	URL         string
	Path        string
	ConnTimeout time.Duration // 0 uses 5s;  caps TCP connect + TLS handshake
	Timeout     time.Duration // 0 uses 5m;  caps overall request including body read
	MaxAge      time.Duration // 0 disables; skip HTTP if file mtime is within this
	MinInterval time.Duration // 0 disables; skip HTTP if last Fetch attempt was within this
	AuthHeader  string        // e.g. "Authorization" or "X-API-Key"
	AuthValue   string        // e.g. "Bearer token" or "Basic base64(user:pass)"
	Transform   func(r io.Reader, path string) error // nil = direct atomic copy

	mu          sync.Mutex
	etag        string
	lastMod     string
	lastChecked time.Time
	metaLoaded  bool
}

// cacheMeta is the sidecar format persisted alongside the downloaded file.
type cacheMeta struct {
	ETag    string `json:"etag,omitempty"`
	LastMod string `json:"last_modified,omitempty"`
}

func (c *Cacher) metaPath() string { return c.Path + ".meta" }

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
func (c *Cacher) saveMeta() {
	m := cacheMeta{ETag: c.etag, LastMod: c.lastMod}
	data, err := json.Marshal(m)
	if err != nil {
		return
	}
	tmp := c.metaPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return
	}
	os.Rename(tmp, c.metaPath())
}

// New creates a Cacher that fetches URL and writes it to path.
func New(url, path string) *Cacher {
	return &Cacher{URL: url, Path: path}
}

// Fetch sends a conditional GET and writes new content to Path if the server
// responds with 200. Returns whether the file was updated.
//
// Both MaxAge and MinInterval are checked before making any HTTP request.
func (c *Cacher) Fetch() (updated bool, err error) {
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

	connTimeout := c.ConnTimeout
	if connTimeout == 0 {
		connTimeout = defaultConnTimeout
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	req, err := http.NewRequest(http.MethodGet, c.URL, nil)
	if err != nil {
		return false, err
	}

	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	} else if c.lastMod != "" {
		req.Header.Set("If-Modified-Since", c.lastMod)
	}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: connTimeout}).DialContext,
		TLSHandshakeTimeout: connTimeout,
	}

	if c.AuthHeader != "" {
		req.Header.Set(c.AuthHeader, c.AuthValue)
	}

	client := &http.Client{Timeout: timeout, Transport: transport}
	if c.AuthHeader != "" {
		// Strip auth before following any redirect — redirect targets (e.g.
		// presigned S3/R2 URLs) must not receive our credentials.
		authHeader := c.AuthHeader
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			req.Header.Del(authHeader)
			return nil
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, c.URL)
	}

	if c.Transform != nil {
		if err := c.Transform(resp.Body, c.Path); err != nil {
			return false, err
		}
	} else {
		tmp := c.Path + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			return false, err
		}
		n, err := io.Copy(f, resp.Body)
		f.Close()
		if err != nil {
			os.Remove(tmp)
			return false, err
		}
		if n == 0 {
			os.Remove(tmp)
			return false, fmt.Errorf("empty response from %s", c.URL)
		}
		if err := os.Rename(tmp, c.Path); err != nil {
			os.Remove(tmp)
			return false, err
		}
	}

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.etag = etag
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		c.lastMod = lm
	}
	c.saveMeta()

	return true, nil
}
