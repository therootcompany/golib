package httpcache

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const defaultTimeout = 30 * time.Second

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
// Auth — Username/Password sets HTTP Basic Auth on the initial request only.
// The Authorization header is stripped before following any redirect, so
// presigned redirect targets (e.g. Cloudflare R2) never receive credentials.
//
// Transform — if set, called with the response body instead of the default
// atomic file copy. The func is responsible for writing to path atomically.
// Use this for archives (e.g. extracting a .mmdb from a MaxMind tar.gz).
type Cacher struct {
	URL         string
	Path        string
	Timeout     time.Duration // 0 uses 30s
	MaxAge      time.Duration // 0 disables; skip HTTP if file mtime is within this
	MinInterval time.Duration // 0 disables; skip HTTP if last Fetch attempt was within this
	Username    string        // Basic Auth — not forwarded on redirects
	Password    string
	Transform   func(r io.Reader, path string) error // nil = direct atomic copy

	mu          sync.Mutex
	etag        string
	lastMod     string
	lastChecked time.Time
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

	// MinInterval: in-memory last-checked gate.
	if c.MinInterval > 0 && !c.lastChecked.IsZero() {
		if time.Since(c.lastChecked) < c.MinInterval {
			return false, nil
		}
	}
	c.lastChecked = time.Now()

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

	var client *http.Client
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
		// Strip auth before following any redirect — presigned URLs (e.g. R2)
		// must not receive our credentials.
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				req.Header.Del("Authorization")
				return nil
			},
		}
	} else {
		client = &http.Client{Timeout: timeout}
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
		if _, err := io.Copy(f, resp.Body); err != nil {
			f.Close()
			os.Remove(tmp)
			return false, err
		}
		f.Close()
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

	return true, nil
}
