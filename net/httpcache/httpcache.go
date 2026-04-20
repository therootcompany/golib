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
type Cacher struct {
	URL     string
	Path    string
	Timeout time.Duration // 0 uses 30s

	mu      sync.Mutex
	etag    string
	lastMod string
}

// New creates a Cacher that fetches URL and writes it to path.
func New(url, path string) *Cacher {
	return &Cacher{URL: url, Path: path}
}

// Fetch sends a conditional GET and writes new content to Path if the server
// responds with 200. Returns whether the file was updated.
func (c *Cacher) Fetch() (updated bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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

	client := &http.Client{Timeout: timeout}
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

	// Write to a temp file then rename for an atomic swap.
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

	if etag := resp.Header.Get("ETag"); etag != "" {
		c.etag = etag
	}
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		c.lastMod = lm
	}

	return true, nil
}
