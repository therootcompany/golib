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
// unchanged responses. Calls registered callbacks when the file changes.
type Cacher struct {
	URL     string
	Path    string
	Timeout time.Duration // 0 uses 30s

	mu        sync.Mutex
	etag      string
	lastMod   string
	callbacks []func() error
}

// New creates a Cacher that fetches URL and writes it to path.
func New(url, path string) *Cacher {
	return &Cacher{URL: url, Path: path}
}

// Register adds a callback invoked after each successful fetch.
func (c *Cacher) Register(fn func() error) {
	c.callbacks = append(c.callbacks, fn)
}

// Init fetches the URL unconditionally (no cached headers yet) and invokes
// all callbacks, ensuring files are loaded on startup.
func (c *Cacher) Init() error {
	if _, err := c.fetch(); err != nil {
		return err
	}
	return c.invokeCallbacks()
}

// Sync sends a conditional GET. If the server returns new content, writes it
// to Path and invokes callbacks. Returns whether the file was updated.
func (c *Cacher) Sync() (updated bool, err error) {
	updated, err = c.fetch()
	if err != nil || !updated {
		return updated, err
	}
	return true, c.invokeCallbacks()
}

func (c *Cacher) fetch() (updated bool, err error) {
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

func (c *Cacher) invokeCallbacks() error {
	for _, fn := range c.callbacks {
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "error: reload callback: %v\n", err)
		}
	}
	return nil
}
