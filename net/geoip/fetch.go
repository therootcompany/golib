package geoip

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/https"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/sync/cacheable"
)

const (
	DefaultFailureBackoff = 6 * time.Hour
	DefaultRefreshTimeout = 24*time.Hour + time.Minute + 7*time.Second
)

// GeoIPDB downloads the GeoLite2 archives named by a GeoIP.conf. It
// implements dataset.Upstream and keeps freshness/backoff policy in the
// httpcache layer.
type GeoIPDB struct {
	ConfPath       string
	Dir            string
	BaseURL        string
	FreshDays      int
	FailureBackoff time.Duration
	RefreshTimeout time.Duration
	HTTPClient     *http.Client

	conf       *Conf
	auth       http.Header
	maxAge     time.Duration
	cachers    []*httpcache.Cacher
	current    atomic.Pointer[Databases]
	start      sync.Once
	generation atomic.Uint64
	cancel     context.CancelFunc
	loadedAt   atomic.Pointer[time.Time]
	lastErr    atomic.Pointer[error]
	refresh    cacheable.Refresh
	local      bool
}

// NewGeoIPDB parses confPath and creates a fetcher for its editions.
func NewGeoIPDB(confPath string) (*GeoIPDB, error) {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}
	conf, err := ParseConf(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", confPath, err)
	}
	if len(conf.EditionIDs) == 0 {
		return nil, fmt.Errorf("no EditionIDs found in %s", confPath)
	}
	dir := conf.DatabaseDirectory
	if dir == "" {
		dir = "."
	}
	return &GeoIPDB{ConfPath: confPath, Dir: dir, BaseURL: conf.BaseURL, conf: conf}, nil
}

func (f *GeoIPDB) ready() error {
	if f.auth != nil {
		return nil
	}
	f.auth = http.Header{"Authorization": []string{
		"Basic " + base64.StdEncoding.EncodeToString([]byte(f.conf.AccountID+":"+f.conf.LicenseKey)),
	}}
	freshDays := f.FreshDays
	if freshDays <= 0 {
		freshDays = 3
	}
	f.maxAge = time.Duration(freshDays) * 24 * time.Hour
	backoff := f.FailureBackoff
	if backoff == 0 {
		backoff = DefaultFailureBackoff
	}
	base := f.BaseURL
	if base == "" {
		base = DownloadBase
	}
	client := f.HTTPClient
	if client == nil {
		client = https.NewSlowClient(5 * time.Minute)
	}
	f.cachers = make([]*httpcache.Cacher, 0, len(f.conf.EditionIDs))
	for _, edition := range f.conf.EditionIDs {
		path := filepath.Join(f.Dir, TarGzName(edition))
		cacher := httpcache.NewWith(base+"/"+edition+"/download?suffix=tar.gz", path, client)
		cacher.MaxAge = f.maxAge
		cacher.FailureBackoff = backoff
		cacher.Header = f.auth
		f.cachers = append(f.cachers, cacher)
	}
	return nil
}

// Fetch downloads all configured editions and reports whether any changed.
var (
	_ cacheable.Cacheable[Databases] = (*GeoIPDB)(nil)
	_ cacheable.Mutable[Databases]   = (*GeoIPDB)(nil)
	_ cacheable.Inspectable          = (*GeoIPDB)(nil)
	_ cacheable.Tickable             = (*GeoIPDB)(nil)
)

// Current returns the newest completed City+ASN snapshot without blocking.
func (f *GeoIPDB) Current() *Databases {
	return f.current.Load()
}

// Due reports whether the source should be revalidated. The fetcher
// delegates freshness checks to httpcache, so this is deliberately cheap.
func (f *GeoIPDB) Due(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	status := f.Status()
	return !status.HasValue || status.StaleAt.IsZero() || !time.Now().Before(status.StaleAt), nil
}

// Revalidate fetches archives when stale and publishes City and ASN together.
func (f *GeoIPDB) Revalidate(ctx context.Context) (started bool, err error) {
	due, err := f.Due(ctx)
	if err != nil || !due {
		return false, err
	}
	if !f.refresh.Begin() {
		return false, nil
	}
	go func() {
		timeout := f.RefreshTimeout
		if timeout <= 0 {
			timeout = DefaultRefreshTimeout
		}
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		f.refresh.Finish(f.update(refreshCtx))
	}()
	return true, nil
}

func (f *GeoIPDB) update(ctx context.Context) error {
	generation := f.generation.Load()
	changed, err := f.Update(ctx)
	if err != nil {
		errCopy := err
		f.lastErr.Store(&errCopy)
		return err
	}
	if !changed && f.current.Load() != nil {
		return nil
	}
	databases, err := Open(f.Dir)
	if err != nil {
		return err
	}
	if f.generation.Load() != generation {
		_ = databases.Close()
		return nil
	}
	previous := f.current.Swap(databases)
	if previous != nil {
		_ = previous.Close()
	}
	now := time.Now()
	f.loadedAt.Store(&now)
	f.lastErr.Store(nil)
	return nil
}

func (f *GeoIPDB) Set(databases *Databases) error {
	f.generation.Add(1)
	previous := f.current.Swap(databases)
	if previous != nil && previous != databases {
		_ = previous.Close()
	}
	if databases != nil {
		now := time.Now()
		f.loadedAt.Store(&now)
	} else {
		f.loadedAt.Store(nil)
	}
	return nil
}

func (f *GeoIPDB) Clear() error {
	return f.Set(nil)
}

func (f *GeoIPDB) Status() cacheable.Status {
	loadedAt := time.Time{}
	if t := f.loadedAt.Load(); t != nil {
		loadedAt = *t
	}
	var lastErr error
	if p := f.lastErr.Load(); p != nil {
		lastErr = *p
	}
	status := cacheable.Status{LoadedAt: loadedAt, HasValue: f.Current() != nil, Refreshing: f.refresh.Running(), LastError: lastErr}
	if !loadedAt.IsZero() && f.maxAge > 0 {
		status.StaleAt = loadedAt.Add(f.maxAge)
	}
	return status
}

// Load returns the newest completed snapshot. A failed refresh keeps the last
// good snapshot, but is returned to the caller for observability.
func (f *GeoIPDB) Load(ctx context.Context, wait bool) (*Databases, error) {
	if _, err := f.Revalidate(ctx); err != nil {
		return f.Current(), err
	}
	if f.Current() == nil || wait {
		if err := f.refresh.Wait(ctx); err != nil {
			return f.Current(), err
		}
	}
	return f.Current(), nil
}

// Start starts at most one optional background revalidation ticker.
func (f *GeoIPDB) Start(ctx context.Context, interval time.Duration) {
	f.start.Do(func() {
		if interval <= 0 {
			interval = time.Hour
		}
		tickCtx, cancel := context.WithCancel(ctx)
		f.cancel = cancel
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-tickCtx.Done():
					return
				case <-ticker.C:
					_, _ = f.Revalidate(tickCtx)
				}
			}
		}()
	})
}

// Stop stops the optional background ticker and waits for any in-flight
// refresh to finish or reach RefreshTimeout. It is safe to call repeatedly.
func (f *GeoIPDB) Stop() error {
	if f == nil {
		return nil
	}
	if f.cancel != nil {
		f.cancel()
	}
	timeout := f.RefreshTimeout
	if timeout <= 0 {
		timeout = DefaultRefreshTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return f.refresh.Stop(ctx)
}

func NewLocalGeoIPDB(dir string) *GeoIPDB {
	return &GeoIPDB{Dir: dir, local: true, maxAge: time.Hour}
}

func (f *GeoIPDB) Update(ctx context.Context) (bool, error) {
	if f.local {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if f.Current() != nil {
			return true, nil
		}
	} else if err := f.ready(); err != nil {
		return false, err
	}
	updated := false
	for _, cacher := range f.cachers {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		u, err := cacher.Update(ctx)
		if err != nil {
			return false, err
		}
		updated = updated || u
	}
	return updated, nil
}
