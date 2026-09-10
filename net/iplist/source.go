package iplist

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/sync/cacheable"
)

const (
	DefaultRefreshInterval = time.Hour + 57*time.Minute + 13*time.Second
	DefaultRefreshTimeout  = 15 * time.Minute
)

type IPListConfig struct {
	Source          string
	CacheDir        string
	HTTPClient      *http.Client
	RefreshInterval time.Duration
	Optional        bool
	RefreshTimeout  time.Duration
}

type IPList struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     IPListConfig
	current    atomic.Pointer[[]string]
	start      sync.Once
	generation atomic.Uint64
	loadedAt   atomic.Pointer[time.Time]
	lastErr    atomic.Pointer[error]
	refresh    cacheable.Refresh
}

var (
	_ cacheable.Cacheable[[]string] = (*IPList)(nil)
	_ cacheable.Mutable[[]string]   = (*IPList)(nil)
	_ cacheable.Inspectable         = (*IPList)(nil)
	_ cacheable.Tickable            = (*IPList)(nil)
)

func NewIPList(ctx context.Context, config IPListConfig) (*IPList, error) {
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = DefaultRefreshInterval
	}
	sourceCtx, cancel := context.WithCancel(ctx)
	s := &IPList{ctx: sourceCtx, cancel: cancel, config: config}
	if _, err := s.Load(ctx, true); err != nil {
		cancel()
		return nil, err
	}
	return s, nil
}

func (s *IPList) Current() *[]string {
	return s.current.Load()
}

func (s *IPList) Due(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	status := s.Status()
	return !status.HasValue || status.StaleAt.IsZero() || !time.Now().Before(status.StaleAt), nil
}

func (s *IPList) Revalidate(ctx context.Context) (started bool, err error) {
	due, err := s.Due(ctx)
	if err != nil || !due {
		return false, err
	}
	if !s.refresh.Begin() {
		return false, nil
	}
	go func() {
		timeout := s.config.RefreshTimeout
		if timeout <= 0 {
			timeout = DefaultRefreshTimeout
		}
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		s.refresh.Finish(s.update(refreshCtx))
	}()
	return true, nil
}

func (s *IPList) update(ctx context.Context) error {
	generation := s.generation.Load()
	entries, err := s.load(ctx)
	if err != nil {
		errCopy := err
		s.lastErr.Store(&errCopy)
		return err
	}
	old := s.current.Load()
	changed := old == nil || !sameEntries(*old, entries)
	if changed && s.generation.Load() == generation {
		s.store(entries)
	}
	s.lastErr.Store(nil)
	return nil
}

func (s *IPList) Load(ctx context.Context, wait bool) (*[]string, error) {
	_, startErr := s.Revalidate(ctx)
	if startErr != nil {
		return s.Current(), startErr
	}
	if s.Current() == nil || wait {
		if err := s.refresh.Wait(ctx); err != nil {
			return s.Current(), err
		}
	}
	return s.Current(), nil
}

func (s *IPList) Set(entries *[]string) error {
	if entries == nil {
		return s.Clear()
	}
	s.generation.Add(1)
	s.store(*entries)
	return nil
}

func (s *IPList) Clear() error {
	s.generation.Add(1)
	s.current.Store(nil)
	s.loadedAt.Store(nil)
	return nil
}

func (s *IPList) Status() cacheable.Status {
	loadedAt := time.Time{}
	if t := s.loadedAt.Load(); t != nil {
		loadedAt = *t
	}
	var lastErr error
	if p := s.lastErr.Load(); p != nil {
		lastErr = *p
	}
	status := cacheable.Status{LoadedAt: loadedAt, HasValue: s.Current() != nil, Refreshing: s.refresh.Running(), LastError: lastErr}
	if !loadedAt.IsZero() {
		status.StaleAt = loadedAt.Add(s.config.RefreshInterval)
	}
	return status
}

func (s *IPList) Start(ctx context.Context, interval time.Duration) {
	s.start.Do(func() {
		if interval <= 0 {
			interval = s.config.RefreshInterval
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-s.ctx.Done():
					return
				case <-ticker.C:
					_, _ = s.Revalidate(s.ctx)
				}
			}
		}()
	})
}

func (s *IPList) Stop() error {
	if s == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	timeout := s.config.RefreshTimeout
	if timeout <= 0 {
		timeout = DefaultRefreshTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.refresh.Stop(ctx)
}

func (s *IPList) load(ctx context.Context) ([]string, error) {
	if s.config.Source == "" {
		if s.config.Optional {
			return nil, nil
		}
		return nil, errors.New("source is required")
	}
	if s.config.Optional {
		parsed, parseErr := url.Parse(s.config.Source)
		isURL := parseErr == nil && (parsed.Scheme == "http" || parsed.Scheme == "https")
		if !isURL {
			if _, err := os.Stat(s.config.Source); os.IsNotExist(err) {
				return nil, nil
			} else if err != nil {
				return nil, err
			}
		}
	}
	return Load(ctx, s.config.Source, s.config.CacheDir, s.config.HTTPClient)
}

func (s *IPList) store(entries []string) {
	cp := append([]string(nil), entries...)
	s.current.Store(&cp)
	now := time.Now()
	s.loadedAt.Store(&now)
}

func sameEntries(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
