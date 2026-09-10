package ippolicy

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/cachable"
)

const (
	DefaultPrefixSetRefreshInterval = time.Hour + 57*time.Minute + 13*time.Second
	DefaultRefreshTimeout           = time.Hour + 57*time.Minute + 13*time.Second
)

type IPPrefixSet struct {
	ctx            context.Context
	cancel         context.CancelFunc
	repo           *gitshallow.Repo
	files          []string
	cohort         atomic.Pointer[ipcohort.Cohort]
	start          sync.Once
	generation     atomic.Uint64
	loadedAt       atomic.Pointer[time.Time]
	lastErr        atomic.Pointer[error]
	interval       time.Duration
	RefreshTimeout time.Duration
	refresh        cachable.Refresh
}

func EmptyIPPrefixSet() *IPPrefixSet {
	ps := &IPPrefixSet{}
	ps.cohort.Store(&ipcohort.Cohort{})
	return ps
}

func NewIPPrefixSet(ctx context.Context, repoURL, dataPath string, files []string, interval time.Duration) (*IPPrefixSet, error) {
	if err := os.MkdirAll(dataPath, 0o755); err != nil {
		return nil, fmt.Errorf("ippolicy: create data dir: %w", err)
	}

	if interval <= 0 {
		interval = DefaultPrefixSetRefreshInterval
	}
	setCtx, cancel := context.WithCancel(ctx)
	repo := gitshallow.New(repoURL, dataPath, 0, "")

	ps := &IPPrefixSet{
		ctx:      setCtx,
		cancel:   cancel,
		repo:     repo,
		files:    files,
		interval: interval,
	}
	ps.cohort.Store(&ipcohort.Cohort{})

	return ps, nil
}

var (
	_ cachable.Cacheable[ipcohort.Cohort] = (*IPPrefixSet)(nil)
	_ cachable.Mutable[ipcohort.Cohort]   = (*IPPrefixSet)(nil)
	_ cachable.Inspectable                = (*IPPrefixSet)(nil)
	_ cachable.Tickable                   = (*IPPrefixSet)(nil)
)

func (ps *IPPrefixSet) Current() *ipcohort.Cohort {
	return ps.cohort.Load()
}

func (ps *IPPrefixSet) Due(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	status := ps.Status()
	return !status.HasValue || status.StaleAt.IsZero() || !time.Now().Before(status.StaleAt), nil
}

func (ps *IPPrefixSet) Revalidate(ctx context.Context) (started bool, err error) {
	due, err := ps.Due(ctx)
	if err != nil || !due {
		return false, err
	}
	if !ps.refresh.Begin() {
		return false, nil
	}
	go func() {
		timeout := ps.RefreshTimeout
		if timeout <= 0 {
			timeout = DefaultRefreshTimeout
		}
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		ps.refresh.Finish(ps.update(refreshCtx))
	}()
	return true, nil
}

func (ps *IPPrefixSet) update(ctx context.Context) error {
	generation := ps.generation.Load()
	cohort, err := ps.reload(ctx)
	if err != nil {
		errCopy := err
		ps.lastErr.Store(&errCopy)
		return err
	}
	if ps.generation.Load() != generation {
		return nil
	}
	if cohort != nil {
		ps.cohort.Store(cohort)
	}
	now := time.Now()
	ps.loadedAt.Store(&now)
	ps.lastErr.Store(nil)
	return nil
}

func (ps *IPPrefixSet) Set(cohort *ipcohort.Cohort) error {
	ps.generation.Add(1)
	ps.cohort.Store(cohort)
	if cohort == nil {
		ps.loadedAt.Store(nil)
		return nil
	}
	now := time.Now()
	ps.loadedAt.Store(&now)
	return nil
}

func (ps *IPPrefixSet) Clear() error {
	return ps.Set(nil)
}

func (ps *IPPrefixSet) Status() cachable.Status {
	loadedAt := time.Time{}
	if t := ps.loadedAt.Load(); t != nil {
		loadedAt = *t
	}
	var lastErr error
	if p := ps.lastErr.Load(); p != nil {
		lastErr = *p
	}
	status := cachable.Status{LoadedAt: loadedAt, HasValue: ps.Current() != nil, Refreshing: ps.refresh.Running(), LastError: lastErr}
	if !loadedAt.IsZero() {
		status.StaleAt = loadedAt.Add(ps.interval)
	}
	return status
}

func (ps *IPPrefixSet) Load(ctx context.Context, wait bool) (*ipcohort.Cohort, error) {
	if _, err := ps.Revalidate(ctx); err != nil {
		return ps.Current(), err
	}
	if ps.Current() == nil || wait {
		if err := ps.refresh.Wait(ctx); err != nil {
			return ps.Current(), err
		}
	}
	return ps.Current(), nil
}

func (ps *IPPrefixSet) Start(ctx context.Context, interval time.Duration) {
	ps.start.Do(func() {
		if interval <= 0 {
			interval = DefaultPrefixSetRefreshInterval
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ps.ctx.Done():
					return
				case <-ticker.C:
					if _, err := ps.Revalidate(ps.ctx); err != nil {
						log().Warn("prefix set reload failed", "err", err)
					}
				}
			}
		}()
	})
}

func (ps *IPPrefixSet) Stop() error {
	if ps == nil {
		return nil
	}
	if ps.cancel != nil {
		ps.cancel()
	}
	timeout := ps.RefreshTimeout
	if timeout <= 0 {
		timeout = DefaultRefreshTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return ps.refresh.Stop(ctx)
}

func (ps *IPPrefixSet) Contains(addr netip.Addr) bool {
	cohort := ps.cohort.Load()
	if cohort == nil {
		cohort = &ipcohort.Cohort{}
		ps.cohort.CompareAndSwap(nil, cohort)
	}
	return cohort.ContainsAddr(addr)
}

func (ps *IPPrefixSet) reload(ctx context.Context) (*ipcohort.Cohort, error) {
	updated, err := ps.repo.Update(ctx)
	if err != nil {
		return nil, err
	}

	paths := make([]string, len(ps.files))
	for i, f := range ps.files {
		paths[i] = ps.repo.FilePath(f)
	}

	if cachedCohortValid(updated, ps.cohort.Load(), paths) {
		return nil, nil
	}

	cohort, err := ipcohort.LoadFiles(paths...)
	if err != nil {
		return nil, fmt.Errorf("load files: %w", err)
	}

	log().Info("prefix set loaded", "entries", commaify(cohort.Size()))
	return cohort, nil
}

// cachedCohortValid reports whether the current cohort can be reused
// without reloading from disk: the repo was not updated, the cohort is
// non-nil and non-empty, and all data files are present.
func cachedCohortValid(updated bool, cohort *ipcohort.Cohort, paths []string) bool {
	return !updated && cohort != nil && cohort.Size() > 0 && filesPresent(paths)
}

func filesPresent(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}
