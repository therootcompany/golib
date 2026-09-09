package ippolicy

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

const DefaultPrefixSetRefreshInterval = time.Hour + 57*time.Minute + 13*time.Second

// PrefixSet is a Git-backed IP prefix set. dataset owns fetching, loading,
// atomic snapshot replacement, and refresh cadence.
type PrefixSet struct {
	ctx    context.Context
	cancel context.CancelFunc
	set    *dataset.Set
	view   *dataset.View[ipcohort.Cohort]
}

// EmptyPrefixSet returns an empty, ready-to-use PrefixSet.
func EmptyPrefixSet() *PrefixSet {
	set := dataset.NewSet(dataset.NopFetcher{})
	view := dataset.AddInitial(set, &ipcohort.Cohort{}, func(context.Context) (*ipcohort.Cohort, error) {
		return &ipcohort.Cohort{}, nil
	})
	_ = set.Load(context.Background())
	return &PrefixSet{set: set, view: view}
}

// NewPrefixSet creates a Git-backed prefix set. The initial fetch starts in
// the background; Contains returns false until a valid snapshot is loaded.
func NewPrefixSet(ctx context.Context, repoURL, dataPath string, files []string, interval time.Duration) (*PrefixSet, error) {
	if err := os.MkdirAll(dataPath, 0o755); err != nil {
		return nil, fmt.Errorf("ippolicy: create data dir: %w", err)
	}
	if interval <= 0 {
		interval = DefaultPrefixSetRefreshInterval
	}
	setCtx, cancel := context.WithCancel(ctx)
	repo := gitshallow.New(repoURL, dataPath, 0, "")
	set := dataset.NewSet(repo)
	view := dataset.AddInitial(set, &ipcohort.Cohort{}, func(ctx context.Context) (*ipcohort.Cohort, error) {
		paths := make([]string, len(files))
		for i, file := range files {
			paths[i] = repo.FilePath(file)
		}
		cohort, err := ipcohort.LoadFiles(paths...)
		if err != nil {
			return nil, fmt.Errorf("load files: %w", err)
		}
		log().Info("prefix set loaded", "entries", commaify(cohort.Size()))
		return cohort, nil
	})

	ps := &PrefixSet{ctx: setCtx, cancel: cancel, set: set, view: view}
	go func() {
		if err := set.Load(setCtx); err != nil && setCtx.Err() == nil {
			log().Warn("prefix set initial load (will retry)", "err", err)
		}
		set.Tick(setCtx, interval, func(err error) {
			log().Warn("prefix set reload failed", "err", err)
		})
	}()
	return ps, nil
}

func (ps *PrefixSet) Close() error {
	if ps == nil {
		return nil
	}
	if ps.cancel != nil {
		ps.cancel()
	}
	if ps.set != nil {
		return ps.set.Close()
	}
	return nil
}

func (ps *PrefixSet) Contains(addr netip.Addr) bool {
	if ps == nil || ps.view == nil {
		return false
	}
	cohort := ps.view.Value()
	return cohort != nil && cohort.ContainsAddr(addr)
}

// Loaded reports whether the initial dataset load succeeded.
func (ps *PrefixSet) Loaded() bool {
	return ps != nil && ps.set != nil && ps.set.Loaded()
}

// LoadedAt reports when the current snapshot was loaded.
func (ps *PrefixSet) LoadedAt() time.Time {
	if ps == nil || ps.view == nil {
		return time.Time{}
	}
	return ps.view.LoadedAt()
}

// Size reports the number of prefixes in the current snapshot.
func (ps *PrefixSet) Size() int {
	if ps == nil || ps.view == nil || ps.view.Value() == nil {
		return 0
	}
	return ps.view.Value().Size()
}
