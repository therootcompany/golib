package ipgate

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
)

const prefixSetRefreshInterval = 47 * time.Minute

type PrefixSet struct {
	repo   *gitshallow.Repo
	files  []string
	cohort atomic.Pointer[ipcohort.Cohort]
}

func EmptyPrefixSet() *PrefixSet {
	ps := &PrefixSet{}
	ps.cohort.Store(&ipcohort.Cohort{})
	return ps
}

func NewPrefixSet(ctx context.Context, repoURL, dataPath string, files []string) (*PrefixSet, error) {
	if err := os.MkdirAll(dataPath, 0o755); err != nil {
		return nil, fmt.Errorf("ipgate: create data dir: %w", err)
	}

	repo := gitshallow.New(repoURL, dataPath, 0, "")

	ps := &PrefixSet{
		repo:  repo,
		files: files,
	}
	ps.cohort.Store(&ipcohort.Cohort{})

	go ps.refreshLoop(ctx)

	return ps, nil
}

func (ps *PrefixSet) Contains(addr netip.Addr) bool {
	cohort := ps.cohort.Load()
	if cohort == nil {
		cohort = &ipcohort.Cohort{}
		ps.cohort.CompareAndSwap(nil, cohort)
	}
	return cohort.ContainsAddr(addr)
}

func (ps *PrefixSet) reload(ctx context.Context) error {
	updated, err := ps.repo.Fetch(ctx)
	if err != nil {
		return err
	}

	paths := make([]string, len(ps.files))
	for i, f := range ps.files {
		paths[i] = ps.repo.FilePath(f)
	}

	if cachedCohortValid(updated, ps.cohort.Load(), paths) {
		return nil
	}

	cohort, err := ipcohort.LoadFiles(paths...)
	if err != nil {
		return fmt.Errorf("load files: %w", err)
	}

	ps.cohort.Store(cohort)

	log().Info("prefix set loaded", "entries", commaify(cohort.Size()))
	return nil
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

func (ps *PrefixSet) refreshLoop(ctx context.Context) {
	if err := ps.reload(ctx); err != nil {
		log().Warn("prefix set initial load (will retry)", "err", err)
	}

	ticker := time.NewTicker(prefixSetRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ps.reload(ctx); err != nil {
				log().Warn("prefix set reload failed", "err", err)
			}
		}
	}
}
