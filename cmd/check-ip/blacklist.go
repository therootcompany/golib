package main

import (
	"path/filepath"

	"github.com/therootcompany/golib/net/dataset"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
)

// HTTPSource pairs a remote URL with a local cache path.
type HTTPSource struct {
	URL  string
	Path string
}

// Sources holds fetch configuration for the three blocklist cohorts.
// It knows how to pull data from git or HTTP, but owns no atomic state.
type Sources struct {
	whitelistPaths []string
	inboundPaths   []string
	outboundPaths  []string

	syncs []dataset.Syncer // all syncable sources
}

func newFileSources(whitelist, inbound, outbound []string) *Sources {
	return &Sources{
		whitelistPaths: whitelist,
		inboundPaths:   inbound,
		outboundPaths:  outbound,
	}
}

func newGitSources(gitURL, repoDir string, whitelist, inboundRel, outboundRel []string) *Sources {
	abs := func(rel []string) []string {
		out := make([]string, len(rel))
		for i, p := range rel {
			out[i] = filepath.Join(repoDir, p)
		}
		return out
	}
	repo := gitshallow.New(gitURL, repoDir, 1, "")
	return &Sources{
		whitelistPaths: whitelist,
		inboundPaths:   abs(inboundRel),
		outboundPaths:  abs(outboundRel),
		syncs:          []dataset.Syncer{repo},
	}
}

func newHTTPSources(whitelist []string, inbound, outbound []HTTPSource) *Sources {
	s := &Sources{whitelistPaths: whitelist}
	for _, src := range inbound {
		s.inboundPaths = append(s.inboundPaths, src.Path)
		s.syncs = append(s.syncs, httpcache.New(src.URL, src.Path))
	}
	for _, src := range outbound {
		s.outboundPaths = append(s.outboundPaths, src.Path)
		s.syncs = append(s.syncs, httpcache.New(src.URL, src.Path))
	}
	return s
}

// Fetch pulls updates from all sources. Returns whether any new data arrived.
// Satisfies dataset.Syncer.
func (s *Sources) Fetch() (bool, error) {
	var anyUpdated bool
	for _, syn := range s.syncs {
		updated, err := syn.Fetch()
		if err != nil {
			return anyUpdated, err
		}
		anyUpdated = anyUpdated || updated
	}
	return anyUpdated, nil
}

// Datasets builds a dataset.Group backed by this Sources and returns typed
// datasets for whitelist, inbound, and outbound cohorts. Either whitelist or
// outbound may be nil if no paths were configured.
func (s *Sources) Datasets() (
	g *dataset.Group,
	whitelist *dataset.View[ipcohort.Cohort],
	inbound *dataset.View[ipcohort.Cohort],
	outbound *dataset.View[ipcohort.Cohort],
) {
	g = dataset.NewGroup(s)
	if len(s.whitelistPaths) > 0 {
		paths := s.whitelistPaths
		whitelist = dataset.Add(g, func() (*ipcohort.Cohort, error) {
			return ipcohort.LoadFiles(paths...)
		})
	}
	if len(s.inboundPaths) > 0 {
		paths := s.inboundPaths
		inbound = dataset.Add(g, func() (*ipcohort.Cohort, error) {
			return ipcohort.LoadFiles(paths...)
		})
	}
	if len(s.outboundPaths) > 0 {
		paths := s.outboundPaths
		outbound = dataset.Add(g, func() (*ipcohort.Cohort, error) {
			return ipcohort.LoadFiles(paths...)
		})
	}
	return g, whitelist, inbound, outbound
}

// isBlocked returns true if ip is in cohort and not in whitelist.
func isBlocked(ip string, whitelist, cohort *dataset.View[ipcohort.Cohort]) bool {
	if cohort == nil {
		return false
	}
	if whitelist != nil && whitelist.Load().Contains(ip) {
		return false
	}
	return cohort.Load().Contains(ip)
}

func cohortSize(ds *dataset.View[ipcohort.Cohort]) int {
	if ds == nil {
		return 0
	}
	return ds.Load().Size()
}
