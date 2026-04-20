package main

import (
	"path/filepath"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
)

// HTTPSource pairs a remote URL with a local cache path.
type HTTPSource struct {
	URL  string
	Path string
}

// Sources holds the configuration for fetching and loading the three cohorts.
// It knows how to pull data from git or HTTP, but owns no atomic state.
type Sources struct {
	whitelistPaths []string
	inboundPaths   []string
	outboundPaths  []string

	gitRepo *gitshallow.Repo  // non-nil for git source; used by Init for clone-if-missing
	syncs   []httpcache.Syncer // all syncable sources (git repo or HTTP cachers)
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
		gitRepo:        repo,
		syncs:          []httpcache.Syncer{repo},
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
// Satisfies httpcache.Syncer.
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

// Init ensures remotes are ready. For git: clones if missing then syncs.
// For HTTP: fetches each cacher unconditionally on first run.
func (s *Sources) Init() error {
	if s.gitRepo != nil {
		_, err := s.gitRepo.Init()
		return err
	}
	for _, syn := range s.syncs {
		if _, err := syn.Fetch(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Sources) LoadWhitelist() (*ipcohort.Cohort, error) {
	if len(s.whitelistPaths) == 0 {
		return nil, nil
	}
	return ipcohort.LoadFiles(s.whitelistPaths...)
}

func (s *Sources) LoadInbound() (*ipcohort.Cohort, error) {
	if len(s.inboundPaths) == 0 {
		return nil, nil
	}
	return ipcohort.LoadFiles(s.inboundPaths...)
}

func (s *Sources) LoadOutbound() (*ipcohort.Cohort, error) {
	if len(s.outboundPaths) == 0 {
		return nil, nil
	}
	return ipcohort.LoadFiles(s.outboundPaths...)
}
