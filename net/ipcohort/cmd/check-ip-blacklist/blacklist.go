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

	git          *gitshallow.Repo
	httpInbound  []*httpcache.Cacher
	httpOutbound []*httpcache.Cacher
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
	return &Sources{
		whitelistPaths: whitelist,
		inboundPaths:   abs(inboundRel),
		outboundPaths:  abs(outboundRel),
		git:            gitshallow.New(gitURL, repoDir, 1, ""),
	}
}

func newHTTPSources(whitelist []string, inbound, outbound []HTTPSource) *Sources {
	s := &Sources{whitelistPaths: whitelist}
	for _, src := range inbound {
		s.inboundPaths = append(s.inboundPaths, src.Path)
		s.httpInbound = append(s.httpInbound, httpcache.New(src.URL, src.Path))
	}
	for _, src := range outbound {
		s.outboundPaths = append(s.outboundPaths, src.Path)
		s.httpOutbound = append(s.httpOutbound, httpcache.New(src.URL, src.Path))
	}
	return s
}

// Fetch pulls updates from the remote (git or HTTP).
// Returns whether any new data was received.
func (s *Sources) Fetch(lightGC bool) (bool, error) {
	switch {
	case s.git != nil:
		return s.git.Sync(lightGC)
	case len(s.httpInbound) > 0 || len(s.httpOutbound) > 0:
		var anyUpdated bool
		for _, c := range s.httpInbound {
			updated, err := c.Fetch()
			if err != nil {
				return anyUpdated, err
			}
			anyUpdated = anyUpdated || updated
		}
		for _, c := range s.httpOutbound {
			updated, err := c.Fetch()
			if err != nil {
				return anyUpdated, err
			}
			anyUpdated = anyUpdated || updated
		}
		return anyUpdated, nil
	default:
		return false, nil
	}
}

// Init ensures the remote is ready (clones if needed, fetches HTTP files).
// Always returns true so the caller knows to load data on startup.
func (s *Sources) Init(lightGC bool) error {
	switch {
	case s.git != nil:
		_, err := s.git.Init(lightGC)
		return err
	case len(s.httpInbound) > 0 || len(s.httpOutbound) > 0:
		for _, c := range s.httpInbound {
			if _, err := c.Fetch(); err != nil {
				return err
			}
		}
		for _, c := range s.httpOutbound {
			if _, err := c.Fetch(); err != nil {
				return err
			}
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
