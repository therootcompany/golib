package main

import (
	"path/filepath"
	"strings"

	"github.com/therootcompany/golib/net/dataset"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
)

// Sources holds fetch configuration for the blocklist cohorts.
type Sources struct {
	whitelistPaths []string
	inboundPaths   []string
	outboundPaths  []string
	syncs          []dataset.Syncer
}

// buildSources constructs the right Sources from CLI flags.
//
//   - gitURL set  → clone/pull the bitwire-it repo; inbound/outbound from known relative paths
//   - inbound/outbound set → use those explicit file paths, no network sync
//   - neither set → HTTP-fetch the bitwire-it files into dataDir (or default cache dir)
func buildSources(gitURL, dataDir, whitelistFlag, inboundFlag, outboundFlag string) *Sources {
	// Explicit file paths always win.
	if inboundFlag != "" || outboundFlag != "" {
		return &Sources{
			whitelistPaths: splitPaths(whitelistFlag),
			inboundPaths:   splitPaths(inboundFlag),
			outboundPaths:  splitPaths(outboundFlag),
		}
	}

	cacheDir := dataDir
	if cacheDir == "" {
		cacheDir = defaultCacheDir("bitwire-it")
	}

	if gitURL != "" {
		repo := gitshallow.New(gitURL, cacheDir, 1, "")
		return &Sources{
			whitelistPaths: splitPaths(whitelistFlag),
			inboundPaths: []string{
				filepath.Join(cacheDir, "tables/inbound/single_ips.txt"),
				filepath.Join(cacheDir, "tables/inbound/networks.txt"),
			},
			outboundPaths: []string{
				filepath.Join(cacheDir, "tables/outbound/single_ips.txt"),
				filepath.Join(cacheDir, "tables/outbound/networks.txt"),
			},
			syncs: []dataset.Syncer{repo},
		}
	}

	// Default: HTTP fetch from bitwire-it into cacheDir.
	inboundSingle  := filepath.Join(cacheDir, "inbound_single_ips.txt")
	inboundNetwork := filepath.Join(cacheDir, "inbound_networks.txt")
	outboundSingle  := filepath.Join(cacheDir, "outbound_single_ips.txt")
	outboundNetwork := filepath.Join(cacheDir, "outbound_networks.txt")
	return &Sources{
		whitelistPaths: splitPaths(whitelistFlag),
		inboundPaths:   []string{inboundSingle, inboundNetwork},
		outboundPaths:  []string{outboundSingle, outboundNetwork},
		syncs: []dataset.Syncer{
			httpcache.New(inboundSingleURL, inboundSingle),
			httpcache.New(inboundNetworkURL, inboundNetwork),
			httpcache.New(outboundSingleURL, outboundSingle),
			httpcache.New(outboundNetworkURL, outboundNetwork),
		},
	}
}

func splitPaths(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// Fetch pulls updates from all sources. Satisfies dataset.Syncer.
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

// Datasets builds a dataset.Group and returns typed views for each cohort.
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
