package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
)

// HTTPSource pairs a remote URL with a local cache path.
type HTTPSource struct {
	URL  string
	Path string
}

// IPFilter holds up to three cohorts: a whitelist (IPs never blocked),
// an inbound blocklist, and an outbound blocklist.
type IPFilter struct {
	whitelist atomic.Pointer[ipcohort.Cohort]
	inbound   atomic.Pointer[ipcohort.Cohort]
	outbound  atomic.Pointer[ipcohort.Cohort]

	whitelistPaths []string
	inboundPaths   []string
	outboundPaths  []string

	git          *gitshallow.Repo
	httpInbound  []*httpcache.Cacher
	httpOutbound []*httpcache.Cacher
}

// NewFileFilter loads inbound/outbound/whitelist from local files.
func NewFileFilter(whitelist, inbound, outbound []string) *IPFilter {
	return &IPFilter{
		whitelistPaths: whitelist,
		inboundPaths:   inbound,
		outboundPaths:  outbound,
	}
}

// NewGitFilter clones/pulls gitURL into repoDir and loads the given relative
// paths for each cohort on each update.
func NewGitFilter(gitURL, repoDir string, whitelist, inboundRel, outboundRel []string) *IPFilter {
	abs := func(rel []string) []string {
		out := make([]string, len(rel))
		for i, p := range rel {
			out[i] = filepath.Join(repoDir, p)
		}
		return out
	}
	return &IPFilter{
		whitelistPaths: whitelist,
		inboundPaths:   abs(inboundRel),
		outboundPaths:  abs(outboundRel),
		git:            gitshallow.New(gitURL, repoDir, 1, ""),
	}
}

// NewHTTPFilter fetches inbound and outbound sources via HTTP;
// whitelist is always loaded from local files.
func NewHTTPFilter(whitelist []string, inbound, outbound []HTTPSource) *IPFilter {
	f := &IPFilter{whitelistPaths: whitelist}
	for _, src := range inbound {
		f.inboundPaths = append(f.inboundPaths, src.Path)
		f.httpInbound = append(f.httpInbound, httpcache.New(src.URL, src.Path))
	}
	for _, src := range outbound {
		f.outboundPaths = append(f.outboundPaths, src.Path)
		f.httpOutbound = append(f.httpOutbound, httpcache.New(src.URL, src.Path))
	}
	return f
}

func (f *IPFilter) Init(lightGC bool) error {
	switch {
	case f.git != nil:
		if _, err := f.git.Init(lightGC); err != nil {
			return err
		}
	case len(f.httpInbound) > 0 || len(f.httpOutbound) > 0:
		for _, c := range f.httpInbound {
			if _, err := c.Fetch(); err != nil {
				return err
			}
		}
		for _, c := range f.httpOutbound {
			if _, err := c.Fetch(); err != nil {
				return err
			}
		}
	}
	return f.reloadAll()
}

func (f *IPFilter) Run(ctx context.Context, lightGC bool) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updated, err := f.sync(lightGC)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: filter sync: %v\n", err)
			} else if updated {
				fmt.Fprintf(os.Stderr, "filter: reloaded — inbound=%d outbound=%d\n",
					f.InboundSize(), f.OutboundSize())
			}
		case <-ctx.Done():
			return
		}
	}
}

func (f *IPFilter) sync(lightGC bool) (bool, error) {
	switch {
	case f.git != nil:
		updated, err := f.git.Sync(lightGC)
		if err != nil || !updated {
			return updated, err
		}
		return true, f.reloadAll()
	case len(f.httpInbound) > 0 || len(f.httpOutbound) > 0:
		var anyUpdated bool
		for _, c := range f.httpInbound {
			updated, err := c.Fetch()
			if err != nil {
				return anyUpdated, err
			}
			anyUpdated = anyUpdated || updated
		}
		for _, c := range f.httpOutbound {
			updated, err := c.Fetch()
			if err != nil {
				return anyUpdated, err
			}
			anyUpdated = anyUpdated || updated
		}
		if anyUpdated {
			return true, f.reloadAll()
		}
		return false, nil
	default:
		return false, nil
	}
}

// ContainsInbound reports whether ip is in the inbound blocklist and not whitelisted.
func (f *IPFilter) ContainsInbound(ip string) bool {
	if wl := f.whitelist.Load(); wl != nil && wl.Contains(ip) {
		return false
	}
	c := f.inbound.Load()
	return c != nil && c.Contains(ip)
}

// ContainsOutbound reports whether ip is in the outbound blocklist and not whitelisted.
func (f *IPFilter) ContainsOutbound(ip string) bool {
	if wl := f.whitelist.Load(); wl != nil && wl.Contains(ip) {
		return false
	}
	c := f.outbound.Load()
	return c != nil && c.Contains(ip)
}

func (f *IPFilter) InboundSize() int {
	if c := f.inbound.Load(); c != nil {
		return c.Size()
	}
	return 0
}

func (f *IPFilter) OutboundSize() int {
	if c := f.outbound.Load(); c != nil {
		return c.Size()
	}
	return 0
}

func (f *IPFilter) reloadAll() error {
	if err := f.reloadWhitelist(); err != nil {
		return err
	}
	if err := f.reloadInbound(); err != nil {
		return err
	}
	return f.reloadOutbound()
}

func (f *IPFilter) reloadWhitelist() error {
	if len(f.whitelistPaths) == 0 {
		return nil
	}
	c, err := ipcohort.LoadFiles(f.whitelistPaths...)
	if err != nil {
		return err
	}
	f.whitelist.Store(c)
	return nil
}

func (f *IPFilter) reloadInbound() error {
	if len(f.inboundPaths) == 0 {
		return nil
	}
	c, err := ipcohort.LoadFiles(f.inboundPaths...)
	if err != nil {
		return err
	}
	f.inbound.Store(c)
	return nil
}

func (f *IPFilter) reloadOutbound() error {
	if len(f.outboundPaths) == 0 {
		return nil
	}
	c, err := ipcohort.LoadFiles(f.outboundPaths...)
	if err != nil {
		return err
	}
	f.outbound.Store(c)
	return nil
}
