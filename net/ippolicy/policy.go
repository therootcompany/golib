// Package ippolicy composes whitelist and blacklist IP sources into one
// atomically refreshed policy.
package ippolicy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/ipgate"
	"github.com/therootcompany/golib/net/iplist"
)

const DefaultRefreshInterval = time.Hour + 57*time.Minute + 13*time.Second

type Config struct {
	HTTPClient         *http.Client
	Whitelist          string
	BlacklistExtra     string
	BlacklistRepo      string
	BlacklistRepoDir   string
	BlacklistRepoFiles []string
	CacheDir           string
	RefreshInterval    time.Duration
	Resolver           *net.Resolver
	OnRefresh          func(RefreshEvent)
}

type Decision struct {
	Whitelisted  bool
	Blacklisted  bool
	Blocked      bool
	GitMatched   bool
	ExtraMatched bool
}

type RefreshKind string

const (
	RefreshSuccess  RefreshKind = "success"
	RefreshFailure  RefreshKind = "failure"
	RefreshFallback RefreshKind = "fallback"
)

type RefreshEvent struct {
	Kind       RefreshKind
	Generation uint64
	Err        error
}

type snapshot struct {
	whitelist  *ipgate.DomainSet
	extra      *ipgate.DomainSet
	git        *ipgate.PrefixSet
	generation uint64
}

type Policy struct {
	ctx      context.Context
	cancel   context.CancelFunc
	config   Config
	current  atomic.Pointer[snapshot]
	sequence atomic.Uint64
}

func New(ctx context.Context, config Config) (*Policy, error) {
	if config.RefreshInterval <= 0 {
		config.RefreshInterval = DefaultRefreshInterval
	}
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	policyCtx, cancel := context.WithCancel(ctx)
	p := &Policy{ctx: policyCtx, cancel: cancel, config: config}
	if err := p.refresh(true); err != nil {
		cancel()
		return nil, err
	}
	go p.refreshLoop()
	return p, nil
}

func (p *Policy) Evaluate(addr netip.Addr) Decision {
	current := p.current.Load()
	if current == nil {
		return Decision{}
	}
	whitelisted := current.whitelist.Contains(addr)
	extraMatched := current.extra != nil && current.extra.Contains(addr)
	gitMatched := current.git != nil && current.git.Contains(addr)
	blacklisted := extraMatched || gitMatched
	return Decision{
		Whitelisted:  whitelisted,
		Blacklisted:  blacklisted,
		Blocked:      blacklisted && !whitelisted,
		GitMatched:   gitMatched,
		ExtraMatched: extraMatched,
	}
}

func (p *Policy) Close() error {
	if p != nil && p.cancel != nil {
		p.cancel()
	}
	return nil
}

func (p *Policy) refresh(initial bool) error {
	whitelist, err := p.load(p.config.Whitelist, false)
	if err != nil {
		if initial {
			p.publish(&snapshot{whitelist: ipgate.EmptyDomainSet()})
			p.emit(RefreshFallback, err)
			return nil
		}
		p.emit(RefreshFailure, err)
		return err
	}
	whitelistSet, err := p.build(whitelist)
	if err != nil {
		return p.failed(initial, err)
	}

	extra := []string(nil)
	var fallbackErr error
	if p.config.BlacklistExtra != "" {
		extra, err = p.load(p.config.BlacklistExtra, true)
		if err != nil {
			if !initial {
				return p.failed(false, err)
			}
			fallbackErr = err
		}
	}
	extraSet := ipgate.EmptyDomainSet()
	if fallbackErr == nil {
		extraSet, err = p.build(extra)
		if err != nil {
			if !initial {
				return p.failed(false, err)
			}
			fallbackErr = err
		}
	}

	var git *ipgate.PrefixSet
	if p.config.BlacklistRepo != "" && p.config.BlacklistRepo != "none" {
		files := p.config.BlacklistRepoFiles
		if len(files) == 0 {
			files = []string{"tables/inbound/single_ips.txt", "tables/inbound/networks.txt"}
		}
		git, err = ipgate.NewPrefixSet(p.ctx, p.config.BlacklistRepo, p.config.BlacklistRepoDir, files)
		if err != nil {
			if !initial {
				return p.failed(false, err)
			}
			fallbackErr = err
		}
	}
	p.publish(&snapshot{whitelist: whitelistSet, extra: extraSet, git: git})
	if fallbackErr != nil {
		p.emit(RefreshFallback, fallbackErr)
	} else {
		p.emit(RefreshSuccess, nil)
	}
	return nil
}

func (p *Policy) failed(initial bool, err error) error {
	if initial {
		p.publish(&snapshot{whitelist: ipgate.EmptyDomainSet()})
		p.emit(RefreshFallback, err)
		return nil
	}
	p.emit(RefreshFailure, err)
	return err
}

func (p *Policy) load(source string, optional bool) ([]string, error) {
	if source == "" {
		if optional {
			return nil, nil
		}
		return nil, fmt.Errorf("whitelist source is required")
	}
	if optional {
		parsed, parseErr := url.Parse(source)
		isURL := parseErr == nil && (parsed.Scheme == "http" || parsed.Scheme == "https")
		if !isURL {
			if _, err := os.Stat(source); os.IsNotExist(err) {
				return nil, nil
			} else if err != nil {
				return nil, err
			}
		}
	}
	entries, err := iplist.Load(p.ctx, source, p.config.CacheDir, p.config.HTTPClient)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (p *Policy) build(entries []string) (*ipgate.DomainSet, error) {
	prefixes := make([]string, 0, len(entries))
	domains := make([]string, 0, len(entries))
	for _, entry := range entries {
		if net.ParseIP(entry) != nil {
			prefixes = append(prefixes, entry)
		} else if _, _, err := net.ParseCIDR(entry); err == nil {
			prefixes = append(prefixes, entry)
		} else {
			domains = append(domains, entry)
		}
	}
	for _, domain := range domains {
		ips, err := p.config.Resolver.LookupNetIP(p.ctx, "ip", domain)
		if err != nil {
			return nil, fmt.Errorf("resolve domain %q: %w", domain, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve domain %q: no addresses", domain)
		}
		for _, ip := range ips {
			prefixes = append(prefixes, ip.String())
		}
	}
	return ipgate.NewDomainSet(p.ctx, prefixes, nil), nil
}

func (p *Policy) publish(next *snapshot) {
	next.generation = p.sequence.Add(1)
	p.current.Store(next)
}

func (p *Policy) emit(kind RefreshKind, err error) {
	if p.config.OnRefresh == nil {
		return
	}
	current := p.current.Load()
	var generation uint64
	if current != nil {
		generation = current.generation
	}
	p.config.OnRefresh(RefreshEvent{Kind: kind, Generation: generation, Err: err})
}

func (p *Policy) refreshLoop() {
	ticker := time.NewTicker(p.config.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			_ = p.refresh(false)
		}
	}
}
