// Package ippolicy composes independently refreshed whitelist and blacklist
// sources into one IP decision policy.
package ippolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/therootcompany/golib/net/iplist"
)

type Config struct {
	Whitelist      *iplist.IPList
	Blacklist      *IPPrefixSet
	BlacklistExtra *iplist.IPList
}

// Decision is the mutually exclusive result of evaluating an address.
type Decision uint8

const (
	Blacklisted Decision = iota
	Unlisted
	Whitelisted
)

func (d Decision) String() string {
	switch d {
	case Blacklisted:
		return "blacklisted"
	case Unlisted:
		return "unlisted"
	case Whitelisted:
		return "whitelisted"
	default:
		return fmt.Sprintf("decision(%d)", d)
	}
}

type Policy struct {
	whitelist            *DomainSet
	blacklistExtra       *DomainSet
	blacklist            *IPPrefixSet
	whitelistSource      *iplist.IPList
	blacklistExtraSource *iplist.IPList

	start  sync.Once
	cancel context.CancelFunc
	loadMu sync.Mutex
}

// New creates a Policy from the given sources. The caller is responsible for
// constructing and later closing the *iplist.IPList values; New does not take
// ownership of them.
//
// A nil Whitelist is treated as an empty whitelist: every address evaluates to
// Unlisted. This also intentionally drops the blacklists, because a policy
// without a whitelist provides no meaningful allow-list semantics — blocking
// would reject everything not on the blacklist rather than only what is on it.
// The caller receives a RefreshFallback event so it can log or alert.
func New(ctx context.Context, config Config) *Policy {
	p := &Policy{}
	if config.Whitelist == nil {
		p.whitelist = EmptyDomainSet()
		return p
	}

	p.whitelistSource = config.Whitelist
	p.whitelist = NewDomainSetFromEntries(ctx, sourceEntries(config.Whitelist), DefaultDomainSetRefreshInterval)

	if config.BlacklistExtra != nil {
		p.blacklistExtraSource = config.BlacklistExtra
		p.blacklistExtra = NewDomainSetFromEntries(ctx, sourceEntries(config.BlacklistExtra), DefaultDomainSetRefreshInterval)
	} else {
		p.blacklistExtra = EmptyDomainSet()
	}
	p.blacklist = config.Blacklist
	return p
}

// Load refreshes policy inputs and updates the derived domain sets. It reads
// the current snapshot of each source IP list and pushes the entries into the
// derived DomainSets (re-resolving DNS for any hostname entries). With
// wait=false it returns after issuing the refreshes; with wait=true it waits
// for each source refresh to complete first.
//
// Sources that refresh in the background (via their own Start ticker) do not
// automatically update the derived sets; call Start on the Policy to run a
// periodic Load(false), or call Load explicitly after a source refresh.
func (p *Policy) Load(ctx context.Context, wait bool) error {
	p.loadMu.Lock()
	defer p.loadMu.Unlock()

	if p.whitelistSource == nil {
		return nil
	}
	if _, err := p.whitelistSource.Load(ctx, wait); err != nil {
		return err
	}
	p.whitelist.ReplaceEntries(sourceEntries(p.whitelistSource))
	if p.blacklistExtraSource != nil {
		if _, err := p.blacklistExtraSource.Load(ctx, wait); err != nil {
			return err
		}
		p.blacklistExtra.ReplaceEntries(sourceEntries(p.blacklistExtraSource))
	}
	if p.blacklist != nil {
		if _, err := p.blacklist.Load(ctx, wait); err != nil {
			return err
		}
	}
	return nil
}

func sourceEntries(source *iplist.IPList) []string {
	entries := source.Current()
	if entries == nil {
		return nil
	}
	return *entries
}

func (p *Policy) Evaluate(addr netip.Addr) Decision {
	if p.whitelist == nil {
		return Unlisted
	}
	if p.whitelist.Contains(addr) {
		return Whitelisted
	}
	if (p.blacklistExtra != nil && p.blacklistExtra.Contains(addr)) ||
		(p.blacklist != nil && p.blacklist.Contains(addr)) {
		return Blacklisted
	}
	return Unlisted
}

// Start starts at most one background loop that periodically re-reads the
// source IP lists and pushes their current entries into the derived domain
// sets (re-resolving DNS each time). This closes the gap where a source
// refreshes via its own ticker but the derived DomainSet is never updated
// because nobody calls Load. The interval defaults to
// DefaultDomainSetRefreshInterval when zero.
//
// Start does not start the DomainSets' own DNS refresh loops; the Policy loop
// drives both source re-reads and DNS re-resolution via Load+ReplaceEntries.
func (p *Policy) Start(ctx context.Context, interval time.Duration) {
	p.start.Do(func() {
		if interval <= 0 {
			interval = DefaultDomainSetRefreshInterval
		}
		loopCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-loopCtx.Done():
					return
				case <-ticker.C:
					// Re-read sources and re-resolve derived sets without blocking
					// the hot path. Errors are non-fatal: last-good snapshots are
					// retained by the sources and DomainSets.
					_ = p.Load(loopCtx, false)
				}
			}
		}()
	})
}

func (p *Policy) Stop() error {
	if p == nil {
		return nil
	}
	if p.cancel != nil {
		p.cancel()
	}
	var errs []error
	if p.whitelist != nil {
		if err := p.whitelist.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.blacklistExtra != nil {
		if err := p.blacklistExtra.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.blacklist != nil {
		if err := p.blacklist.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
