// Package ippolicy manages IP policy sources and evaluates client addresses.
package ippolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/net/iplist"
	"github.com/therootcompany/golib/sync/cacheable"
)

type Config struct {
	Whitelist       *iplist.IPList
	Blacklist       *IPPrefixSet
	BlacklistExtra  *iplist.IPList
	RefreshInterval time.Duration
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

// Evaluator is an immutable policy snapshot. It is safe to use concurrently.
type Evaluator struct {
	whitelist      *ipcohort.Cohort
	blacklist      *ipcohort.Cohort
	blacklistExtra *ipcohort.Cohort
}

// Evaluate returns the decision for addr. A whitelist match always wins.
func (e *Evaluator) Evaluate(addr netip.Addr) Decision {
	if e == nil {
		return Unlisted
	}
	if e.whitelist != nil && e.whitelist.ContainsAddr(addr) {
		return Whitelisted
	}
	if (e.blacklistExtra != nil && e.blacklistExtra.ContainsAddr(addr)) ||
		(e.blacklist != nil && e.blacklist.ContainsAddr(addr)) {
		return Blacklisted
	}
	return Unlisted
}

// Policy owns policy source loading and publishes immutable Evaluator snapshots.
type Policy struct {
	whitelist            *DomainSet
	blacklistExtra       *DomainSet
	blacklist            *IPPrefixSet
	whitelistSource      *iplist.IPList
	blacklistExtraSource *iplist.IPList

	current  atomic.Pointer[Evaluator]
	loadedAt atomic.Pointer[time.Time]
	lastErr  atomic.Pointer[error]
	refresh  cacheable.Refresh
	loadMu   sync.Mutex
	interval time.Duration
}

var (
	_ cacheable.Cacheable[Evaluator] = (*Policy)(nil)
	_ cacheable.Mutable[Evaluator]   = (*Policy)(nil)
	_ cacheable.Inspectable          = (*Policy)(nil)
)

// New creates a Policy from the given sources. The caller owns the sources and
// must stop them separately or through Policy.Stop.
func New(ctx context.Context, config Config) *Policy {
	p := &Policy{interval: config.RefreshInterval}
	if p.interval <= 0 {
		p.interval = DefaultDomainSetRefreshInterval
	}
	if config.Whitelist == nil {
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

// Current returns the last published evaluator without blocking.
func (p *Policy) Current() *Evaluator { return p.current.Load() }

// Load refreshes policy sources and returns the last-good evaluator. With
// wait=false, a refresh runs in the background when the snapshot is stale.
// Refresh errors are returned while the previous evaluator is retained.
func (p *Policy) Load(ctx context.Context, wait bool) (*Evaluator, error) {
	if _, err := p.Revalidate(ctx); err != nil {
		return p.lastGood(), err
	}
	if p.loadedAt.Load() == nil || wait {
		if err := p.refresh.Wait(ctx); err != nil {
			return p.lastGood(), err
		}
	}
	return p.lastGood(), nil
}

func (p *Policy) lastGood() *Evaluator {
	if evaluator := p.Current(); evaluator != nil {
		return evaluator
	}
	return &Evaluator{}
}

func (p *Policy) Due(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	status := p.Status()
	return !status.HasValue || status.StaleAt.IsZero() || !time.Now().Before(status.StaleAt), nil
}

func (p *Policy) Revalidate(ctx context.Context) (bool, error) {
	due, err := p.Due(ctx)
	if err != nil || !due || !p.refresh.Begin() {
		return false, err
	}
	go func() { p.refresh.Finish(p.update(ctx)) }()
	return true, nil
}

func (p *Policy) update(ctx context.Context) error {
	p.loadMu.Lock()
	defer p.loadMu.Unlock()

	if p.whitelistSource == nil {
		return p.publish()
	}
	if _, err := p.whitelistSource.Load(ctx, true); err != nil {
		return p.recordError(err)
	}
	p.whitelist.ReplaceEntries(sourceEntries(p.whitelistSource))
	if p.blacklistExtraSource != nil {
		if _, err := p.blacklistExtraSource.Load(ctx, true); err != nil {
			return p.recordError(err)
		}
		p.blacklistExtra.ReplaceEntries(sourceEntries(p.blacklistExtraSource))
	}
	if p.blacklist != nil {
		if _, err := p.blacklist.Load(ctx, true); err != nil {
			return p.recordError(err)
		}
	}
	return p.publish()
}

func (p *Policy) publish() error {
	e := &Evaluator{}
	if p.whitelist != nil {
		e.whitelist = p.whitelist.Current()
	}
	if p.blacklistExtra != nil {
		e.blacklistExtra = p.blacklistExtra.Current()
	}
	if p.blacklist != nil {
		e.blacklist = p.blacklist.Current()
	}
	p.current.Store(e)
	now := time.Now()
	p.loadedAt.Store(&now)
	p.lastErr.Store(nil)
	return nil
}

func (p *Policy) recordError(err error) error {
	errCopy := err
	p.lastErr.Store(&errCopy)
	return err
}

func (p *Policy) Set(e *Evaluator) error {
	if e == nil {
		return p.Clear()
	}
	p.current.Store(e)
	now := time.Now()
	p.loadedAt.Store(&now)
	return nil
}

func (p *Policy) Clear() error {
	p.current.Store(nil)
	p.loadedAt.Store(nil)
	return nil
}

func (p *Policy) Status() cacheable.Status {
	loadedAt := time.Time{}
	if t := p.loadedAt.Load(); t != nil {
		loadedAt = *t
	}
	var lastErr error
	if e := p.lastErr.Load(); e != nil {
		lastErr = *e
	}
	status := cacheable.Status{LoadedAt: loadedAt, HasValue: p.Current() != nil, Refreshing: p.refresh.Running(), LastError: lastErr}
	if !loadedAt.IsZero() {
		status.StaleAt = loadedAt.Add(p.interval)
	}
	return status
}

// Stop stops policy source and DNS refresh work.
func (p *Policy) Stop() error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.whitelist != nil {
		errs = appendStopError(errs, p.whitelist.Stop())
	}
	if p.blacklistExtra != nil {
		errs = appendStopError(errs, p.blacklistExtra.Stop())
	}
	if p.blacklist != nil {
		errs = appendStopError(errs, p.blacklist.Stop())
	}
	return errors.Join(errs...)
}

func appendStopError(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
}

func sourceEntries(source *iplist.IPList) []string {
	entries := source.Current()
	if entries == nil {
		return nil
	}
	return *entries
}
