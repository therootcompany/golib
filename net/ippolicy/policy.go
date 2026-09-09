// Package ippolicy composes independently refreshed whitelist and blacklist
// sources into one IP decision policy.
package ippolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/therootcompany/golib/net/iplist"
)

type Config struct {
	Whitelist      *iplist.Source
	Blacklist      *PrefixSet
	BlacklistExtra *iplist.Source
	OnRefresh      func(RefreshEvent)
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

type RefreshKind uint8

const (
	RefreshSuccess RefreshKind = iota
	RefreshFailure
	RefreshFallback
)

func (k RefreshKind) String() string {
	switch k {
	case RefreshSuccess:
		return "success"
	case RefreshFailure:
		return "failure"
	case RefreshFallback:
		return "fallback"
	default:
		return fmt.Sprintf("refresh(%d)", k)
	}
}

type RefreshEvent struct {
	Kind RefreshKind
	Err  error
}

type Policy struct {
	onRefresh func(RefreshEvent)
	whitelist *DomainSet
	extra     *DomainSet
	git       *PrefixSet
}

// New creates a Policy from the given sources. The caller is responsible for
// constructing and later closing the *iplist.Source values; New does not take
// ownership of them.
//
// A nil Whitelist is treated as an empty whitelist: every address evaluates to
// Unlisted. This also intentionally drops the blacklists, because a policy
// without a whitelist provides no meaningful allow-list semantics — blocking
// would reject everything not on the blacklist rather than only what is on it.
// The caller receives a RefreshFallback event so it can log or alert.
func New(ctx context.Context, config Config) *Policy {
	p := &Policy{onRefresh: config.OnRefresh}
	if config.Whitelist == nil {
		p.whitelist = EmptyDomainSet()
		p.emit(RefreshFallback, errors.New("whitelist source is required"))
		return p
	}

	p.whitelist = NewDomainSetFromEntries(ctx, config.Whitelist.Entries(), DefaultDomainSetRefreshInterval)
	config.Whitelist.Subscribe(func(event iplist.SourceEvent) {
		if event.Err != nil {
			p.emit(RefreshFailure, event.Err)
			return
		}
		p.whitelist.ReplaceEntries(config.Whitelist.Entries())
		p.emit(RefreshSuccess, nil)
	})

	if config.BlacklistExtra != nil {
		p.extra = NewDomainSetFromEntries(ctx, config.BlacklistExtra.Entries(), DefaultDomainSetRefreshInterval)
		config.BlacklistExtra.Subscribe(func(event iplist.SourceEvent) {
			if event.Err != nil {
				p.emit(RefreshFailure, event.Err)
				return
			}
			p.extra.ReplaceEntries(config.BlacklistExtra.Entries())
			p.emit(RefreshSuccess, nil)
		})
	} else {
		p.extra = EmptyDomainSet()
	}
	p.git = config.Blacklist
	p.emit(RefreshSuccess, nil)
	return p
}

func (p *Policy) Evaluate(addr netip.Addr) Decision {
	if p.whitelist == nil {
		return Unlisted
	}
	if p.whitelist.Contains(addr) {
		return Whitelisted
	}
	if (p.extra != nil && p.extra.Contains(addr)) ||
		(p.git != nil && p.git.Contains(addr)) {
		return Blacklisted
	}
	return Unlisted
}

func (p *Policy) Close() error {
	if p == nil {
		return nil
	}
	if p.whitelist != nil {
		_ = p.whitelist.Close()
	}
	if p.extra != nil {
		_ = p.extra.Close()
	}
	if p.git != nil {
		_ = p.git.Close()
	}
	return nil
}

func (p *Policy) emit(kind RefreshKind, err error) {
	if p.onRefresh == nil {
		return
	}
	p.onRefresh(RefreshEvent{Kind: kind, Err: err})
}
