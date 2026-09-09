package ipgate

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/dnsresolver"
	"github.com/therootcompany/golib/net/ipcohort"
)

const DefaultDomainSetRefreshInterval = 5 * time.Minute

type domainSources struct {
	staticPrefixes []string
	domains        []string
}

type DomainSet struct {
	ctx      context.Context
	cancel   context.CancelFunc
	sources  atomic.Pointer[domainSources]
	resolved atomic.Pointer[map[string][]string]
	cohort   atomic.Pointer[ipcohort.Cohort]
	start    sync.Once
	interval time.Duration
}

func EmptyDomainSet() *DomainSet {
	ds := &DomainSet{}
	ds.cohort.Store(&ipcohort.Cohort{})
	return ds
}

// NewDomainSet creates a DomainSet from pre-parsed inputs.
// staticPrefixes is a list of CIDRs or bare IPs.
// domains is a list of hostnames to resolve periodically.
func NewDomainSet(ctx context.Context, staticPrefixes []string, domains []string, interval time.Duration) *DomainSet {
	if interval <= 0 {
		interval = DefaultDomainSetRefreshInterval
	}
	setCtx, cancel := context.WithCancel(ctx)
	ds := &DomainSet{ctx: setCtx, cancel: cancel, interval: interval}
	ds.sources.Store(&domainSources{
		staticPrefixes: append([]string(nil), staticPrefixes...),
		domains:        append([]string(nil), domains...),
	})

	ds.cohort.Store(&ipcohort.Cohort{})

	emptyResolved := make(map[string][]string)
	ds.resolved.Store(&emptyResolved)

	ds.rebuildCohort()

	log().Info("domain set loaded", "static", commaify(len(staticPrefixes)), "domains", commaify(len(domains)))

	if len(domains) > 0 {
		ds.startRefreshLoop()
	}

	return ds
}

func (ds *DomainSet) Replace(staticPrefixes, domains []string) {
	ds.sources.Store(&domainSources{
		staticPrefixes: append([]string(nil), staticPrefixes...),
		domains:        append([]string(nil), domains...),
	})
	if len(domains) > 0 {
		ds.startRefreshLoop()
	}
	ds.resolveDomains(ds.ctx)
	ds.rebuildCohort()
}

func (ds *DomainSet) startRefreshLoop() {
	ds.start.Do(func() { go ds.refreshLoop(ds.interval) })
}

func (ds *DomainSet) Close() error {
	if ds != nil && ds.cancel != nil {
		ds.cancel()
	}
	return nil
}

func (ds *DomainSet) Contains(addr netip.Addr) bool {
	cohort := ds.cohort.Load()
	if cohort == nil {
		cohort = &ipcohort.Cohort{}
		ds.cohort.CompareAndSwap(nil, cohort)
	}
	return cohort.ContainsAddr(addr)
}

func (ds *DomainSet) refreshLoop(interval time.Duration) {
	ds.resolveDomains(ds.ctx)
	ds.rebuildCohort()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ds.ctx.Done():
			return
		case <-ticker.C:
			ds.resolveDomains(ds.ctx)
			ds.rebuildCohort()
		}
	}
}

func (ds *DomainSet) resolveDomains(ctx context.Context) {
	sources := ds.sources.Load()
	if sources == nil || len(sources.domains) == 0 {
		return
	}

	prev := *ds.resolved.Load()
	next := make(map[string][]string, len(sources.domains))

	resolver := dnsresolver.New()
	for _, domain := range sources.domains {
		ips, _, err := resolver.LookupIP(ctx, domain)

		if err != nil || len(ips) == 0 {
			if old, ok := prev[domain]; ok {
				next[domain] = old
				log().Warn("resolve failed, keeping prior IPs", "domain", domain, "count", len(old), "err", err)
			} else {
				log().Warn("resolve failed, no prior data", "domain", domain, "err", err)
			}
			continue
		}

		addrs := make([]string, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
		next[domain] = addrs
	}

	ds.resolved.Store(&next)
}

func (ds *DomainSet) rebuildCohort() {
	var all []string
	sources := ds.sources.Load()
	if sources == nil {
		return
	}
	all = append(all, sources.staticPrefixes...)

	resolved := *ds.resolved.Load()
	for _, addrs := range resolved {
		for _, addr := range addrs {
			all = append(all, addr+"/32")
		}
	}

	cohort, err := ipcohort.Parse(all)
	if err != nil {
		log().Warn("domain set rebuild failed", "err", err)
	}
	if cohort != nil {
		ds.cohort.Store(cohort)
	}
}
