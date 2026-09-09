package ipgate

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/dnsresolver"
	"github.com/therootcompany/golib/net/ipcohort"
)

const domainSetRefreshInterval = 5 * time.Minute

type DomainSet struct {
	staticPrefixes []string
	domains        []string
	resolved       atomic.Pointer[map[string][]string]
	cohort         atomic.Pointer[ipcohort.Cohort]
}

func EmptyDomainSet() *DomainSet {
	ds := &DomainSet{}
	ds.cohort.Store(&ipcohort.Cohort{})
	return ds
}

// NewDomainSet creates a DomainSet from pre-parsed inputs.
// staticPrefixes is a list of CIDRs or bare IPs.
// domains is a list of hostnames to resolve periodically.
func NewDomainSet(ctx context.Context, staticPrefixes []string, domains []string) *DomainSet {
	ds := &DomainSet{
		staticPrefixes: staticPrefixes,
		domains:        domains,
	}

	emptyResolved := make(map[string][]string)
	ds.resolved.Store(&emptyResolved)

	ds.rebuildCohort()

	log().Info("domain set loaded", "static", commaify(len(staticPrefixes)), "domains", commaify(len(domains)))

	go ds.refreshLoop(ctx)

	return ds
}

func (ds *DomainSet) Contains(addr netip.Addr) bool {
	cohort := ds.cohort.Load()
	return cohort != nil && cohort.ContainsAddr(addr)
}

func (ds *DomainSet) refreshLoop(ctx context.Context) {
	ds.resolveDomains(ctx)
	ds.rebuildCohort()

	ticker := time.NewTicker(domainSetRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ds.resolveDomains(ctx)
			ds.rebuildCohort()
		}
	}
}

func (ds *DomainSet) resolveDomains(ctx context.Context) {
	if len(ds.domains) == 0 {
		return
	}

	prev := *ds.resolved.Load()
	next := make(map[string][]string, len(ds.domains))

	resolver := dnsresolver.New()
	for _, domain := range ds.domains {
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
	all = append(all, ds.staticPrefixes...)

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
