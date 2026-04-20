package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/therootcompany/golib/net/ipcohort"
)

// inbound blocklist
const (
	inboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"
	inboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/networks.txt"
)

// outbound blocklist
const (
	outboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/single_ips.txt"
	outboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/networks.txt"
)

func main() {
	cityDBPath := flag.String("city-db", "", "path to GeoLite2-City.mmdb")
	asnDBPath := flag.String("asn-db", "", "path to GeoLite2-ASN.mmdb")
	gitURL := flag.String("git", "", "clone/pull blocklist from this git URL into data-dir")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <data-dir|blacklist.txt> <ip-address>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  data-dir:      fetch blocklists via HTTP (or git with -git)\n")
		fmt.Fprintf(os.Stderr, "  blacklist.txt: load single local file as inbound list\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	dataPath := flag.Arg(0)
	ipStr := flag.Arg(1)

	var src *Sources
	switch {
	case *gitURL != "":
		src = newGitSources(*gitURL, dataPath,
			nil,
			[]string{"tables/inbound/single_ips.txt", "tables/inbound/networks.txt"},
			[]string{"tables/outbound/single_ips.txt", "tables/outbound/networks.txt"},
		)
	case strings.HasSuffix(dataPath, ".txt") || strings.HasSuffix(dataPath, ".csv"):
		src = newFileSources(nil, []string{dataPath}, nil)
	default:
		src = newHTTPSources(
			nil,
			[]HTTPSource{
				{inboundSingleURL, dataPath + "/inbound_single_ips.txt"},
				{inboundNetworkURL, dataPath + "/inbound_networks.txt"},
			},
			[]HTTPSource{
				{outboundSingleURL, dataPath + "/outbound_single_ips.txt"},
				{outboundNetworkURL, dataPath + "/outbound_networks.txt"},
			},
		)
	}

	var whitelist, inbound, outbound atomic.Pointer[ipcohort.Cohort]

	if err := src.Init(false); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := reload(src, &whitelist, &inbound, &outbound); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		size(&inbound), size(&outbound))

	// GeoIP readers.
	var cityDB, asnDB atomic.Pointer[geoip2.Reader]
	if *cityDBPath != "" {
		if r, err := geoip2.Open(*cityDBPath); err != nil {
			fmt.Fprintf(os.Stderr, "warn: city-db: %v\n", err)
		} else {
			cityDB.Store(r)
			defer r.Close()
		}
	}
	if *asnDBPath != "" {
		if r, err := geoip2.Open(*asnDBPath); err != nil {
			fmt.Fprintf(os.Stderr, "warn: asn-db: %v\n", err)
		} else {
			asnDB.Store(r)
			defer r.Close()
		}
	}

	// Keep data fresh in the background if running as a daemon.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go run(ctx, src, &whitelist, &inbound, &outbound)

	blockedInbound := containsInbound(ipStr, &whitelist, &inbound)
	blockedOutbound := containsOutbound(ipStr, &whitelist, &outbound)

	switch {
	case blockedInbound && blockedOutbound:
		fmt.Printf("%s is BLOCKED (inbound + outbound)\n", ipStr)
	case blockedInbound:
		fmt.Printf("%s is BLOCKED (inbound)\n", ipStr)
	case blockedOutbound:
		fmt.Printf("%s is BLOCKED (outbound)\n", ipStr)
	default:
		fmt.Printf("%s is allowed\n", ipStr)
	}

	printGeoInfo(ipStr, &cityDB, &asnDB)

	if blockedInbound || blockedOutbound {
		os.Exit(1)
	}
}

func printGeoInfo(ipStr string, cityDB, asnDB *atomic.Pointer[geoip2.Reader]) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return
	}
	stdIP := ip.AsSlice()

	if r := cityDB.Load(); r != nil {
		if rec, err := r.City(stdIP); err == nil {
			city := rec.City.Names["en"]
			country := rec.Country.Names["en"]
			iso := rec.Country.IsoCode
			var parts []string
			if city != "" {
				parts = append(parts, city)
			}
			if len(rec.Subdivisions) > 0 {
				if sub := rec.Subdivisions[0].Names["en"]; sub != "" && sub != city {
					parts = append(parts, sub)
				}
			}
			if country != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", country, iso))
			}
			if len(parts) > 0 {
				fmt.Printf("  Location: %s\n", strings.Join(parts, ", "))
			}
		}
	}

	if r := asnDB.Load(); r != nil {
		if rec, err := r.ASN(stdIP); err == nil && rec.AutonomousSystemNumber != 0 {
			fmt.Printf("  ASN:      AS%d %s\n", rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization)
		}
	}
}

func reload(src *Sources,
	whitelist, inbound, outbound *atomic.Pointer[ipcohort.Cohort],
) error {
	if wl, err := src.LoadWhitelist(); err != nil {
		return err
	} else if wl != nil {
		whitelist.Store(wl)
	}
	if in, err := src.LoadInbound(); err != nil {
		return err
	} else if in != nil {
		inbound.Store(in)
	}
	if out, err := src.LoadOutbound(); err != nil {
		return err
	} else if out != nil {
		outbound.Store(out)
	}
	return nil
}

func run(ctx context.Context, src *Sources,
	whitelist, inbound, outbound *atomic.Pointer[ipcohort.Cohort],
) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updated, err := src.Fetch(false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: sync: %v\n", err)
				continue
			}
			if !updated {
				continue
			}
			if err := reload(src, whitelist, inbound, outbound); err != nil {
				fmt.Fprintf(os.Stderr, "error: reload: %v\n", err)
				continue
			}
			fmt.Fprintf(os.Stderr, "reloaded: inbound=%d outbound=%d\n",
				size(inbound), size(outbound))
		case <-ctx.Done():
			return
		}
	}
}

func containsInbound(ip string, whitelist, inbound *atomic.Pointer[ipcohort.Cohort]) bool {
	if wl := whitelist.Load(); wl != nil && wl.Contains(ip) {
		return false
	}
	c := inbound.Load()
	return c != nil && c.Contains(ip)
}

func containsOutbound(ip string, whitelist, outbound *atomic.Pointer[ipcohort.Cohort]) bool {
	if wl := whitelist.Load(); wl != nil && wl.Contains(ip) {
		return false
	}
	c := outbound.Load()
	return c != nil && c.Contains(ip)
}

func size(ptr *atomic.Pointer[ipcohort.Cohort]) int {
	if c := ptr.Load(); c != nil {
		return c.Size()
	}
	return 0
}
