package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/httpcache"
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
	cityDBPath := flag.String("city-db", "", "path to GeoLite2-City.mmdb (overrides -geoip-conf)")
	asnDBPath := flag.String("asn-db", "", "path to GeoLite2-ASN.mmdb (overrides -geoip-conf)")
	geoipConf := flag.String("geoip-conf", "", "path to GeoIP.conf; auto-downloads City+ASN into data-dir")
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

	// Blocklist source.
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

	if err := src.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := reloadBlocklists(src, &whitelist, &inbound, &outbound); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		cohortSize(&inbound), cohortSize(&outbound))

	// GeoIP: resolve paths and build cachers if we have credentials.
	var cityDB, asnDB atomic.Pointer[geoip2.Reader]
	var cityCacher, asnCacher *httpcache.Cacher

	resolvedCityPath := *cityDBPath
	resolvedASNPath := *asnDBPath

	if *geoipConf != "" {
		cfg, err := geoip.ParseConf(*geoipConf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: geoip-conf: %v\n", err)
		} else {
			dbDir := cfg.DatabaseDirectory
			if dbDir == "" {
				dbDir = dataPath
			}
			d := geoip.New(cfg.AccountID, cfg.LicenseKey)
			if resolvedCityPath == "" {
				resolvedCityPath = filepath.Join(dbDir, geoip.CityEdition+".mmdb")
			}
			if resolvedASNPath == "" {
				resolvedASNPath = filepath.Join(dbDir, geoip.ASNEdition+".mmdb")
			}
			cityCacher = d.NewCacher(geoip.CityEdition, resolvedCityPath)
			asnCacher = d.NewCacher(geoip.ASNEdition, resolvedASNPath)
			if err := os.MkdirAll(dbDir, 0o755); err != nil {
				fmt.Fprintf(os.Stderr, "warn: mkdir %s: %v\n", dbDir, err)
			}
		}
	}

	// Fetch GeoIP DBs if we have cachers; otherwise just open existing files.
	if cityCacher != nil {
		if _, err := cityCacher.Fetch(); err != nil {
			fmt.Fprintf(os.Stderr, "warn: city DB fetch: %v\n", err)
		}
	}
	if asnCacher != nil {
		if _, err := asnCacher.Fetch(); err != nil {
			fmt.Fprintf(os.Stderr, "warn: ASN DB fetch: %v\n", err)
		}
	}
	openGeoIPReader(resolvedCityPath, &cityDB)
	openGeoIPReader(resolvedASNPath, &asnDB)

	// Keep everything fresh in the background if running as a daemon.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runLoop(ctx, src, &whitelist, &inbound, &outbound,
		cityCacher, asnCacher, &cityDB, &asnDB)

	// Check and report.
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

func openGeoIPReader(path string, ptr *atomic.Pointer[geoip2.Reader]) {
	if path == "" {
		return
	}
	r, err := geoip2.Open(path)
	if err != nil {
		return
	}
	if old := ptr.Swap(r); old != nil {
		old.Close()
	}
}

func runLoop(ctx context.Context, src *Sources,
	whitelist, inbound, outbound *atomic.Pointer[ipcohort.Cohort],
	cityCacher, asnCacher *httpcache.Cacher,
	cityDB, asnDB *atomic.Pointer[geoip2.Reader],
) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Blocklists.
			if updated, err := src.Fetch(); err != nil {
				fmt.Fprintf(os.Stderr, "error: blocklist sync: %v\n", err)
			} else if updated {
				if err := reloadBlocklists(src, whitelist, inbound, outbound); err != nil {
					fmt.Fprintf(os.Stderr, "error: blocklist reload: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "reloaded: inbound=%d outbound=%d\n",
						cohortSize(inbound), cohortSize(outbound))
				}
			}

			// GeoIP DBs.
			if cityCacher != nil {
				if updated, err := cityCacher.Fetch(); err != nil {
					fmt.Fprintf(os.Stderr, "error: city DB sync: %v\n", err)
				} else if updated {
					openGeoIPReader(cityCacher.Path, cityDB)
					fmt.Fprintf(os.Stderr, "reloaded: %s\n", cityCacher.Path)
				}
			}
			if asnCacher != nil {
				if updated, err := asnCacher.Fetch(); err != nil {
					fmt.Fprintf(os.Stderr, "error: ASN DB sync: %v\n", err)
				} else if updated {
					openGeoIPReader(asnCacher.Path, asnDB)
					fmt.Fprintf(os.Stderr, "reloaded: %s\n", asnCacher.Path)
				}
			}
		case <-ctx.Done():
			return
		}
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
			fmt.Printf("  ASN:      AS%d %s\n",
				rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization)
		}
	}
}

func reloadBlocklists(src *Sources,
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

func cohortSize(ptr *atomic.Pointer[ipcohort.Cohort]) int {
	if c := ptr.Load(); c != nil {
		return c.Size()
	}
	return 0
}
