package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/therootcompany/golib/net/dataset"
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

	// Build typed datasets from the source.
	// blGroup.Init() calls src.Fetch() which handles initial git clone and HTTP download.
	blGroup, whitelistDS, inboundDS, outboundDS := src.Datasets()
	if err := blGroup.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		cohortSize(inboundDS), cohortSize(outboundDS))

	// GeoIP datasets.
	resolvedCityPath := *cityDBPath
	resolvedASNPath := *asnDBPath

	var cityDS, asnDS *dataset.Dataset[geoip2.Reader]

	if *geoipConf != "" {
		cfg, err := geoip.ParseConf(*geoipConf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: geoip-conf: %v\n", err)
		} else {
			dbDir := cfg.DatabaseDirectory
			if dbDir == "" {
				dbDir = dataPath
			}
			if err := os.MkdirAll(dbDir, 0o755); err != nil {
				fmt.Fprintf(os.Stderr, "warn: mkdir %s: %v\n", dbDir, err)
			}
			d := geoip.New(cfg.AccountID, cfg.LicenseKey)
			if resolvedCityPath == "" {
				resolvedCityPath = filepath.Join(dbDir, geoip.CityEdition+".mmdb")
			}
			if resolvedASNPath == "" {
				resolvedASNPath = filepath.Join(dbDir, geoip.ASNEdition+".mmdb")
			}
			cityDS = newGeoIPDataset(d, geoip.CityEdition, resolvedCityPath)
			asnDS = newGeoIPDataset(d, geoip.ASNEdition, resolvedASNPath)
		}
	} else {
		// Manual paths: no auto-download, just open existing files.
		if resolvedCityPath != "" {
			cityDS = newGeoIPDataset(nil, "", resolvedCityPath)
		}
		if resolvedASNPath != "" {
			asnDS = newGeoIPDataset(nil, "", resolvedASNPath)
		}
	}

	if cityDS != nil {
		if err := cityDS.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "warn: city DB: %v\n", err)
		}
	}
	if asnDS != nil {
		if err := asnDS.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "warn: ASN DB: %v\n", err)
		}
	}

	// Keep everything fresh in the background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go blGroup.Run(ctx, 47*time.Minute)
	if cityDS != nil {
		go cityDS.Run(ctx, 47*time.Minute)
	}
	if asnDS != nil {
		go asnDS.Run(ctx, 47*time.Minute)
	}

	// Check and report.
	blockedInbound := containsInbound(ipStr, whitelistDS, inboundDS)
	blockedOutbound := containsOutbound(ipStr, whitelistDS, outboundDS)

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

	printGeoInfo(ipStr, cityDS, asnDS)

	if blockedInbound || blockedOutbound {
		os.Exit(1)
	}
}

// newGeoIPDataset creates a Dataset[geoip2.Reader]. If d is nil, only
// opens the existing file (no download). Close is wired to Reader.Close.
func newGeoIPDataset(d *geoip.Downloader, edition, path string) *dataset.Dataset[geoip2.Reader] {
	var syncer httpcache.Syncer
	if d != nil {
		syncer = d.NewCacher(edition, path)
	} else {
		syncer = httpcache.NopSyncer{}
	}
	ds := dataset.New(syncer, func() (*geoip2.Reader, error) {
		return geoip2.Open(path)
	})
	ds.Name = edition
	ds.Close = func(r *geoip2.Reader) { r.Close() }
	return ds
}

func containsInbound(ip string,
	whitelist, inbound *dataset.View[ipcohort.Cohort],
) bool {
	if whitelist != nil {
		if wl := whitelist.Load(); wl != nil && wl.Contains(ip) {
			return false
		}
	}
	if inbound == nil {
		return false
	}
	c := inbound.Load()
	return c != nil && c.Contains(ip)
}

func containsOutbound(ip string,
	whitelist, outbound *dataset.View[ipcohort.Cohort],
) bool {
	if whitelist != nil {
		if wl := whitelist.Load(); wl != nil && wl.Contains(ip) {
			return false
		}
	}
	if outbound == nil {
		return false
	}
	c := outbound.Load()
	return c != nil && c.Contains(ip)
}

func printGeoInfo(ipStr string, cityDS, asnDS *dataset.Dataset[geoip2.Reader]) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return
	}
	stdIP := ip.AsSlice()

	if cityDS != nil {
		if r := cityDS.Load(); r != nil {
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
	}

	if asnDS != nil {
		if r := asnDS.Load(); r != nil {
			if rec, err := r.ASN(stdIP); err == nil && rec.AutonomousSystemNumber != 0 {
				fmt.Printf("  ASN:      AS%d %s\n",
					rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization)
			}
		}
	}
}

func cohortSize(ds *dataset.View[ipcohort.Cohort]) int {
	if ds == nil {
		return 0
	}
	if c := ds.Load(); c != nil {
		return c.Size()
	}
	return 0
}
