package geoip

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/therootcompany/golib/net/dataset"
)

// Databases pairs city and ASN datasets. All methods are nil-safe no-ops so
// callers need not check whether geoip was configured.
type Databases struct {
	City *dataset.Dataset[geoip2.Reader]
	ASN  *dataset.Dataset[geoip2.Reader]
}

// NewDatabases creates Databases for the given paths without a Downloader
// (uses whatever is already on disk).
func NewDatabases(cityPath, asnPath string) *Databases {
	return &Databases{
		City: newDataset(nil, CityEdition, cityPath),
		ASN:  newDataset(nil, ASNEdition, asnPath),
	}
}

// NewDatabases creates Databases backed by this Downloader.
func (d *Downloader) NewDatabases(cityPath, asnPath string) *Databases {
	return &Databases{
		City: newDataset(d, CityEdition, cityPath),
		ASN:  newDataset(d, ASNEdition, asnPath),
	}
}

func newDataset(d *Downloader, edition, path string) *dataset.Dataset[geoip2.Reader] {
	var syncer dataset.Syncer
	if d != nil {
		syncer = d.NewCacher(edition, path)
	} else {
		syncer = dataset.NopSyncer{}
	}
	ds := dataset.New(syncer, func() (*geoip2.Reader, error) {
		return geoip2.Open(path)
	})
	ds.Name = edition
	ds.Close = func(r *geoip2.Reader) { r.Close() }
	return ds
}

// Init downloads (if needed) and opens both databases. Returns the first error.
// No-op on nil receiver.
func (dbs *Databases) Init() error {
	if dbs == nil {
		return nil
	}
	if err := dbs.City.Init(); err != nil {
		return err
	}
	return dbs.ASN.Init()
}

// Run starts background refresh goroutines for both databases.
// No-op on nil receiver.
func (dbs *Databases) Run(ctx context.Context, interval time.Duration) {
	if dbs == nil {
		return
	}
	go dbs.City.Run(ctx, interval)
	go dbs.ASN.Run(ctx, interval)
}

// PrintInfo writes city and ASN info for ip to w.
// No-op on nil receiver or unparseable IP.
func (dbs *Databases) PrintInfo(w io.Writer, ip string) {
	if dbs == nil {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	stdIP := addr.AsSlice()

	if rec, err := dbs.City.Load().City(stdIP); err == nil {
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
			fmt.Fprintf(w, "  Location: %s\n", strings.Join(parts, ", "))
		}
	}

	if rec, err := dbs.ASN.Load().ASN(stdIP); err == nil && rec.AutonomousSystemNumber != 0 {
		fmt.Fprintf(w, "  ASN:      AS%d %s\n",
			rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization)
	}
}
