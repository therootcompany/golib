package geoip

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

// Databases holds open GeoLite2 readers. A nil field means that edition
// wasn't configured. A nil *Databases means geoip is disabled; all methods
// are nil-safe no-ops so callers need not branch.
type Databases struct {
	City *geoip2.Reader
	ASN  *geoip2.Reader
}

// OpenDatabases resolves configuration, downloads stale .mmdb files (when a
// GeoIP.conf with credentials is available), and opens the readers.
//
//   - confPath=""  → auto-discover from DefaultConfPaths
//   - conf found   → auto-download; cityPath/asnPath override default locations
//   - no conf      → cityPath and asnPath must point to existing .mmdb files
//   - no conf and no paths → returns nil, nil (geoip disabled)
func OpenDatabases(confPath, cityPath, asnPath string) (*Databases, error) {
	if confPath == "" {
		for _, p := range DefaultConfPaths() {
			if _, err := os.Stat(p); err == nil {
				confPath = p
				break
			}
		}
	}

	if confPath != "" {
		cfg, err := ParseConf(confPath)
		if err != nil {
			return nil, fmt.Errorf("geoip-conf: %w", err)
		}
		dbDir := cfg.DatabaseDirectory
		if dbDir == "" {
			if dbDir, err = DefaultCacheDir(); err != nil {
				return nil, fmt.Errorf("geoip cache dir: %w", err)
			}
		}
		if err := os.MkdirAll(dbDir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dbDir, err)
		}
		if cityPath == "" {
			cityPath = filepath.Join(dbDir, CityEdition+".mmdb")
		}
		if asnPath == "" {
			asnPath = filepath.Join(dbDir, ASNEdition+".mmdb")
		}
		dl := New(cfg.AccountID, cfg.LicenseKey)
		if _, err := dl.NewCacher(CityEdition, cityPath).Fetch(); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", CityEdition, err)
		}
		if _, err := dl.NewCacher(ASNEdition, asnPath).Fetch(); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", ASNEdition, err)
		}
		return Open(cityPath, asnPath)
	}

	if cityPath == "" && asnPath == "" {
		return nil, nil
	}
	return Open(cityPath, asnPath)
}

// Open opens city and ASN .mmdb files from the given paths. Empty paths are
// treated as unconfigured (the corresponding field stays nil).
func Open(cityPath, asnPath string) (*Databases, error) {
	d := &Databases{}
	if cityPath != "" {
		r, err := geoip2.Open(cityPath)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", cityPath, err)
		}
		d.City = r
	}
	if asnPath != "" {
		r, err := geoip2.Open(asnPath)
		if err != nil {
			if d.City != nil {
				_ = d.City.Close()
			}
			return nil, fmt.Errorf("open %s: %w", asnPath, err)
		}
		d.ASN = r
	}
	return d, nil
}

// Close closes any open readers. No-op on nil receiver.
func (d *Databases) Close() error {
	if d == nil {
		return nil
	}
	var errs []error
	if d.City != nil {
		if err := d.City.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if d.ASN != nil {
		if err := d.ASN.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PrintInfo writes city and ASN info for ip to w. No-op on nil receiver or
// unparseable IP; missing readers are skipped silently.
func (d *Databases) PrintInfo(w io.Writer, ip string) {
	if d == nil {
		return
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	stdIP := addr.AsSlice()

	if d.City != nil {
		if rec, err := d.City.City(stdIP); err == nil {
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
	}

	if d.ASN != nil {
		if rec, err := d.ASN.ASN(stdIP); err == nil && rec.AutonomousSystemNumber != 0 {
			fmt.Fprintf(w, "  ASN:      AS%d %s\n",
				rec.AutonomousSystemNumber, rec.AutonomousSystemOrganization)
		}
	}
}
