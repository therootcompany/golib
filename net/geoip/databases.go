package geoip

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/oschwald/geoip2-golang"
)

// Databases holds open GeoLite2 City + ASN readers.
type Databases struct {
	City *geoip2.Reader
	ASN  *geoip2.Reader
}

// OpenDatabases resolves configuration, downloads stale .mmdb files (when a
// GeoIP.conf with credentials is available), and opens the readers.
//
//   - confPath=""  → auto-discover from DefaultConfPaths
//   - conf found   → auto-download to cityPath/asnPath
//   - no conf      → cityPath and asnPath must point to existing .mmdb files
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
		if err := os.MkdirAll(filepath.Dir(cityPath), 0o755); err != nil {
			return nil, err
		}
		dl := New(cfg.AccountID, cfg.LicenseKey)
		if _, err := dl.NewCacher(CityEdition, cityPath).Fetch(); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", CityEdition, err)
		}
		if _, err := dl.NewCacher(ASNEdition, asnPath).Fetch(); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", ASNEdition, err)
		}
	}
	return Open(cityPath, asnPath)
}

// Open opens city and ASN .mmdb files from the given paths.
func Open(cityPath, asnPath string) (*Databases, error) {
	city, err := geoip2.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", cityPath, err)
	}
	asn, err := geoip2.Open(asnPath)
	if err != nil {
		_ = city.Close()
		return nil, fmt.Errorf("open %s: %w", asnPath, err)
	}
	return &Databases{City: city, ASN: asn}, nil
}

// Close closes the city and ASN readers.
func (d *Databases) Close() error {
	return errors.Join(d.City.Close(), d.ASN.Close())
}

// Info is the structured result of a GeoIP lookup.
type Info struct {
	City       string `json:"city,omitempty"`
	Region     string `json:"region,omitempty"`
	Country    string `json:"country,omitempty"`
	CountryISO string `json:"country_iso,omitempty"`
	ASN        uint   `json:"asn,omitzero"`
	ASNOrg     string `json:"asn_org,omitempty"`
}

// Lookup returns city + ASN info for ip. Returns a zero Info on unparseable
// IP or database miss.
func (d *Databases) Lookup(ip string) Info {
	var info Info
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return info
	}
	stdIP := addr.AsSlice()

	if rec, err := d.City.City(stdIP); err == nil {
		info.City = rec.City.Names["en"]
		info.Country = rec.Country.Names["en"]
		info.CountryISO = rec.Country.IsoCode
		if len(rec.Subdivisions) > 0 {
			if sub := rec.Subdivisions[0].Names["en"]; sub != "" && sub != info.City {
				info.Region = sub
			}
		}
	}
	if rec, err := d.ASN.ASN(stdIP); err == nil {
		info.ASN = rec.AutonomousSystemNumber
		info.ASNOrg = rec.AutonomousSystemOrganization
	}
	return info
}
