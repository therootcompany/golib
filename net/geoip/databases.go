package geoip

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/oschwald/geoip2-golang"
)

// Databases holds open GeoLite2 City + ASN readers.
type Databases struct {
	City *geoip2.Reader
	ASN  *geoip2.Reader
}

// Open opens <dir>/GeoLite2-City.mmdb and <dir>/GeoLite2-ASN.mmdb.
func Open(dir string) (*Databases, error) {
	cityPath := filepath.Join(dir, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(dir, "GeoLite2-ASN.mmdb")
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
