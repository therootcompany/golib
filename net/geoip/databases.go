package geoip

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

// Databases holds open GeoLite2 City + ASN readers.
type Databases struct {
	City *geoip2.Reader
	ASN  *geoip2.Reader
}

// Open loads the City and ASN editions from dir. For each edition it
// prefers <edition>_LATEST.tar.gz and falls back to the
// lexicographically greatest <edition>_*.tar.gz match (MaxMind's
// Content-Disposition names sort chronologically by release date).
// Archives are extracted in memory — no .mmdb files are written to disk.
func Open(dir string) (*Databases, error) {
	cityPath, err := FindTarGz(dir, CityEdition)
	if err != nil {
		return nil, fmt.Errorf("city: %w", err)
	}
	city, err := openMMDBTarGz(cityPath)
	if err != nil {
		return nil, fmt.Errorf("city: %w", err)
	}
	asnPath, err := FindTarGz(dir, ASNEdition)
	if err != nil {
		_ = city.Close()
		return nil, fmt.Errorf("asn: %w", err)
	}
	asn, err := openMMDBTarGz(asnPath)
	if err != nil {
		_ = city.Close()
		return nil, fmt.Errorf("asn: %w", err)
	}
	return &Databases{City: city, ASN: asn}, nil
}

// FindTarGz resolves the cached tarball path for edition inside dir,
// preferring <edition>_LATEST.tar.gz and falling back to the
// lexicographically greatest <edition>_*.tar.gz match.
func FindTarGz(dir, edition string) (string, error) {
	preferred := filepath.Join(dir, TarGzName(edition))
	if _, err := os.Stat(preferred); err == nil {
		return preferred, nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, edition+"_*.tar.gz"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no %s_*.tar.gz in %s", edition, dir)
	}
	slices.Sort(matches)
	return matches[len(matches)-1], nil
}

func openMMDBTarGz(path string) (*geoip2.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip %s: %w", path, err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no .mmdb entry in %s", path)
		}
		if err != nil {
			return nil, err
		}
		if !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		return geoip2.FromBytes(data)
	}
}

// Close closes the city and ASN readers.
func (d *Databases) Close() error {
	return errors.Join(d.City.Close(), d.ASN.Close())
}

// Info is the structured result of a GeoIP lookup.
type Info struct {
	City              string   `json:"city,omitempty"`
	Region            string   `json:"region,omitempty"`
	RegionISO         string   `json:"region_iso,omitempty"`
	Country           string   `json:"country,omitempty"`
	CountryISO        string   `json:"country_iso,omitempty"`
	CountryInEU       bool     `json:"country_in_eu,omitzero"`
	RegisteredCountry string   `json:"registered_country,omitempty"`
	RegisteredCountryISO string `json:"registered_country_iso,omitempty"`
	PostalCode        string   `json:"postal_code,omitempty"`
	Continent         string   `json:"continent,omitempty"`
	ContinentCode     string   `json:"continent_code,omitempty"`
	Timezone          string   `json:"timezone,omitempty"`
	Latitude          float64  `json:"latitude,omitzero"`
	Longitude         float64  `json:"longitude,omitzero"`
	MetroCode         uint     `json:"metro_code,omitzero"`
	AccuracyRadius    uint16   `json:"accuracy_radius,omitzero"`
	ASN               uint     `json:"asn,omitzero"`
	ASNOrg            string   `json:"asn_org,omitempty"`
	Anycast           bool     `json:"anycast,omitzero"`
	AnonymousProxy    bool     `json:"anonymous_proxy,omitzero"`
	Satellite         bool     `json:"satellite,omitzero"`
}

// LookupRaw returns the raw maxmind record for ip. Returns nil on
// unparseable IP or database miss.
func (d *Databases) LookupRaw(ip string) *geoip2.City {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	rec, err := d.City.City(addr.AsSlice())
	if err != nil {
		return nil
	}
	return rec
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
		info.CountryInEU = rec.Country.IsInEuropeanUnion
		if rec.RegisteredCountry.IsoCode != "" {
			info.RegisteredCountry = rec.RegisteredCountry.Names["en"]
			info.RegisteredCountryISO = rec.RegisteredCountry.IsoCode
		}
		if len(rec.Subdivisions) > 0 {
			if sub := rec.Subdivisions[0].Names["en"]; sub != "" && sub != info.City {
				info.Region = sub
			}
			info.RegionISO = rec.Subdivisions[0].IsoCode
		}
		if rec.Postal.Code != "" {
			info.PostalCode = rec.Postal.Code
		}
		if rec.Continent.Names["en"] != "" {
			info.Continent = rec.Continent.Names["en"]
			info.ContinentCode = rec.Continent.Code
		}
		if rec.Location.TimeZone != "" {
			info.Timezone = rec.Location.TimeZone
		}
		if rec.Location.Latitude != 0 {
			info.Latitude = rec.Location.Latitude
		}
		if rec.Location.Longitude != 0 {
			info.Longitude = rec.Location.Longitude
		}
		info.MetroCode = rec.Location.MetroCode
		info.AccuracyRadius = rec.Location.AccuracyRadius
		info.Anycast = rec.Traits.IsAnycast
		info.AnonymousProxy = rec.Traits.IsAnonymousProxy
		info.Satellite = rec.Traits.IsSatelliteProvider
	}
	if rec, err := d.ASN.ASN(stdIP); err == nil {
		info.ASN = rec.AutonomousSystemNumber
		info.ASNOrg = rec.AutonomousSystemOrganization
	}
	return info
}
