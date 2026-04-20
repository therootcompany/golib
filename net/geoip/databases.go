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
	"strings"

	"github.com/oschwald/geoip2-golang"
)

// Databases holds open GeoLite2 City + ASN readers.
type Databases struct {
	City *geoip2.Reader
	ASN  *geoip2.Reader
}

// Open reads <dir>/<edition>_LATEST.tar.gz for City and ASN editions,
// extracts the .mmdb entry from each archive in memory, and returns open
// readers. No .mmdb files are written to disk.
func Open(dir string) (*Databases, error) {
	city, err := openMMDBTarGz(filepath.Join(dir, TarGzName(CityEdition)))
	if err != nil {
		return nil, fmt.Errorf("city: %w", err)
	}
	asn, err := openMMDBTarGz(filepath.Join(dir, TarGzName(ASNEdition)))
	if err != nil {
		_ = city.Close()
		return nil, fmt.Errorf("asn: %w", err)
	}
	return &Databases{City: city, ASN: asn}, nil
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
