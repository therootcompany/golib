package geoip

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/therootcompany/golib/net/httpcache"
)

const (
	CityEdition    = "GeoLite2-City"
	ASNEdition     = "GeoLite2-ASN"
	CountryEdition = "GeoLite2-Country"

	downloadBase     = "https://download.maxmind.com/geoip/databases"
	defaultFreshDays = 3
	defaultTimeout   = 5 * time.Minute
)

// Downloader fetches MaxMind GeoLite2 .mmdb files from the download API.
// For one-shot use call Fetch; for polling loops call NewCacher and reuse
// the Cacher so ETag state is preserved across calls.
type Downloader struct {
	AccountID  string
	LicenseKey string
	FreshDays  int           // 0 uses 3
	Timeout    time.Duration // 0 uses 5m
}

// New returns a Downloader configured with the given credentials.
func New(accountID, licenseKey string) *Downloader {
	return &Downloader{AccountID: accountID, LicenseKey: licenseKey}
}

// NewCacher returns an httpcache.Cacher pre-configured for this edition and
// path. Hold the Cacher and call Fetch() on it periodically — ETag state is
// preserved across calls, enabling conditional GETs that skip the download
// count on unchanged releases.
func (d *Downloader) NewCacher(edition, path string) *httpcache.Cacher {
	freshDays := d.FreshDays
	if freshDays == 0 {
		freshDays = defaultFreshDays
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	creds := base64.StdEncoding.EncodeToString([]byte(d.AccountID + ":" + d.LicenseKey))
	return &httpcache.Cacher{
		URL:        fmt.Sprintf("%s/%s/download?suffix=tar.gz", downloadBase, edition),
		Path:       path,
		MaxAge:     time.Duration(freshDays) * 24 * time.Hour,
		Timeout:    timeout,
		AuthHeader: "Authorization",
		AuthValue:  "Basic " + creds,
		Transform:  ExtractMMDB,
	}
}

// Fetch downloads edition to path if the file is stale. Convenience wrapper
// around NewCacher for one-shot use; ETag state is not retained.
func (d *Downloader) Fetch(edition, path string) (bool, error) {
	return d.NewCacher(edition, path).Fetch()
}

// ExtractMMDB reads a MaxMind tar.gz archive, writes the .mmdb entry to path
// atomically (via tmp+rename), and sets its mtime to MaxMind's release date.
func ExtractMMDB(r io.Reader, path string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("no .mmdb file found in archive")
		}
		if err != nil {
			return err
		}
		if !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}

		tmp := path + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
		f.Close()

		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			return err
		}

		// Preserve MaxMind's release date so mtime == data age, not download time.
		if !hdr.ModTime.IsZero() {
			os.Chtimes(path, hdr.ModTime, hdr.ModTime)
		}

		return nil
	}
}
