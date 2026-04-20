package geoip

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
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
// It checks file mtime before downloading to stay within the 30/day rate limit.
//
// MaxMind preserves the database release date as the mtime of the .mmdb entry
// inside the tar archive. After extraction, mtime reflects data age — not
// download time — so it is reliable for freshness checks across restarts.
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

// Fetch downloads the named edition to path if the file is stale (mtime older
// than FreshDays). Returns whether the file was updated.
func (d *Downloader) Fetch(edition, path string) (bool, error) {
	freshDays := d.FreshDays
	if freshDays == 0 {
		freshDays = defaultFreshDays
	}

	if info, err := os.Stat(path); err == nil {
		if time.Since(info.ModTime()) < time.Duration(freshDays)*24*time.Hour {
			return false, nil
		}
	}

	timeout := d.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	url := fmt.Sprintf("%s/%s/download?suffix=tar.gz", downloadBase, edition)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(d.AccountID, d.LicenseKey)

	// Strip auth on redirects: MaxMind issues a 302 to a Cloudflare R2 presigned
	// URL that must not receive our credentials.
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Header.Del("Authorization")
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, url)
	}

	if err := extractMMDB(resp.Body, path); err != nil {
		return false, fmt.Errorf("%s: %w", edition, err)
	}
	return true, nil
}

// extractMMDB reads a MaxMind tar.gz archive, writes the .mmdb entry to path
// atomically (via tmp+rename), and sets its mtime to MaxMind's release date.
func extractMMDB(r io.Reader, path string) error {
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
