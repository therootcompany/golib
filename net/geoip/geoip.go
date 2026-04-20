package geoip

import (
	"os"
	"path/filepath"
)

const (
	CityEdition    = "GeoLite2-City"
	ASNEdition     = "GeoLite2-ASN"
	CountryEdition = "GeoLite2-Country"

	// DownloadBase is the MaxMind databases download endpoint. Full URL:
	// <DownloadBase>/<edition>/download?suffix=tar.gz
	DownloadBase = "https://download.maxmind.com/geoip/databases"
)

// TarGzName returns the cache filename for edition's tar.gz archive.
// MaxMind's Content-Disposition names include a release date
// (e.g. GeoLite2-ASN_20260101.tar.gz); we use _LATEST so httpcache's
// ETag sidecar stays tied to a stable path across releases.
func TarGzName(edition string) string {
	return edition + "_LATEST.tar.gz"
}

// DefaultConfPaths returns the standard locations where GeoIP.conf is looked
// up: ./GeoIP.conf, then ~/.config/maxmind/GeoIP.conf.
func DefaultConfPaths() []string {
	paths := []string{"GeoIP.conf"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".config", "maxmind", "GeoIP.conf"))
	}
	return paths
}

// DefaultCacheDir returns the OS cache directory for MaxMind databases,
// e.g. ~/.cache/maxmind on Linux or ~/Library/Caches/maxmind on macOS.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "maxmind"), nil
}
