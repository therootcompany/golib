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

// DefaultCacheDir returns ~/.cache/maxmind. CLI tools use the XDG
// convention on all platforms — os.UserCacheDir's macOS default
// (~/Library/Caches) is meant for bundled desktop apps and hides the
// files from anyone looking under ~/.cache.
func DefaultCacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "maxmind"), nil
}
