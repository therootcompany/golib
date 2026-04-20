package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/therootcompany/golib/net/geoip"
)

// discoverConf looks for GeoIP.conf in the current directory and then
// at ~/.config/maxmind/GeoIP.conf. Returns the path or "".
func discoverConf() string {
	if _, err := os.Stat("GeoIP.conf"); err == nil {
		return "GeoIP.conf"
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".config", "maxmind", "GeoIP.conf")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// setupGeo returns a Databases ready to Init, or nil if geoip is not configured.
//
//   - confPath="" → auto-discover GeoIP.conf from cwd and ~/.config/maxmind/
//   - conf found   → auto-download; cityPath/asnPath override the default locations
//   - conf absent  → cityPath and asnPath must point to existing .mmdb files
//   - no conf and no paths → geoip disabled (returns nil)
func setupGeo(confPath, cityPath, asnPath string) (*geoip.Databases, error) {
	if confPath == "" {
		confPath = discoverConf()
	}

	if confPath != "" {
		cfg, err := geoip.ParseConf(confPath)
		if err != nil {
			return nil, fmt.Errorf("geoip-conf: %w", err)
		}
		dbDir := cfg.DatabaseDirectory
		if dbDir == "" {
			if dbDir, err = geoip.DefaultCacheDir(); err != nil {
				return nil, fmt.Errorf("geoip cache dir: %w", err)
			}
		}
		if err := os.MkdirAll(dbDir, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dbDir, err)
		}
		if cityPath == "" {
			cityPath = filepath.Join(dbDir, geoip.CityEdition+".mmdb")
		}
		if asnPath == "" {
			asnPath = filepath.Join(dbDir, geoip.ASNEdition+".mmdb")
		}
		return geoip.New(cfg.AccountID, cfg.LicenseKey).NewDatabases(cityPath, asnPath), nil
	}

	if cityPath == "" && asnPath == "" {
		return nil, nil
	}
	// Explicit paths only — no auto-download. Init will fail if files are absent.
	return geoip.NewDatabases(cityPath, asnPath), nil
}
