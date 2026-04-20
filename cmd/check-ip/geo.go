package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/therootcompany/golib/net/geoip"
)

// setupGeo parses geoip-conf (if given) and returns a Databases ready to Init.
// Returns nil if no geoip flags were provided.
func setupGeo(confPath, cityPath, asnPath string) (*geoip.Databases, error) {
	if confPath == "" && cityPath == "" && asnPath == "" {
		return nil, nil
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
	return geoip.NewDatabases(cityPath, asnPath), nil
}
