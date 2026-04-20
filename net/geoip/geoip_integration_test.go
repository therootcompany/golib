//go:build integration

package geoip_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/httpcache"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	dir, _ := filepath.Abs(".")
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}

func geoipConf(t *testing.T) *geoip.Conf {
	t.Helper()
	dir, _ := filepath.Abs(".")
	for {
		p := filepath.Join(dir, "GeoIP.conf")
		if _, err := os.Stat(p); err == nil {
			cfg, err := geoip.ParseConf(p)
			if err != nil {
				t.Fatalf("GeoIP.conf: %v", err)
			}
			return cfg
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("GeoIP.conf not found; skipping MaxMind integration test")
	return nil
}

func newCacher(cfg *geoip.Conf, edition, path string) *httpcache.Cacher {
	return &httpcache.Cacher{
		URL:        geoip.DownloadBase + "/" + edition + "/download?suffix=tar.gz",
		Path:       path,
		AuthHeader: "Authorization",
		AuthValue:  httpcache.BasicAuth(cfg.AccountID, cfg.LicenseKey),
	}
}

func TestDownload_CityAndASN(t *testing.T) {
	cfg := geoipConf(t)
	td := testdataDir(t)

	for _, edition := range []string{geoip.CityEdition, geoip.ASNEdition} {
		path := filepath.Join(td, edition+".tar.gz")
		os.Remove(path)
		os.Remove(path + ".meta")

		updated, err := newCacher(cfg, edition, path).Fetch()
		if err != nil {
			t.Fatalf("%s Fetch: %v", edition, err)
		}
		if !updated {
			t.Errorf("%s: expected updated=true on first fetch", edition)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: file not created: %v", edition, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s: downloaded file is empty", edition)
		}
		t.Logf("%s: %d bytes", edition, info.Size())

		if _, err := os.Stat(path + ".meta"); err != nil {
			t.Errorf("%s: sidecar not written: %v", edition, err)
		}
	}
}

func TestDownload_ConditionalGet_FreshCacher(t *testing.T) {
	cfg := geoipConf(t)
	td := testdataDir(t)

	for _, edition := range []string{geoip.CityEdition, geoip.ASNEdition} {
		path := filepath.Join(td, edition+".tar.gz")

		if _, err := newCacher(cfg, edition, path).Fetch(); err != nil {
			t.Fatalf("%s initial Fetch: %v", edition, err)
		}

		updated, err := newCacher(cfg, edition, path).Fetch()
		if err != nil {
			t.Fatalf("%s fresh Fetch: %v", edition, err)
		}
		if updated {
			t.Errorf("%s: fresh cacher expected updated=false (sidecar ETag should have been used)", edition)
		}
		t.Logf("%s: fresh-cacher conditional GET correctly skipped re-download", edition)
	}
}
