package geoip

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/therootcompany/golib/https"
	"github.com/therootcompany/golib/net/httpcache"
)

const DefaultFailureBackoff = 6 * time.Hour

// Fetcher downloads the GeoLite2 archives named by a GeoIP.conf. It
// implements dataset.Fetcher and keeps freshness/backoff policy in the
// httpcache layer.
type Fetcher struct {
	ConfPath       string
	Dir            string
	BaseURL        string
	FreshDays      int
	FailureBackoff time.Duration
	HTTPClient     *http.Client

	conf    *Conf
	auth    http.Header
	maxAge  time.Duration
	cachers []*httpcache.Cacher
}

// NewFetcher parses confPath and creates a fetcher for its editions.
func NewFetcher(confPath string) (*Fetcher, error) {
	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}
	conf, err := ParseConf(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", confPath, err)
	}
	if len(conf.EditionIDs) == 0 {
		return nil, fmt.Errorf("no EditionIDs found in %s", confPath)
	}
	dir := conf.DatabaseDirectory
	if dir == "" {
		dir = "."
	}
	return &Fetcher{ConfPath: confPath, Dir: dir, BaseURL: conf.BaseURL, conf: conf}, nil
}

func (f *Fetcher) ready() error {
	if f.auth != nil {
		return nil
	}
	f.auth = http.Header{"Authorization": []string{
		"Basic " + base64.StdEncoding.EncodeToString([]byte(f.conf.AccountID+":"+f.conf.LicenseKey)),
	}}
	freshDays := f.FreshDays
	if freshDays <= 0 {
		freshDays = 3
	}
	f.maxAge = time.Duration(freshDays) * 24 * time.Hour
	backoff := f.FailureBackoff
	if backoff == 0 {
		backoff = DefaultFailureBackoff
	}
	base := f.BaseURL
	if base == "" {
		base = DownloadBase
	}
	client := f.HTTPClient
	if client == nil {
		client = https.NewSlowClient(5 * time.Minute)
	}
	f.cachers = make([]*httpcache.Cacher, 0, len(f.conf.EditionIDs))
	for _, edition := range f.conf.EditionIDs {
		path := filepath.Join(f.Dir, TarGzName(edition))
		cacher := httpcache.NewWith(base+"/"+edition+"/download?suffix=tar.gz", path, client)
		cacher.MaxAge = f.maxAge
		cacher.FailureBackoff = backoff
		cacher.Header = f.auth
		f.cachers = append(f.cachers, cacher)
	}
	return nil
}

// Fetch downloads all configured editions and reports whether any changed.
func (f *Fetcher) Fetch(ctx context.Context) (bool, error) {
	if err := f.ready(); err != nil {
		return false, err
	}
	updated := false
	for _, cacher := range f.cachers {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		u, err := cacher.Fetch(ctx)
		if err != nil {
			return false, err
		}
		updated = updated || u
	}
	return updated, nil
}
