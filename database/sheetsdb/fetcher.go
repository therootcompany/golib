// Package sheetsdb provides generic Google Sheets fetchers backed by a
// config-indexed workbook pattern. It does not provide an Updater: Sheets
// are read-only sources.
package sheetsdb

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/therootcompany/golib/database/rowsync"

	"github.com/jszwec/csvutil"
	"github.com/therootcompany/golib/io/transform/gsheet2csv"

	"github.com/therootcompany/golib/database/csvx"
)

const DefaultTimeout = 30 * time.Second
const MaxSourceBytes = 16 << 20

var ErrSourceNotFound = errors.New("source not found")
var ErrSourceNotConfigured = errors.New("source not configured")

// ConfigRow is the required shape of the workbook's index tab.
type ConfigRow struct {
	Description string `json:"description"`
	Key         string `json:"key"`
	Value       string `json:"value"`
}

// Config is the typed config-tab result. Rows stay ordered so duplicate keys
// can be detected instead of silently resolved by map iteration.
type Config struct {
	Rows []ConfigRow
}

// SourceURL returns the configured URL/path for a source key.
func (c Config) SourceURL(key string) (string, bool, bool) {
	wanted := NormalizeConfigKey(key)
	var value string
	found := false
	duplicate := false
	for _, row := range c.Rows {
		if NormalizeConfigKey(row.Key) != wanted {
			continue
		}
		if found {
			duplicate = true
			continue
		}
		value = strings.TrimSpace(row.Value)
		found = true
	}
	return value, found, duplicate
}

// Environment returns a normalized environment value. Both NAME and env:NAME
// forms are accepted.
func (c Config) Environment(name string) (string, bool, bool) {
	return c.value(NormalizeEnvironmentKey(name))
}

// EnvironmentValues returns ALL_CAPS and env:-prefixed config values.
func (c Config) EnvironmentValues() (map[string]string, error) {
	values := make(map[string]string)
	for _, row := range c.Rows {
		rawKey := strings.TrimSpace(row.Key)
		key := rawKey
		if strings.HasPrefix(strings.ToLower(key), "env:") {
			key = strings.TrimSpace(key[len("env:"):])
		} else if key != strings.ToUpper(key) {
			continue
		}
		key = strings.ToUpper(key)
		if key == "" {
			return nil, fmt.Errorf("empty environment key")
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("duplicate environment key %q", key)
		}
		values[key] = strings.TrimSpace(row.Value)
	}
	return values, nil
}

func (c Config) value(wanted string) (string, bool, bool) {
	var value string
	found := false
	duplicate := false
	for _, row := range c.Rows {
		if NormalizeEnvironmentKey(row.Key) != wanted {
			continue
		}
		if found {
			duplicate = true
			continue
		}
		value = strings.TrimSpace(row.Value)
		found = true
	}
	return value, found, duplicate
}

// NormalizeConfigKey lowercases, trims, and applies collection aliases.
func NormalizeConfigKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "profiles" {
		return "identities"
	}
	return value
}

// NormalizeEnvironmentKey normalizes an environment key by lowercasing,
// trimming, and stripping an optional env: prefix.
func NormalizeEnvironmentKey(value string) string {
	value = NormalizeConfigKey(value)
	value = strings.TrimPrefix(value, "env:")
	return value
}

// ConfigCache provides thread-safe, once-only loading of a workbook's config tab.
type ConfigCache struct {
	mu       sync.Mutex
	rows     []ConfigRow
	loaded   bool
	loading  bool
	finished chan struct{}
}

// Load fetches the config tab if not already loaded.
func (c *ConfigCache) Load(ctx context.Context, indexURL string, client *http.Client) (Config, error) {
	for {
		c.mu.Lock()
		if c.loaded {
			rows := append([]ConfigRow(nil), c.rows...)
			c.mu.Unlock()
			return Config{Rows: rows}, nil
		}
		if c.loading {
			finished := c.finished
			c.mu.Unlock()
			select {
			case <-finished:
				continue
			case <-ctx.Done():
				return Config{}, ctx.Err()
			}
		}
		c.loading = true
		c.finished = make(chan struct{})
		finished := c.finished
		c.mu.Unlock()

		rows, err := (&WebFetcher[ConfigRow]{URL: indexURL, Client: client}).Fetch(ctx)
		c.mu.Lock()
		c.loading = false
		if err == nil {
			c.rows = append([]ConfigRow(nil), rows...)
			c.loaded = true
		}
		close(finished)
		c.mu.Unlock()
		if err != nil {
			return Config{}, fmt.Errorf("fetch Google Sheets config: %w", err)
		}
		return Config{Rows: append([]ConfigRow(nil), rows...)}, nil
	}
}

var configCaches sync.Map

func sharedConfigCache(indexURL string) *ConfigCache {
	if cached, ok := configCaches.Load(indexURL); ok {
		return cached.(*ConfigCache)
	}
	cache := &ConfigCache{}
	actual, _ := configCaches.LoadOrStore(indexURL, cache)
	return actual.(*ConfigCache)
}

// LoadConfig fetches and caches the workbook config tab using a process-wide cache.
func LoadConfig(ctx context.Context, indexURL string, client *http.Client) (Config, error) {
	if strings.TrimSpace(indexURL) == "" {
		return Config{}, errors.New("a Google Sheets index URL is required")
	}
	return sharedConfigCache(indexURL).Load(ctx, indexURL, client)
}

// WebFetcher fetches one Google Sheets tab (or local CSV/TSV file) and
// decodes it into T. T should use json tags, and nullable source cells
// should use csvx fields.
type WebFetcher[T any] struct {
	URL    string
	Format string
	Client *http.Client
}

func (f *WebFetcher[T]) Init(ctx context.Context) ([]rowsync.Message, error) {
	if f == nil || strings.TrimSpace(f.URL) == "" {
		return nil, errors.New("source URL or filepath is required")
	}
	if isLocalPath(f.URL) {
		if _, err := os.Stat(f.URL); err != nil {
			return nil, fmt.Errorf("stat source %q: %w", f.URL, err)
		}
		return []rowsync.Message{{String: filepath.Base(f.URL), Type: "debug"}}, nil
	}
	csvURL, err := sheetCSVURL(f.URL)
	if err != nil {
		return nil, err
	}
	client := f.client()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, csvURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create Google Sheets request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to Google Sheets: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch from Google Sheets returned HTTP %d", resp.StatusCode)
	}
	return []rowsync.Message{{String: "Google Sheets", Type: "debug"}}, nil
}

func (f *WebFetcher[T]) Fetch(ctx context.Context) ([]T, error) {
	if f == nil || strings.TrimSpace(f.URL) == "" {
		return nil, errors.New("a Google Sheets URL is required")
	}
	body, err := f.get(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()

	format := strings.ToLower(strings.TrimSpace(f.Format))
	if format == "" {
		format = detectFormat(f.URL)
	}
	if format != "csv" && format != "tsv" && format != "tab" {
		return nil, fmt.Errorf("unsupported Google Sheets format %q", f.Format)
	}
	limited := &io.LimitedReader{R: body, N: MaxSourceBytes + 1}
	var rows []T
	if isLocalPath(f.URL) {
		reader := csv.NewReader(limited)
		reader.Comment = '#'
		if format == "tsv" || format == "tab" {
			reader.Comma = '\t'
		}
		rows, err = parseSourceCSV[T](reader)
	} else {
		reader := gsheet2csv.NewReader(limited)
		rows, err = parseSourceCSV[T](reader)
	}
	if err != nil {
		return nil, fmt.Errorf("parse Google Sheets rows from %q: %w", f.URL, err)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("the Google Sheets source exceeds %d bytes", MaxSourceBytes)
	}
	return rows, nil
}

// parseSourceCSV reads human-edited source data. Known tagged columns are
// mapped and extra columns are ignored so harmless additions do not break a
// refresh.
func parseSourceCSV[T any](reader csvutil.Reader) ([]T, error) {
	return csvx.ParseCSV[T](reader)
}

func (f *WebFetcher[T]) get(ctx context.Context) (io.ReadCloser, error) {
	if isLocalPath(f.URL) {
		return os.Open(f.URL)
	}
	csvURL, err := sheetCSVURL(f.URL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, csvURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create Google Sheets request: %w", err)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Google Sheets: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("fetch from Google Sheets returned HTTP %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func (f *WebFetcher[T]) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{Timeout: DefaultTimeout}
}

func isLocalPath(value string) bool {
	return !strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "http://") &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "https://")
}

func detectFormat(value string) string {
	if strings.HasSuffix(strings.ToLower(value), ".tsv") || strings.HasSuffix(strings.ToLower(value), ".tab") {
		return "tsv"
	}
	return "csv"
}

func sheetCSVURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid Google Sheets URL")
	}
	if !strings.Contains(u.Path, "/spreadsheets/d/") {
		return "", fmt.Errorf("URL is not a Google Sheets URL")
	}
	docID, gid := gsheet2csv.ParseIDs(rawURL)
	if docID == "" {
		return "", fmt.Errorf("the Google Sheets document ID is missing")
	}
	return gsheet2csv.ToCSVURL(docID, gid), nil
}

// IndexedFetcher resolves a source tab URL from the workbook's config tab,
// then fetches and decodes that tab into T.
type IndexedFetcher[T any] struct {
	IndexURL string
	Key      string
	Client   *http.Client
	Config   *ConfigCache
}

func (f *IndexedFetcher[T]) Init(ctx context.Context) ([]rowsync.Message, error) {
	if f == nil || strings.TrimSpace(f.IndexURL) == "" {
		return nil, errors.New("a Google Sheets index URL is required")
	}
	if strings.TrimSpace(f.Key) == "" {
		return nil, errors.New("a Google Sheets source key is required")
	}
	cache := f.Config
	if cache == nil {
		cache = sharedConfigCache(f.IndexURL)
	}
	if _, err := cache.Load(ctx, f.IndexURL, f.Client); err != nil {
		return nil, fmt.Errorf("initialize Google Sheets index: %w", err)
	}
	return []rowsync.Message{{String: "Google Sheets index", Type: "debug"}}, nil
}

func (f *IndexedFetcher[T]) Fetch(ctx context.Context) ([]T, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cache := f.Config
	if cache == nil {
		cache = sharedConfigCache(f.IndexURL)
	}
	configValue, err := cache.Load(ctx, f.IndexURL, f.Client)
	if err != nil {
		return nil, err
	}
	value, found, duplicate := configValue.SourceURL(f.Key)
	if duplicate {
		return nil, fmt.Errorf("the Google Sheets source %q is configured more than once", f.Key)
	}
	if !found {
		return nil, fmt.Errorf("%w: Google Sheets source %q", ErrSourceNotFound, f.Key)
	}
	if value != "" && isLocalPath(f.IndexURL) && isLocalPath(value) && !filepath.IsAbs(value) {
		value = filepath.Join(filepath.Dir(f.IndexURL), value)
	}
	if value == "" {
		return nil, fmt.Errorf("%w: Google Sheets source %q has an empty URL", ErrSourceNotConfigured, f.Key)
	}
	return (&WebFetcher[T]{URL: value, Client: f.Client}).Fetch(ctx)
}

// OptionalIndexedFetcher treats a missing config source as an empty source.
type OptionalIndexedFetcher[T any] struct{ Indexed IndexedFetcher[T] }

func (f *OptionalIndexedFetcher[T]) Init(ctx context.Context) ([]rowsync.Message, error) {
	if f == nil {
		return nil, errors.New("optional source is required")
	}
	return f.Indexed.Init(ctx)
}

func (f *OptionalIndexedFetcher[T]) Fetch(ctx context.Context) ([]T, error) {
	if f == nil {
		return nil, errors.New("optional source is required")
	}
	rows, err := f.Indexed.Fetch(ctx)
	if errors.Is(err, ErrSourceNotFound) || errors.Is(err, ErrSourceNotConfigured) {
		return nil, nil
	}
	return rows, err
}
