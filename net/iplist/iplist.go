// Package iplist loads and validates IP policy entries from local TSV/CSV
// files, cached HTTP(S) URLs, and Google Sheets.
//
// Each entry must be an IP address, CIDR range, domain name, or HTTP(S)
// URL pointing to another TSV/CSV source. URL entries are recursively
// expanded up to [MaxNestedSources] levels.
package iplist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/therootcompany/golib/https"
	"github.com/therootcompany/golib/io/transform/gsheet2csv"
	"github.com/therootcompany/golib/net/httpcache"
)

// MaxNestedSources is the maximum nesting depth for URL sources whose
// entries are themselves URLs. The top-level source is depth 0; a URL
// entry at depth 0 is expanded at depth 1, and so on. A source at
// depth MaxNestedSources+1 triggers an error.
//
// In other words, this limits *nesting* (URL-within-URL), not the total
// number of sources fetched. Sibling URLs at the same depth are all
// fetched.
const MaxNestedSources = 2

const (
	defaultMaxAge   = time.Hour
	defaultMaxBytes = 10 << 20
)

// Load reads source, which may be a local TSV/CSV file path or an HTTP(S)
// URL (including Google Sheets edit/share URLs). Entries that are
// themselves HTTP(S) URLs are recursively expanded up to
// [MaxNestedSources] levels. URL responses are cached below cacheDir and
// the cache remains available across process restarts.
//
// Each non-URL entry must be an IP address, CIDR range, or domain name.
// Invalid entries cause an error.
// Load reads source using client. A nil client uses the internal client with
// the package's standard timeout and transport policy.
func Load(ctx context.Context, source, cacheDir string, client *http.Client) ([]string, error) {
	if client == nil {
		client = https.NewInternalClient()
	}
	return load(ctx, strings.TrimSpace(source), cacheDir, make(map[string]struct{}), 0, client)
}

func load(ctx context.Context, source, cacheDir string, seen map[string]struct{}, depth int, client *http.Client) ([]string, error) {
	if source == "" {
		return nil, nil
	}
	if depth > MaxNestedSources {
		return nil, fmt.Errorf("source nesting exceeds %d levels", MaxNestedSources)
	}
	entries, err := readSource(ctx, source, cacheDir, seen, client)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if isURL(entry) {
			nested, err := load(ctx, entry, cacheDir, seen, depth+1, client)
			if err != nil {
				return nil, err
			}
			result = append(result, nested...)
			continue
		}
		if !Validate(entry) {
			return nil, fmt.Errorf("invalid entry %q: must be an IP address, CIDR range, domain name, or HTTP(S) URL", entry)
		}
		result = append(result, entry)
	}
	return result, nil
}

func isURL(s string) bool {
	parsed, err := url.Parse(s)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

// Validate reports whether s is a valid IP address, CIDR range, or domain
// name. URL entries (HTTP(S) sources to be expanded) are not considered
// valid by this function — they are handled separately by Load.
func Validate(s string) bool {
	if s == "" {
		return false
	}
	// IP address (IPv4 or IPv6).
	if net.ParseIP(s) != nil {
		return true
	}
	// CIDR range.
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	// Domain name.
	return isDomain(s)
}

// isDomain reports whether s looks like a domain name: it must contain at
// least one dot, have no scheme, and consist of valid DNS label characters.
func isDomain(s string) bool {
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return false
	}
	// Reject anything with a scheme — URLs are handled separately.
	if parsed.Scheme != "" {
		return false
	}
	// Reject whitespace, slashes, colons, and other characters that don't
	// belong in a bare domain name.
	if strings.ContainsAny(s, " \t\r\n/:@?") {
		return false
	}
	// Each label must be non-empty and contain only letters, digits, and
	// hyphens (RFC 1035).
	labels := strings.SplitSeq(s, ".")
	for label := range labels {
		if label == "" {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

func readSource(ctx context.Context, source, cacheDir string, seen map[string]struct{}, client *http.Client) ([]string, error) {
	parsed, err := url.Parse(source)
	if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		if docid, gid := gsheet2csv.ParseIDs(source); docid != "" {
			source = gsheet2csv.ToCSVURL(docid, gid)
			parsed, err = url.Parse(source)
		}
	}
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		body, err := os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("read source %q: %w", source, err)
		}
		return Parse(bytes.NewReader(body))
	}
	key := parsed.String()
	if _, ok := seen[key]; ok {
		return nil, fmt.Errorf("source cycle detected at %q", safeURL(source))
	}
	seen[key] = struct{}{}
	defer delete(seen, key)

	// Collect headers: Basic Auth from URL userinfo plus Accept for
	// content negotiation.
	header := make(http.Header)
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(parsed.User.Username()+":"+password)))
		parsed.User = nil
	}
	// Prefer TSV but accept CSV and generic content.
	header.Set("Accept", "text/tab-separated-values, text/csv;q=0.5, */*;q=0.1")

	digest := sha256.Sum256([]byte(key))
	cachePath := filepath.Join(cacheDir, "ip-sources", hex.EncodeToString(digest[:8])+".tsv")

	// Ensure the cache directory exists before httpcache tries to write.
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir for %s: %w", safeURL(source), err)
	}

	// previous is the last-known-good cache content. If the fetch fails or
	// the new content can't be parsed, we fall back to (or restore) it.
	previous, previousErr := os.ReadFile(cachePath)

	cache := httpcache.NewWith(parsed.String(), cachePath, client)
	cache.Header = header
	cache.MaxAge = defaultMaxAge
	cache.MaxBytes = defaultMaxBytes
	if _, fetchErr := cache.Update(ctx); fetchErr != nil {
		// No previous cache to fall back on — propagate the fetch error.
		if previousErr != nil {
			return nil, fmt.Errorf("fetch %s: %w", safeURL(source), fetchErr)
		}
		// Previous cache exists — fall through and read it instead.
	}
	body, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("read cached source %s: %w", safeURL(source), err)
	}
	entries, err := Parse(bytes.NewReader(body))
	if err != nil {
		// Fetch succeeded but produced unparseable content. If we had a
		// previous cache, restore it so the next call can retry cleanly.
		// On the first-ever run (no previous cache) there is nothing to
		// restore, so we just return the parse error.
		if previousErr == nil {
			_ = os.WriteFile(cachePath, previous, 0o600)
			_ = os.Remove(cachePath + ".meta")
		}
		return nil, fmt.Errorf("parse cached source %s: %w", safeURL(source), err)
	}
	return entries, nil
}

// Parse reads TSV or CSV data from r and returns the first column of each
// row. Blank lines, comments (lines starting with #), and an optional
// "network" header on the first line are ignored. Other columns are
// treated as labels and discarded.
//
// The format is auto-detected: if the first non-empty, non-comment line
// contains a tab character, TSV is assumed; otherwise CSV is used.
func Parse(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if isTSV(data) {
		return parseTSV(bytes.NewReader(data))
	}
	return parseCSV(bytes.NewReader(data))
}

// isTSV heuristically detects TSV format by checking whether the first
// non-empty, non-comment line contains a tab character.
func isTSV(data []byte) bool {
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || bytes.HasPrefix(trimmed, []byte("#")) {
			continue
		}
		return bytes.ContainsRune(line, '\t')
	}
	return false
}

func parseTSV(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	entries := make([]string, 0)
	for line := 1; scanner.Scan(); line++ {
		col, _, _ := strings.Cut(scanner.Text(), "\t")
		value := strings.TrimSpace(col)
		if value == "" || strings.HasPrefix(value, "#") || (line == 1 && strings.EqualFold(value, "network")) {
			continue
		}
		entries = append(entries, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func parseCSV(r io.Reader) ([]string, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // allow variable column counts
	cr.Comment = '#'
	records, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	entries := make([]string, 0, len(records))
	for i, record := range records {
		if len(record) == 0 {
			continue
		}
		value := strings.TrimSpace(record[0])
		if value == "" || (i == 0 && strings.EqualFold(value, "network")) {
			continue
		}
		entries = append(entries, value)
	}
	return entries, nil
}

func safeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<unparseable URL>"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
