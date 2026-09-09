// Package iplist loads newline-delimited IP policy entries from local TSV
// files and cached HTTP(S) URLs.
package iplist

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

const MaxNestedSources = 2

const (
	defaultMaxAge   = time.Hour
	defaultMaxBytes = 10 << 20
)

// Load reads source, which may be a local TSV path or an HTTP(S) URL. Entries
// that are themselves HTTP(S) URLs are recursively expanded up to
// MaxNestedSources levels. URL responses are cached below cacheDir and the
// cache remains available across process restarts.
func Load(ctx context.Context, source, cacheDir string) ([]string, error) {
	return load(ctx, strings.TrimSpace(source), cacheDir, make(map[string]struct{}), 0)
}

func load(ctx context.Context, source, cacheDir string, seen map[string]struct{}, depth int) ([]string, error) {
	if source == "" {
		return nil, nil
	}
	if depth > MaxNestedSources {
		return nil, fmt.Errorf("source nesting exceeds %d levels", MaxNestedSources)
	}
	entries, err := readSource(ctx, source, cacheDir, seen)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		parsed, parseErr := url.Parse(entry)
		if parseErr == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			nested, err := load(ctx, entry, cacheDir, seen, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, nested...)
			continue
		}
		result = append(result, entry)
	}
	return result, nil
}

func readSource(ctx context.Context, source, cacheDir string, seen map[string]struct{}) ([]string, error) {
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
		return Parse(strings.NewReader(string(body)))
	}
	key := parsed.String()
	if _, ok := seen[key]; ok {
		return nil, fmt.Errorf("source cycle detected at %q", safeURL(source))
	}
	seen[key] = struct{}{}
	defer delete(seen, key)

	var header http.Header
	if parsed.User != nil {
		header = make(http.Header)
		password, _ := parsed.User.Password()
		header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(parsed.User.Username()+":"+password)))
		parsed.User = nil
	}
	digest := sha256.Sum256([]byte(key))
	path := filepath.Join(cacheDir, "ip-sources", hex.EncodeToString(digest[:8])+".tsv")
	cache := httpcache.NewWith(parsed.String(), path, https.NewInternalClient())
	cache.Header = header
	cache.MaxAge = defaultMaxAge
	cache.MaxBytes = defaultMaxBytes
	if _, fetchErr := cache.Fetch(ctx); fetchErr != nil {
		if _, statErr := os.Stat(path); statErr != nil {
			return nil, fmt.Errorf("fetch %s: %w", safeURL(source), fetchErr)
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cached source %s: %w", safeURL(source), err)
	}
	return Parse(strings.NewReader(string(body)))
}

// Parse reads the first TSV column. Blank lines, comments, and an optional
// network header are ignored. Other columns are labels and are discarded.
func Parse(input *strings.Reader) ([]string, error) {
	scanner := bufio.NewScanner(input)
	entries := make([]string, 0)
	for line := 1; scanner.Scan(); line++ {
		value := strings.TrimSpace(strings.SplitN(scanner.Text(), "\t", 2)[0])
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
