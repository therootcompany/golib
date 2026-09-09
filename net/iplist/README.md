# net/iplist

Load and validate IP policy entries from local TSV/CSV files, cached HTTP(S)
URLs, and Google Sheets.

## Features

- **Local files**: TSV or CSV, auto-detected by content.
- **HTTP(S) URLs**: fetched with conditional GET (ETag / Last-Modified),
  cached to disk, and refreshed periodically. The cache survives process
  restarts.
- **Google Sheets**: edit/share URLs are recognised and fetched as CSV
  exports automatically.
- **Nested sources**: entries that are themselves HTTP(S) URLs are
  recursively expanded up to `MaxNestedSources` (2) levels deep.
- **Basic Auth**: credentials embedded in URL userinfo
  (`https://user:pass@host/path`) are extracted and sent via the
  `Authorization` header. The URL is stripped of credentials before
  being used as a cache key or included in error messages.
- **Content negotiation**: sends `Accept: text/tab-separated-values,
  text/csv;q=0.5` so well-behaved servers return TSV. Format is
  auto-detected from the response content (TSV if the first data line
  contains a tab, otherwise CSV).
- **Entry validation**: each non-URL entry must be an IP address, CIDR
  range, or domain name. Invalid entries cause an error.

## Usage

```go
import "github.com/therootcompany/golib/net/iplist"

// Load from a local TSV file.
entries, err := iplist.Load(ctx, "/etc/policy/allowlist.tsv", "/var/cache/iplist")

// Load from an HTTPS URL with Basic Auth.
entries, err := iplist.Load(ctx, "https://user:pass@policy.example.com/allowlist.tsv", "/var/cache/iplist")

// Load from a Google Sheet.
entries, err := iplist.Load(ctx, "https://docs.google.com/spreadsheets/d/1AbC.../edit?gid=123#gid=123", "/var/cache/iplist")
```

## Entry format

Each row in a TSV or CSV source contributes its first column as an entry.
Blank lines, comments (`#`), and an optional `network` header on the first
line are ignored. Other columns are treated as labels and discarded.

```
# Allowlist
network              note
192.0.2.1            primary
10.0.0.0/8           internal
example.com          partner
https://other.example.com/more-entries.tsv
```

In this example the URL on the last line will be fetched and its entries
expanded inline (counted as one nesting level).

## Validation

Entries must be one of:

| Type       | Examples                          |
|------------|-----------------------------------|
| IP address | `192.0.2.1`, `2001:db8::1`       |
| CIDR range | `10.0.0.0/8`, `2001:db8::/32`    |
| Domain     | `example.com`, `sub.example.com`  |
| Source URL | `https://host/path.tsv` (expanded)|

Use `iplist.Validate(s)` to check a single entry without loading a file.

## Cache resilience

On fetch failure the previous cache file is still used. If a fetch
succeeds but the new content fails to parse, the previous cache is
restored and the `.meta` sidecar is removed so the next call retries
from scratch.

## Dependencies

- [`golib/https`](../https) — internal HTTP client
- [`golib/io/transform/gsheet2csv`](../io/transform/gsheet2csv) — Google Sheet URL parsing
- [`golib/net/httpcache`](../httpcache) — conditional GET caching with disk persistence