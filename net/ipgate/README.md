# net/ipgate

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/net/ipgate.svg)](https://pkg.go.dev/github.com/therootcompany/golib/net/ipgate)

IP allowlist/blocklist for Go services. Two source types, both using
atomic-swapped `ipcohort.Cohort` for lock-free reads.

## PrefixSet — git-backed CIDR files

Fetches a shallow git repo and loads one or more plain-text CIDR files.
Refreshes every 47 minutes in the background.

```go
// Example using the bitwire-it/ipblocklist feed:
const blocklistRepo = "https://github.com/bitwire-it/ipblocklist.git"
blocklistDir := filepath.Join(os.Getenv("HOME"), ".local/share/bitwire-it/ipblocklist")

ps, err := ipgate.NewPrefixSet(ctx, blocklistRepo, blocklistDir, []string{
    "tables/inbound/single_ips.txt",
    "tables/inbound/networks.txt",
})
if err != nil {
    // handle
}
if ps.Contains(addr) {
    // blocked
}
```

## DomainSet — static prefixes + resolved hostnames

Takes pre-parsed inputs. Re-resolves hostnames every 5 minutes; retains
stale IPs if resolution fails.

```go
// Caller owns file open and csv.Reader construction.
f, _ := os.Open("allowed.csv")
defer f.Close()
cr := csv.NewReader(f)
cr.FieldsPerRecord = -1
cr.Comment = '#'
// cr.Comma = '\t'  // for .tsv

staticPrefixes, domains, err := ipgate.ParseDomainSet(cr)
if err != nil {
    // handle
}
ds := ipgate.NewDomainSet(ctx, staticPrefixes, domains)
if ds.Contains(addr) {
    // allowed
}
```

### Input format (CSV or TSV)

```
# comment
192.168.1.10          # bare IP → /32
10.0.0.0/8            # CIDR prefix
trusted.example.com   # hostname, resolved periodically
```

First row is skipped if it contains no IP, prefix, or dotted hostname
(header detection). `ParseDomainSet` accepts any `RecordReader` — caller
controls delimiter, comment char, and field-count validation.
