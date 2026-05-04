# [dataset](https://github.com/therootcompany/golib/tree/main/sync/dataset)

Coordinate periodically-refreshed, hot-swappable values behind `atomic.Pointer`s.
One `Load` drives any number of typed views off a shared set of `Fetcher`s, so
upstreams (one `git pull`, one HTTP download) aren't re-fetched per view.

## When to use this

`dataset` earns its keep when you have **multiple typed views** that should
reload **coherently** off **one or more shared fetchers** — e.g. an IPv4
blocklist, an IPv6 blocklist, and an ASN list all sourced from the same git
repo, where all three should swap atomically when HEAD changes.

## When NOT to use this

For a **single source / single view** (one cohort from one URL or repo), raw
`atomic.Pointer[T]` plus a refresh loop is ~15 lines and pulls in nothing
extra. The fetcher's own `singleflight` already coalesces concurrent callers.

```go
var cohort atomic.Pointer[ipcohort.Cohort]

cacher := httpcache.New("https://example.com/blocklist.txt", "/srv/data/inbound.txt")
if _, err := cacher.Fetch(ctx); err != nil {
    log.Fatalf("fetch: %v", err)
}
c, err := ipcohort.LoadFile("/srv/data/inbound.txt")
if err != nil {
    log.Fatalf("load: %v", err)
}
cohort.Store(c)

go func() {
    for range time.Tick(47 * time.Minute) {
        updated, err := cacher.Fetch(ctx)
        if err != nil || !updated {
            continue
        }
        if c, err := ipcohort.LoadFile("/srv/data/inbound.txt"); err == nil {
            cohort.Store(c)
        }
    }
}()
```

Reach for `dataset` once that pattern starts repeating across multiple
files/cohorts/views in the same process.

## Example: shared git repo, multiple views

```go
import (
    "context"
    "time"

    "github.com/therootcompany/golib/net/gitshallow"
    "github.com/therootcompany/golib/net/ipcohort"
    "github.com/therootcompany/golib/sync/dataset"
)

repo := gitshallow.New(
    "https://github.com/bitwire-it/ipblocklist.git",
    "/srv/data/ipblocklist", 1, "",
)
set := dataset.NewSet(repo)

inbound := dataset.Add(set, func(ctx context.Context) (*ipcohort.Cohort, error) {
    return ipcohort.LoadFile(repo.FilePath("tables/inbound/single_ips.txt"))
})
outbound := dataset.Add(set, func(ctx context.Context) (*ipcohort.Cohort, error) {
    return ipcohort.LoadFile(repo.FilePath("tables/outbound/single_ips.txt"))
})

if err := set.Load(ctx); err != nil {
    log.Fatalf("initial load: %v", err)
}
go set.Tick(ctx, 47*time.Minute, func(err error) { log.Printf("refresh: %v", err) })

// in a request handler — lock-free reads, both views swap together:
if blocked, _ := inbound.Value().Contains(peerIP); blocked { ... }
if banned, _ := outbound.Value().Contains(destIP); banned { ... }
```

`Set.Load` runs every fetcher; if any reports a change, every view's loader
runs and the new values are installed atomically. Views that fail to load
leave the previous value in place.

## Lifecycle

- `NewSet(fetchers...)` — register the upstream sources
- `Add(set, loader)` — register a typed view; must be called before `Load`
- `Load(ctx)` — initial populate; safe to call from `main` before serving traffic
- `Tick(ctx, interval, onError)` — periodic refresh; run in a goroutine
- `Close()` — calls `Close` on any view value implementing `io.Closer` (e.g.
  `*sql.DB` or a file-backed value); cancel the `Tick` ctx first or a
  refresh-after-close can reanimate views
