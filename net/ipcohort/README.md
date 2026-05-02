# [ipcohort](https://github.com/therootcompany/golib/tree/main/net/ipcohort)

A memory-efficient, fast IP cohort checker for blacklists, whitelists, and ad cohorts.

- 6 bytes per IP address (5 + 1 for alignment)
- binary search for /32 hosts, linear scan for CIDR ranges
- immutable cohorts — callers swap via `atomic.Pointer` for lock-free reads

## Example

Check if an IP address belongs to a cohort (such as a blacklist):

```go
cohort, err := ipcohort.LoadFile("/srv/data/inbound.txt")
if err != nil {
    log.Fatalf("load: %v", err)
}

blocked, err := cohort.Contains("92.255.85.72")
if err != nil {
    log.Fatalf("parse: %v", err)
}
if blocked {
    fmt.Println("BLOCKED")
    os.Exit(1)
}
fmt.Println("allowed")
```

`Cohort.Contains(string)` parses the address each call and returns an error
on unparseable input — callers decide fail-open vs fail-closed. If you
already have a `netip.Addr` (e.g. from `netip.ParseAddr` on a request peer),
use `Cohort.ContainsAddr(netip.Addr)` to skip the parse and the error.

## Recommended: hot-swap with `sync/dataset`

`sync/dataset` wraps the `atomic.Pointer` + refresh-loop boilerplate so live
requests see the new list without locks or restarts. Pair it with either
`gitshallow` (best when you want incremental updates and don't mind a `git`
binary in the runtime image) or `httpcache` (best for minimal images that
just need a single file over HTTPS).

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

view := dataset.Add(set, func(ctx context.Context) (*ipcohort.Cohort, error) {
    return ipcohort.LoadFile(repo.FilePath("tables/inbound/single_ips.txt"))
})

if err := set.Load(ctx); err != nil {
    log.Fatalf("initial load: %v", err)
}
go set.Tick(ctx, 47*time.Minute, func(err error) { log.Printf("refresh: %v", err) })

// in a request handler:
blocked, err := view.Value().Contains(peerIP)
if err != nil {
    http.Error(w, "bad ip", http.StatusBadRequest)
    return
}
if blocked {
    http.Error(w, "blocked", http.StatusForbidden)
    return
}
```

## Manual hot-swap: git (shallow)

Without `sync/dataset` if you want to keep the dependency surface small:

```go
import (
    "sync/atomic"
    "time"

    "github.com/therootcompany/golib/net/gitshallow"
    "github.com/therootcompany/golib/net/ipcohort"
)

var cohort atomic.Pointer[ipcohort.Cohort]

repo := gitshallow.New("https://github.com/bitwire-it/ipblocklist.git", "/srv/data/ipblocklist", 1, "")

// Init: clone if missing, pull, load.
if _, err := repo.Init(ctx); err != nil {
    log.Fatalf("init: %v", err)
}
c, err := ipcohort.LoadFile(repo.FilePath("tables/inbound/single_ips.txt"))
if err != nil {
    log.Fatalf("load: %v", err)
}
cohort.Store(c)

// Background: pull and reload when HEAD changes.
go func() {
    for range time.Tick(47 * time.Minute) {
        updated, err := repo.Sync(ctx)
        if err != nil {
            log.Printf("sync: %v", err)
            continue
        }
        if !updated {
            continue
        }
        c, err := ipcohort.LoadFile(repo.FilePath("tables/inbound/single_ips.txt"))
        if err != nil {
            log.Printf("reload: %v", err)
            continue
        }
        cohort.Store(c)
        log.Printf("reloaded %d entries", c.Size())
    }
}()
```

## Manual hot-swap: HTTP (cache)

Same pattern with `httpcache` for minimal runtime images that don't have
`git`:

```go
import (
    "sync/atomic"
    "time"

    "github.com/therootcompany/golib/net/httpcache"
    "github.com/therootcompany/golib/net/ipcohort"
)

const listURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"

var cohort atomic.Pointer[ipcohort.Cohort]

cacher := httpcache.New(listURL, "/srv/data/inbound.txt")

// Init: fetch unconditionally, load.
if _, err := cacher.Fetch(ctx); err != nil {
    log.Fatalf("fetch: %v", err)
}
c, err := ipcohort.LoadFile("/srv/data/inbound.txt")
if err != nil {
    log.Fatalf("load: %v", err)
}
cohort.Store(c)

// Background: conditional GET, reload only when content changes.
go func() {
    for range time.Tick(47 * time.Minute) {
        updated, err := cacher.Fetch(ctx)
        if err != nil {
            log.Printf("fetch: %v", err)
            continue
        }
        if !updated {
            continue
        }
        c, err := ipcohort.LoadFile("/srv/data/inbound.txt")
        if err != nil {
            log.Printf("reload: %v", err)
            continue
        }
        cohort.Store(c)
        log.Printf("reloaded %d entries", c.Size())
    }
}()
```
