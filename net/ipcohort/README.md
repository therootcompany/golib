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

if cohort.Contains("92.255.85.72") {
    fmt.Println("BLOCKED")
    os.Exit(1)
}
fmt.Println("allowed")
```

## Update the list periodically: git (shallow)

```go
import (
    "sync/atomic"

    "github.com/therootcompany/golib/net/gitshallow"
    "github.com/therootcompany/golib/net/ipcohort"
)

var cohort atomic.Pointer[ipcohort.Cohort]

repo := gitshallow.New("https://github.com/bitwire-it/ipblocklist.git", "/srv/data/ipblocklist", 1, "")

// Init: clone if missing, pull, load.
if _, err := repo.Init(false); err != nil {
    log.Fatalf("init: %v", err)
}
c, err := ipcohort.LoadFile("/srv/data/ipblocklist/tables/inbound/single_ips.txt")
if err != nil {
    log.Fatalf("load: %v", err)
}
cohort.Store(c)

// Background: pull and reload when HEAD changes.
go func() {
    ticker := time.NewTicker(47 * time.Minute)
    defer ticker.Stop()
    for range ticker.C {
        updated, err := repo.Sync(false)
        if err != nil {
            log.Printf("sync: %v", err)
            continue
        }
        if !updated {
            continue
        }
        c, err := ipcohort.LoadFile("/srv/data/ipblocklist/tables/inbound/single_ips.txt")
        if err != nil {
            log.Printf("reload: %v", err)
            continue
        }
        cohort.Store(c)
        log.Printf("reloaded %d entries", cohort.Load().Size())
    }
}()
```

## Update the list periodically: HTTP (cache)

```go
import (
    "sync/atomic"

    "github.com/therootcompany/golib/net/httpcache"
    "github.com/therootcompany/golib/net/ipcohort"
)

const listURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"

var cohort atomic.Pointer[ipcohort.Cohort]

cacher := httpcache.New(listURL, "/srv/data/inbound.txt")

// Init: fetch unconditionally, load.
if _, err := cacher.Fetch(); err != nil {
    log.Fatalf("fetch: %v", err)
}
c, err := ipcohort.LoadFile("/srv/data/inbound.txt")
if err != nil {
    log.Fatalf("load: %v", err)
}
cohort.Store(c)

// Background: conditional GET, reload only when content changes.
go func() {
    ticker := time.NewTicker(47 * time.Minute)
    defer ticker.Stop()
    for range ticker.C {
        updated, err := cacher.Fetch()
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
        log.Printf("reloaded %d entries", cohort.Load().Size())
    }
}()
```
