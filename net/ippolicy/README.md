# net/ippolicy

`ippolicy` composes whitelist, blacklist-extra, and repository-backed prefix data into a fast policy
check. Sources expose lazy loading and explicit refresh; policy construction
does not start hidden refresh goroutines.

## Quick start

```go
whitelist, err := iplist.NewIPList(ctx, iplist.IPListConfig{
    Source:   "allowed.csv",
    CacheDir: "/var/cache/app/iplist",
})
if err != nil {
    return err
}
defer whitelist.Stop()

blacklist, err := ippolicy.NewIPPrefixSet(
    ctx,
    "https://github.com/bitwire-it/ipblocklist.git",
    "/var/cache/app/ipblocklist",
    []string{"ipblocklist.txt"},
    ippolicy.DefaultPrefixSetRefreshInterval,
)
if err != nil {
    return err
}
defer blacklist.Stop()

policy := ippolicy.New(ctx, ippolicy.Config{
    Whitelist: whitelist,
    Blacklist: blacklist,
})
defer policy.Stop()

evaluator, err := policy.Load(ctx, false)
if err != nil {
    slog.Warn("ip policy refresh failed", "err", err)
}

switch evaluator.Evaluate(addr) {
case ippolicy.Blacklisted:
    // reject
case ippolicy.Whitelisted, ippolicy.Unlisted:
    // continue
}
```

`Policy` owns source loading and refresh coordination. `Evaluator` is the
immutable, read-only decision snapshot. Use `Load(ctx, false)` when the current
snapshot may be used while refresh work runs; it returns the last-good evaluator
when refresh fails. `Stop` shuts down source and DNS refresh work.
Every source keeps its last-good snapshot after a failed update.

A nil whitelist produces an `Unlisted` policy and intentionally ignores
blacklists: without a whitelist there is no meaningful allow-list boundary.
