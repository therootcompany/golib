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

if err := policy.Load(ctx, true); err != nil {
    return err
}

switch policy.Evaluate(addr) {
case ippolicy.Blacklisted:
    // reject
case ippolicy.Whitelisted, ippolicy.Unlisted:
    // continue
}
```

Use `Load(ctx, false)` when a current snapshot may be used while refresh work
runs. Use `Start`/`Stop` only when periodic background checks are wanted.
Every source keeps its last-good snapshot after a failed update.

A nil whitelist produces an `Unlisted` policy and intentionally ignores
blacklists: without a whitelist there is no meaningful allow-list boundary.
