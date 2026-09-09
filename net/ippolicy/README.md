# net/ippolicy

`ippolicy` composes independently refreshed IP sources into a fast policy
check. It uses `net/iplist` for local/HTTP source refresh and provides IP
matching, DNS refresh, and the legacy git blacklist.

## Quick start

Construct each source with `net/iplist.NewSource`, then pass them to
`ippolicy.New`:

```go
whitelist, err := iplist.NewSource(ctx, iplist.SourceConfig{
    Source:     "allowed.csv",
    CacheDir:   "/var/cache/app/iplist",
    // HTTPClient: nil, // uses golib's internal client
})
if err != nil {
    return err
}
defer whitelist.Close()

blacklistExtra, err := iplist.NewSource(ctx, iplist.SourceConfig{
    Source:     "blocked-ips-extra.tsv",
    CacheDir:   "/var/cache/app/iplist",
    Optional:   true,
})
if err != nil {
    return err
}
defer blacklistExtra.Close()

gitBlacklist, err := ippolicy.NewPrefixSet(
    ctx,
    "https://github.com/bitwire-it/ipblocklist.git",
    "/var/cache/app/ipblocklist",
    []string{"ipblocklist.txt"},
    ippolicy.DefaultPrefixSetRefreshInterval,
)
if err != nil {
    return err
}
defer gitBlacklist.Close()

policy := ippolicy.New(ctx, ippolicy.Config{
    Whitelist:      whitelist,
    Blacklist:      gitBlacklist,
    BlacklistExtra: blacklistExtra,
    OnRefresh: func(e ippolicy.RefreshEvent) {
        slog.Info("ippolicy refresh", "kind", e.Kind, "err", e.Err)
    },
})
defer policy.Close()

switch policy.Evaluate(addr) {
case ippolicy.Blacklisted:
    // reject
case ippolicy.Whitelisted, ippolicy.Unlisted:
    // continue
}
```

## Behavior

Each source refreshes independently and keeps its last valid data on failure.
Whitelist matches take precedence over blacklist matches. The policy does not
log; use `OnRefresh` for application logging and metrics.

A nil `Whitelist` produces a policy where every address evaluates to
`Unlisted`. This intentionally drops the blacklists as well: without a
whitelist the policy cannot distinguish "allowed" from "unknown", so blocking
would be meaningless. The caller receives a `RefreshFallback` event so it can
log or alert.
