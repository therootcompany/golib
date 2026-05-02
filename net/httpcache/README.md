# [httpcache](https://github.com/therootcompany/golib/tree/main/net/httpcache)

Conditional HTTP GET to a local file. ETag / Last-Modified are persisted to a
`<path>.meta` sidecar so 304s survive process restarts.

- skips HTTP when the local file is newer than `MaxAge`
- skips HTTP when the last attempt was within `MinInterval` (in-memory)
- caps response bodies via `MaxBytes` (defends against fill-disk)
- `O_EXCL` reservation on `<path>.tmp` for cross-process exclusion;
  `singleflight` coalesces in-process callers
- safe to call `Fetch` concurrently — peers see `ErrPeerFetching`

## Example

Fetch a blocklist; re-check periodically:

```go
c := httpcache.New(
    "https://example.com/blocklist.txt",
    "/srv/data/blocklist.txt",
)
c.MaxAge = time.Hour       // skip HTTP if file is < 1h old
c.MaxBytes = 50 << 20      // 50 MiB cap

updated, err := c.Fetch(ctx)
switch {
case errors.Is(err, httpcache.ErrPeerFetching):
    // another process is downloading; reload from disk if updated==true
case err != nil:
    log.Fatalf("fetch: %v", err)
case updated:
    log.Printf("blocklist refreshed")
}
```

Pair with `*http.Client` if you need custom timeouts, transport, or a
`CheckRedirect` that strips non-standard credential headers (the stdlib
already strips `Authorization` / `Cookie` / `WWW-Authenticate` on
cross-host redirects):

```go
c := httpcache.NewWith(url, path, &http.Client{Timeout: 30 * time.Second})
c.Header = http.Header{"Authorization": []string{"Bearer " + token}}
```
