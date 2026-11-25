# http/middleware/realip

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/http/middleware/realip.svg)](https://pkg.go.dev/github.com/therootcompany/golib/http/middleware/realip)

Resolves the real client address of requests that arrive through a proxy
(a TLS router, Caddy, nginx, a load balancer). Independently versioned;
composes with [`http/middleware`](../middleware) or any `net/http` chain.

## Usage

```go
import "github.com/therootcompany/golib/http/middleware/realip"

// from config: bare IPs or CIDRs; panics on a typo so a bad allow list never
// runs quietly. "0.0.0.0/0" + "::/0" is the explicit trust-all opt-in.
mw := middleware.WithMux(mux, realip.MustTrust("10.11.0.0/16", "127.0.0.1"))

// already-parsed addresses (a config struct, an IP policy snapshot)
mw := middleware.WithMux(mux, realip.Trust([]net.IP{
   net.ParseIP("10.11.2.55"), // the TLS router
}))
```

## API

| function | meaning |
|---|---|
| `Trust(trusted []net.IP)` | middleware; nil or empty trusts no proxy (fail closed) |
| `MustTrust(cidrs ...string)` | same, from strings; panics on bad input at startup |
| `PeerIP(r)` | the proxy that actually connected, even after the rewrite |

## Rules

- Forwarding headers are trusted only when the address the request actually
  arrived from is in the allow list - a client-forged `X-Forwarded-For` is
  inert.
- Resolution order: `X-Forwarded-For`, then `Forwarded` (RFC 7239), then
  `X-Real-IP` (nginx; if it appears more than once, the last value wins - it
  is the one written by the hop closest to the app). Vendor headers such as
  `CF-Connecting-IP` are not read - any CDN that sends them also sends
  `X-Forwarded-For`.
- The chain is walked from the hop nearest the app; the first address not in
  the allow list is the client. When every hop is trusted, the leftmost hop
  is used. A hop that cannot be parsed (`unknown`, `_hidden`, an IPv6 zone)
  stops the walk: no client address is inferred and the peer is used
  (fail closed).
- `r.RemoteAddr` is rewritten in place, so every handler, logger, and limiter
  sees the client address without any new API. The address the request
  actually arrived from - the proxy - is `realip.PeerIP(r)`.

Put `Trust` before the logger and before any rate limiter, or the limiter
counts the router instead of the client.
