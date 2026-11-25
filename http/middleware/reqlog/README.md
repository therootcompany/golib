# http/middleware/reqlog

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/http/middleware/reqlog.svg)](https://pkg.go.dev/github.com/therootcompany/golib/http/middleware/reqlog)

Request IDs and structured request logging for `net/http`, built on
`log/slog`. Independently versioned, like [`realip`](../realip).

## Usage

```go
import "github.com/therootcompany/golib/http/middleware/reqlog"

logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
red := reqlog.Redaction{
   QueryDeny: []string{"access_token", "id_token", "code", "sig"},
   Mask:      reqlog.MaskKeepLast,
}

mw := middleware.WithMux(mux,
   realip.Trust([]net.IP{ /* router */ }),   // resolve the client first
   reqlog.RequestID(),                        // one ULID per request
   reqlog.Logger(logger, red),                // one record per request
   recoverPanics,
)
```

## API

| function | meaning |
|---|---|
| `RequestID()` | middleware: reuse the router's `X-Request-Id` when sane, else mint a ULID; echo it in the response |
| `RequestIDFromContext(r)` | the request ID, for handlers, error paths, and limiters |
| `Logger(logger, red)` | middleware: exactly one slog record per completed request |
| `Redaction` | logging policy as data: `Mode`, `QueryAllow`, `QueryDeny`, `PathSecrets`, `Keep`, `Mask` |

One record per request - not a request entry and a response entry. The
record is written in a `defer`, so panics still produce a record (Recover
inside the chain writes the 500 first).

## Record schema

`request_id`, `method`, `path`, `query`, `status`, `duration_ms`, `remote`,
`proto`, `ua`, `content_length`. Headers are never logged; `Authorization`
and `Cookie` never reach the record. Run `realip.Trust` before `Logger` so
`remote` is the client rather than the router.

## Redaction

Redaction is policy as data - the logger is not forked per service.

```go
red := reqlog.Redaction{
   QueryDeny:   []string{"access_token", "id_token", "code", "sig"},
   PathSecrets: []string{"/rooms/*", "/auth/{email}"},
   Mask:        reqlog.MaskKeepLast, // the default
}
```

`/rooms/abc123?access_token=supersecret` logs as
`path=/rooms/**c123 query=access_token=*******cret`. Mask, never delete:
the last four characters survive so a support agent can correlate a ticket
with a log line without the log holding the secret. Use `MaskDelete` where
even a tail is too much. A wildcard segment (`*` or `{name}`) matches exactly
one path segment; an empty `Redaction` logs the request as-is.

### Blacklist and whitelist

Two polarities, one policy struct.

| mode | logged in full | masked | default |
|---|---|---|---|
| `RedactBlacklist` (default) | everything not in `QueryDeny` | `QueryDeny` | forgiving: name what to hide |
| `RedactWhitelist` | `QueryAllow` only | everything else | paranoid: name what may be seen |

Whitelist mode is the one that survives a new parameter being added next
month - an unknown name is masked, not leaked. A name listed in `QueryDeny`
is masked even when it is in `QueryAllow`; the deny rule wins.

```go
red := reqlog.Redaction{
   Mode:       reqlog.RedactWhitelist,
   QueryAllow: []string{"q", "limit", "request_id"},
   QueryDeny:  []string{"access_token"},
   Keep: map[string]reqlog.Keep{
      "request_id":    {Prefix: 4}, // ULIDs are time-ordered: the head is the useful half
      "access_token":  {Prefix: 3, Suffix: 2},
   },
}
```

`Keep` says how much of a masked value survives, per name: `Prefix` leading
characters, `Suffix` trailing characters, keyed by the query parameter name
or the path pattern as written (`"/rooms/*"`). Which end to keep is a data
question - a ULID's head is its timestamp, a random token's tail is what
distinguishes two events. Keeping nothing deletes the value (that is what
`MaskDelete` means); a rule that covers the whole value masks the whole
value.

Path patterns are masked in both modes - the path has no named fields to
allow-list. To widen the path policy, add patterns to `PathSecrets`.

## Status

`RequestID`, `Logger`, `statusRecorder`, and redaction (`sanitizeQuery`,
`sanitizePath`, `mask`) are implemented and tested. ArthurID's `logRequests`
and PaperOS's logger fork are superseded by this module; replacing them is a
follow-up.
