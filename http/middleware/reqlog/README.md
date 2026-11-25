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
| `Redaction` | logging policy as data: `QueryDeny`, `PathSecrets`, `Mask` |

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

## Status

`RequestID`, `Logger`, `statusRecorder`, and redaction (`sanitizeQuery`,
`sanitizePath`, `mask`) are implemented and tested. ArthurID's `logRequests`
and PaperOS's logger fork are superseded by this module; replacing them is a
follow-up.
