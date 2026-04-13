# xhubsig

Verify [X-Hub-Signature-256](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries) HMAC-SHA256 webhook signatures. HTTP middleware included.

```sh
go get github.com/therootcompany/golib/auth/xhubsig
```

## Middleware

Wrap any `http.Handler`. Verified body is buffered and re-readable by the next handler.

```go
x := xhubsig.New(webhookSecret)
mux.Handle("POST /webhook", x.Require(handleWebhook))
```

Require both SHA-256 and SHA-1 (all must pass):

```go
x := xhubsig.New(webhookSecret, xhubsig.SHA256, xhubsig.SHA1)
```

Accept either SHA-256 or SHA-1 (at least one must be present; all present must pass):

```go
x := xhubsig.New(webhookSecret, xhubsig.SHA256, xhubsig.SHA1)
x.AcceptAny = true
```

Raise the body limit (default 256 KiB):

```go
x.Limit = 1 << 20 // 1 MiB
```

## Sign / Verify

Compute a signature (for sending or testing):

```go
sig := xhubsig.Sign(xhubsig.SHA256, secret, body)
// → "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
```

Verify a signature directly:

```go
err := xhubsig.Verify(xhubsig.SHA256, secret, body, r.Header.Get("X-Hub-Signature-256"))
if errors.Is(err, xhubsig.ErrMissingSignature) { ... }
if errors.Is(err, xhubsig.ErrInvalidSignature) { ... }
```

Signature format: `sha256=<hex hmac-sha256 of raw request body>` using the webhook secret as the HMAC key. sha256 is the default algorithm.

## Error responses

Errors honor the `Accept` header; `Content-Type` matches. Default is TSV.

| `Accept` | Format |
|---|---|
| `text/tab-separated-values` | vertical key-value TSV *(default)* |
| `text/html` | `text/plain` TSV *(browser-safe)* |
| `application/json` | JSON object |
| `text/csv` | vertical key-value CSV |
| `text/markdown` | pipe table |

TSV example (`missing_signature`):

```
field	value
error	missing_signature
description	No valid signature header was found.
hint	X-Hub-Signature-256 is required. `X-Hub-Signature-256: sha256=hex(hmac_sha256(secret, body))`
```

JSON example:

```json
{
  "error": "missing_signature",
  "description": "No valid signature header was found.",
  "hint": "X-Hub-Signature-256 is required.\n`X-Hub-Signature-256: sha256=hex(hmac_sha256(secret, body))`"
}
```

Error codes: `missing_signature`, `invalid_signature`, `body_too_large`.

## License

CC0-1.0. Public domain.
