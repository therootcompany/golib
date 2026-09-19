# expresscookie

A general-purpose package for signing and verifying secure cookies in all web applications. Its format is also compatible with the Node.js npm package [`cookie-signature`](https://www.npmjs.com/package/cookie-signature), as used by Express session middleware.

Standard HMAC-SHA256 signature:

```
secret:       example-secret-16
string:       Hello, World!
payload:      SGVsbG8sIFdvcmxkIQ==
signed value: s:SGVsbG8sIFdvcmxkIQ==.F/bW1t2GXhUIqykISYbB+FMA3lLquegPU4jYjVLsnXs
cookie value: s%3ASGVsbG8sIFdvcmxkIQ%3D%3D.F%2FbW1t2GXhUIqykISYbB%2BFMA3lLquegPU4jYjVLsnXs
```

## Usage

```sh
go get github.com/therootcompany/golib/auth/expresscookie@latest
```

Initialize the secret once during application setup:

```go
secret, err := expresscookie.NewSecret([]byte(os.Getenv("COOKIE_SECRET")))
```

> **Payload:** Encode payloads before signing (e.g., base64, JSON). The
> package signs raw bytes as supplied, but the behavior of non-encoded plain
> strings is undefined — in particular, raw payloads containing characters
> such as spaces may not interoperate with Node.js, which uses
> `encodeURIComponent` rather than query-string escaping. With zero-valued
> options, the cookie has zero-valued HTTP attributes except for the security
> defaults applied by `Sign`. These convenience defaults may change.

```go
http.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}
	signed, err := expresscookie.Parse(cookie.Value)
	if err != nil {
		return
	}
	payload, err := signed.Verify(secret)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}
	_, _ = w.Write(payload)
})
```

Sign and send a cookie:

```go
payload := base64.StdEncoding.AppendEncode(nil, []byte(`{"user":"123"}`))
cookie, err := expresscookie.New("session", payload, http.Cookie{
	Expires: time.Now().Add(time.Hour),
})
if err != nil {
	return
}
signed := cookie.Sign(secret)
http.SetCookie(w, &signed.Cookie)
```

`DecodeHexSecret` decodes and validates an `APP_SECRET`-style hexadecimal key.

## License

Authored in 2026 by AJ ONeal.

expresscookie is made available under the terms of any of the following
licenses, at your option:

1. [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/)
2. [MIT License](https://opensource.org/license/mit/)
3. [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)

SPDX-License-Identifier: CC0-1.0 OR MIT OR Apache-2.0
