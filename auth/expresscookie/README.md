# expresscookie

A general-purpose package for signing and verifying secure cookies in all web applications. Its format is also compatible with the Node.js npm package [`cookie-signature`](https://www.npmjs.com/package/cookie-signature), as used by Express session middleware.

Standard HMAC HS256 signature:

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

> **Payload:** The package signs `Payload` exactly as supplied. Encode
> structured data first; the complete signed value is then URL-escaped for the
> cookie.

```go
http.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}
	payload, err := expresscookie.VerifySignedCookie(cookie.Value, secret)
	if err != nil {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}
	_, _ = w.Write(payload)
})
```

Sign and send a cookie:

```go
http.SetCookie(w, expresscookie.BuildSignedCookie(expresscookie.SessionCookie{
	Name:      "session",
	Secret:    secret,
	Path:      "/",
	Payload:   []byte(`{"user":"123"}`),
	ExpiresAt: time.Now().Add(time.Hour),
}))
```

`DecodeHexSecret` decodes and validates an `APP_SECRET`-style hexadecimal key.

## License

```
Authored in 2025 by AJ ONeal <aj@therootcompany.com>

You may use, modify, and distribute this software under the terms of
CC0-1.0, MIT, or Apache-2.0, at your option.

SPDX-License-Identifier: CC0-1.0 OR MIT OR Apache-2.0
```
