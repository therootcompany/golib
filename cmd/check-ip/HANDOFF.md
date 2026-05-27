# check-ip — Handoff

## Done

- Embedded web UI at `/` (index.html, app.js, style.css)
- `//go-embed web/**` + `fs.Sub(webFS, "web")` + `http.FileServer`
- `GET /check?host=` — resolves domains, returns JSON verdict
- `GET /check?` (empty host) — returns client's IP (via X-Forwarded-For / RemoteAddr)
- `GET /check?host=<ip>` — pre-fills input and auto-submits on page load
- `GET /healthz` — dataset health
- Deployed to `ip.bnna.net:3080`
- Created `go-webapp-embed` skill

## Remaining

1. **`?ip=` query param removed** — `handle()` only checks `host` now. Existing API consumers using `?ip=` will break. Fix:
   ```go
   query := cmp.Or(r.URL.Query().Get("host"), r.URL.Query().Get("ip"))
   ```

2. **`105dvh` in CSS** — not universally supported. Use `100dvh` or `min-height: 100vh`.

3. **Domain resolution uses only first result** — `net.LookupHost` can return IPv4 + IPv6. Consider showing all resolved addresses.

4. **No debouncing on client** — fast clicks send multiple requests. Add a simple debounce in app.js.

5. **Error display is raw** — DNS errors show technical messages. Could map to user-friendly text.
