## Senior Go Engineer Review — Findings

### Critical

| # | Finding | File | Response | Status |
|---|---------|------|----------|--------|
| 1 | `Audience.MarshalJSON`: empty slice → `null` instead of `[]` (lossy round-trip) | jwt.go | Empty slice → empty string `""`, not null | ✅ Fixed |
| 2 | `PrivateKey.PublicKey()` silently returns nil `CryptoPublicKey` for non-standard signers | jwk/key.go | Added `ErrSanityFail` sentinel; `PublicKey()` now returns `(*PublicKey, error)` | ✅ Fixed |
| 3 | `Signer` round-robin uint64 wrap at 2⁶⁴ (theoretical, not real) | sign.go | CAS loop keeps counter bounded to `[0, n)` — never approaches overflow | ✅ Fixed |

### Important

| # | Finding | File | Response | Status |
|---|---------|------|----------|--------|
| 4 | `DefaultGracePeriod` comment says "5s" but value is `2 * time.Second` | jwt.go | Intentionally a variable; fixed comment to say 2s | ✅ Fixed |
| 5 | `KeyFetcher` creates redundant context timeout (both client timeout + ctx timeout) | fetcher.go | Context timeout only applied when no HTTPClient timeout is set | ✅ Fixed |
| 6 | `KeyFetcher.Verifier()` doesn't take `context.Context` | fetcher.go | Intentional — background refresh must not be canceled by client request. Added doc comment. | ✅ Documented |
| 7 | `NewVerifier` silently accepts duplicate KIDs | jwt.go | Consolidates same-thumbprint keys; returns error for different material with same KID | ✅ Fixed |
| 8 | `Verifier.Verify` requires KID — tokens without `kid` always fail | jwt.go | Now iterates over slice; tokens without KID try all keys with fallthrough | ✅ Fixed |
| 9 | EC private key `encodePrivate`: does `(*ecdsa.PrivateKey).Bytes()` return DER or raw scalar in Go 1.26? | jwk/key.go | Returns fixed-length big-endian per SEC 1 §2.3.6 (raw format). Already correct. | ✅ Confirmed |
| 10 | Contradictory `RFCValidator` config (IgnoreIss + Iss populated) — no warning | jwt.go | Deferred — may rename Ignore* to Optional* or use different logic | ⏳ Later |
| 11 | `formatDuration` dead subtraction on line ~1008 | jwt.go | Already removed. Negative durations handled by `if d < 0 { d = -d }`. | ✅ Confirmed |
| 12 | `fetchFromDiscovery` doesn't validate `jwks_uri` scheme (SSRF vector) | jwk/fetch.go | Added `https://` scheme validation | ✅ Fixed |

### Minor

| # | Finding | File | Response | Status |
|---|---------|------|----------|--------|
| 13 | `DefaultGracePeriod` is a mutable `var` (should be `const` or unexported) | jwt.go | Intentional. Added comment: Verifier() has no context because background refresh shouldn't be tied to client requests. | ✅ Documented |
| 14 | `Signer` embeds `JWKs`, leaking `Keys` as mutable public field | sign.go | Can't lowercase (breaks `json:"keys"` tag). Added comment: must be exported for json.Marshal. | ✅ Documented |
| 15 | `Audience` empty slice round-trip lossy (same as #1) | jwt.go | Empty string → empty slice, empty slice → empty string | ✅ Fixed |
| 16 | Stale doc (same as #4) | jwt.go | Fixed (same as #4) | ✅ Fixed |
| 17 | 1024-bit RSA minimum is low (2048 recommended) | jwk/key.go | Added comment: for real-world compatibility and testing | ✅ Documented |
| 18 | `ecdsaDERToP1363` doesn't validate R/S fit in keySize (potential panic) | jwt.go | Added R/S byte-length check before FillBytes | ✅ Fixed |
| 19 | Package doc has editing artifacts (garbled sentence) | jwt.go | Review at the end | ⏳ Later |
| 20 | TODO comments in production code | various | Review at the end | ⏳ Later |
