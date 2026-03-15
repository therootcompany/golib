## Senior Go Engineer Review — Findings

### Critical

| # | Finding | File | Response |
|---|---------|------|----------|
| 1 | `Audience.MarshalJSON`: empty slice → `null` instead of `[]` (lossy round-trip) | jwt.go | Empty slice → empty string `""`, not null |
| 2 | `PrivateKey.PublicKey()` silently returns nil `CryptoPublicKey` for non-standard signers | jwk/key.go | What do you mean "non-standard"? |
| 3 | `Signer` round-robin uint64 wrap at 2⁶⁴ (theoretical, not real) | sign.go | Use atomic CompareAndSwap to wrap the value back to 1 (or 0 if you move the Add) |

### Important

| # | Finding | File | Response |
|---|---------|------|----------|
| 4 | `DefaultGracePeriod` comment says "5s" but value is `2 * time.Second` | jwt.go | Intentionally a variable that can be changed before first use |
| 5 | `KeyFetcher` creates redundant context timeout (both client timeout + ctx timeout) | fetcher.go | Eliminate the redundancy |
| 6 | `KeyFetcher.Verifier()` doesn't take `context.Context` | fetcher.go | Update comment to 2s. You rewrote that comment due to stale context |
| 7 | `NewVerifier` silently accepts duplicate KIDs | jwt.go | Add a check: consolidate the keys if they both have the same thumbprint, otherwise error |
| 8 | `Verifier.Verify` requires KID — tokens without `kid` always fail | jwt.go | Change to iterate over a slice (faster than map for small slices). If kid is "none", try comparison but allow fallthrough to next key. Default is failure. |
| 9 | EC private key `encodePrivate`: does `(*ecdsa.PrivateKey).Bytes()` return DER or raw scalar in Go 1.26? | jwk/key.go | Returns `[]byte` — fixed-length big-endian integer per SEC 1 §2.3.6 (raw format, same as `ecdh.PrivateKey.Bytes` for NIST curves) |
| 10 | Contradictory `RFCValidator` config (IgnoreIss + Iss populated) — no warning | jwt.go | Circle back later — may rename Ignore* to Optional* or use different logic |
| 11 | `formatDuration` dead subtraction on line ~1008 | jwt.go | Already removed. Check that we have a test for the <0 second case. |
| 12 | `fetchFromDiscovery` doesn't validate `jwks_uri` scheme (SSRF vector) | jwt.go | What check would you add? |

### Minor

| # | Finding | File | Response |
|---|---------|------|----------|
| 13 | `DefaultGracePeriod` is a mutable `var` (should be `const` or unexported) | jwt.go | Intentional — background request shouldn't be canceled if a single client request fails (add comment) |
| 14 | `Signer` embeds `JWKs`, leaking `Keys` as mutable public field | sign.go | Will making it lowercase fix it? If not, just put a comment for now |
| 15 | `Audience` empty slice round-trip lossy (same as #1) | jwt.go | Empty string → empty slice, empty slice → empty string |
| 16 | Stale doc (same as #4) | jwt.go | Same as #4 |
| 17 | 1024-bit RSA minimum is low (2048 recommended) | jwk/key.go | Leave it — add comment that it's for real-world compatibility and testing |
| 18 | `ecdsaDERToP1363` doesn't validate R/S fit in keySize (potential panic) | jwt.go | Validate it |
| 19 | Package doc has editing artifacts (garbled sentence) | jwt.go | Review at the end |
| 20 | TODO comments in production code | various | Review at the end |
