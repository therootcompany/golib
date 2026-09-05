---
name: jwt
description: Go JWT/JWS/JWK library patterns. Use when writing code that signs, verifies, or validates JWTs, implements OIDC/OAuth flows, builds JWKS endpoints, creates ACME JWS messages, or works with custom JOSE headers.
---

## Core flow

Issuer: `NewSigner` -> `Signer.SignToString` (or `Sign` + `Encode`)
Relying party: `Decode` -> `Verifier.Verify` -> `RawJWT.UnmarshalClaims` -> `Validator.Validate`

## Signing JWTs

```go
pk, _ := jwt.NewPrivateKey()               // Ed25519 by default
signer, _ := jwt.NewSigner([]*jwt.PrivateKey{pk})

token, _ := signer.SignToString(&jwt.TokenClaims{
    Iss: "https://auth.example.com",
    Sub: "user123",
    Aud: jwt.Listish{"https://api.example.com"},
    Exp: time.Now().Add(time.Hour).Unix(),
    IAt: time.Now().Unix(),
})
```

`SignToString` is the one-step path. Use `Sign` when you need the JWT object.

## Verifying + validating

```go
verifier, _ := jwt.NewVerifier(pubKeys)
jws, _ := verifier.VerifyJWT(tokenStr)   // decode + verify in one step

var claims MyCustomClaims
_ = jws.UnmarshalClaims(&claims)

validator := jwt.NewIDTokenValidator(
    []string{"https://auth.example.com"},  // iss (nil=skip, ["*"]=any)
    []string{"https://api.example.com"},   // aud (nil=skip, ["*"]=any)
    nil,                                    // azp (nil=skip)
    0,                                      // grace period (0 = 2s default)
)
_ = validator.Validate(nil, &claims, time.Now())
```

Two-step alternative: `jwt.Decode(tokenStr)` then `verifier.Verify(jws)`.

## Claims embedding pattern

Embed `TokenClaims` (minimal) or `StandardClaims` (with name/email/picture) to satisfy the `Claims` interface for free:

```go
type MyClaims struct {
    jwt.TokenClaims
    OrgID   string   `json:"org_id"`
    Roles   []string `json:"roles"`
}
```

`TokenClaims` fields: Iss, Sub, Aud, Exp, NBf, IAt, JTI, AuthTime, Nonce, AMR, AzP, ClientID, Scope (SpaceDelimited).
`StandardClaims` adds: Name, GivenName, FamilyName, Email, EmailVerified, Picture, and more.

## Custom JOSE headers

Embed `RFCHeader` in your header struct and implement `SignableJWT`:

```go
type DPoPHeader struct {
    jwt.RFCHeader
    Nonce string `json:"nonce,omitempty"`
}

type DPoPJWT struct {
    jwt.RawJWT
    Header DPoPHeader
}

func (d *DPoPJWT) GetHeader() jwt.RFCHeader { return d.Header.RFCHeader }
func (d *DPoPJWT) SetHeader(hdr jwt.Header) error {
    d.Header.RFCHeader = *hdr.GetRFCHeader()
    data, _ := json.Marshal(d.Header)
    d.Protected = []byte(base64.RawURLEncoding.EncodeToString(data))
    return nil
}
func (d *DPoPJWT) SetSignature(sig []byte) { d.Signature = sig }
```

Then sign with `signer.SignJWT(dpopJWT)`.

## Raw JWS signing (ACME, non-JWT protocols)

`SignRaw` signs arbitrary headers + payload without JWT semantics. Only `alg` is set from the key; KID is caller-controlled.

```go
hdr := &AcmeHeader{
    URL:   "https://acme.example.com/acme/new-account",
    Nonce: "server-nonce",
    JWK:   jwkBytes,
}
raw, _ := signer.SignRaw(hdr, payloadJSON)
flatJSON, _ := json.Marshal(raw)  // flattened JWS JSON
```

Header structs must embed `jwt.RFCHeader` and satisfy the `Header` interface (which `RFCHeader` provides via `GetRFCHeader()`). `RFCHeader` uses `omitempty` on KID and Typ so they are absent when empty.

## JWKS endpoint

`Signer` has `WellKnownJWKs`. Serve it directly:

```go
json.Marshal(&signer.WellKnownJWKs)  // {"keys":[...]}
```

## Validators

- `NewIDTokenValidator(iss, aud, azp, gracePeriod)` -- OIDC ID tokens (checks sub, exp, iat, auth_time)
- `NewAccessTokenValidator(iss, aud, gracePeriod)` -- RFC 9068 access tokens (checks sub, exp, iat, jti, client_id)
- Struct literal `&Validator{Checks: ...}` with `Checks` bitmask for custom validation
- A zero-value `Validator` returns `ErrMisconfigured` -- always use a constructor or set flags

Iss/Aud/AzP slice semantics: nil=unchecked, `[]string{}`=misconfigured, `[]string{"*"}`=any, `[]string{"x"}`=must match.

## Listish (JSON quirk)

`Listish` handles the JWT "aud" claim quirk: RFC 7519 allows it to be either a single string `"x"` or an array `["x","y"]`. Unmarshal accepts both; Marshal outputs string for single values, array for multiple.

## SpaceDelimited (trinary)

`SpaceDelimited` is a slice that marshals as a space-separated string in JSON. Three states: `nil` (absent, omitted via omitzero), `SpaceDelimited{}` (present empty string `""`), `SpaceDelimited{"a","b"}` (populated `"a b"`).

## Typ header validation

Call `hdr.IsAllowedTyp(errs, allowed)` between Verify and Validate. Case-insensitive per RFC 7515.
Constants: `DefaultTokenTyp = "JWT"`, `AccessTokenTyp = "at+jwt"` (RFC 9068).

## Key types

- `NewPrivateKey()` -- generates Ed25519 (default, recommended)
- `PrivateKey` -- holds `crypto.Signer` in `.Priv`, JWK metadata (KID, Use, Alg, KeyOps)
- `PublicKey` -- holds `crypto.PublicKey` in `.Pub`, JWK metadata (KID, Use, Alg, KeyOps)
- Algorithm derived from key type automatically (EdDSA, ES256, ES384, ES512, RS256)
- Type-switch on `.Pub` to access raw key: `*ecdsa.PublicKey`, `*rsa.PublicKey`, `ed25519.PublicKey`

## CLI tool (cmd/jwt)

```
jwt sign    --key <key> [claims-json]    sign claims into a compact JWT
jwt inspect [token]                      decode and display (with OIDC/OAuth2 discovery)
jwt verify  --key <key> [token]          verify signature and validate claims
jwt keygen  [--alg EdDSA]               generate a fresh private key (JWK)
```

Key sources: `--key` flag, `JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_FILE` / `JWT_PUBLIC_JWK` env vars.
Time claims: `--exp 1h`, `--nbf -5s`, `--iat +0s` (relative to `--time`), or absolute Unix epoch.

## File layout

| File | Contents |
|------|----------|
| `jwt.go` | Interfaces (VerifiableJWT, SignableJWT), RawJWT, JWT, Header, RFCHeader, Encode/Decode |
| `sign.go` | Signer, SignJWT, SignRaw, key validation |
| `verify.go` | Verifier, NewVerifier, Verify, VerifyJWT |
| `validate.go` | Validator, Checks bitmask, constructors, per-claim check methods |
| `claims.go` | TokenClaims, StandardClaims, Claims interface |
| `types.go` | NullBool, Listish, SpaceDelimited, token type constants |
| `jwk.go` | PrivateKey, PublicKey, NewPrivateKey, JWK marshal/unmarshal, thumbprint |
| `errors.go` | Sentinel errors, ValidationError, GetOAuth2Error |
| `keyfetch/` | KeyFetcher (lazy JWKS fetch + cache), FetchURL, FetchOIDC, FetchOAuth2 |
| `keyfile/` | Load/Save keys from local files (JWK, PEM, DER) |

## Examples

See `examples/` for complete working code:
- `oidc-id-token` -- standard OIDC flow with NewIDTokenValidator
- `oauth-access-token` -- RFC 9068 access tokens with NewAccessTokenValidator
- `http-middleware` -- bearer token middleware
- `mcp-server-auth` -- MCP agent auth
- `acme-jws` -- ACME JWS with SignRaw (with tests)
- `custom-header` -- reading custom JOSE header fields
- `dpop-jws` -- DPoP proof tokens with custom typ and nonce
- `cached-keys` -- remote JWKS fetching with disk persistence
- `mfa-validator` -- auth_time + MaxAge validation
- `rfc-claims` -- standard claims usage
