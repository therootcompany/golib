# ajwt Redesign Notes

## API Summary

### Fetch functions (pub.go — standalone, no Issuer needed)

```go
FetchJWKs(ctx, jwksURL string)           → ([]PublicJWK, error)
FetchJWKsFromOIDC(ctx, baseURL string)   → ([]PublicJWK, error)  // /.well-known/openid-configuration → jwks_uri
FetchJWKsFromOAuth2(ctx, baseURL string) → ([]PublicJWK, error)  // /.well-known/oauth-authorization-server → jwks_uri
```

Both discovery functions share an internal `fetchJWKsFromDiscovery(ctx, discoveryURL)` helper
that parses the `jwks_uri` field and fetches the keys. They also return `issuer` from the
discovery doc so constructors can set `iss.URL` correctly.

### Constructors (jwt.go)

```go
New(issURL string, keys []PublicJWK, v *Validator) *Issuer
NewWithJWKs(ctx, jwksURL string, v *Validator)     → (*Issuer, error)
NewWithOIDC(ctx, baseURL string, v *Validator)     → (*Issuer, error)
NewWithOAuth2(ctx, baseURL string, v *Validator)   → (*Issuer, error)
```

`NewWithOIDC`/`NewWithOAuth2` set `iss.URL` from the discovery document's `issuer` field
(not just the caller's `baseURL`) because OIDC requires them to match.

`v *Validator` is optional (nil = UnsafeVerify only; VerifyAndValidate requires non-nil).

### Issuer struct (unexported fields, immutable after construction)

```go
type Issuer struct {
    URL       string  // exported for inspection
    validator *Validator
    keys      map[string]crypto.PublicKey  // kid → key
}

func (iss *Issuer) UnsafeVerify(tokenStr string) (*JWS, error)
func (iss *Issuer) VerifyAndValidate(tokenStr string, claims StandardClaimsSource, now time.Time) (*JWS, []string, error)
```

`UnsafeVerify` = Decode + sig verify + iss check. "Unsafe" = forgery-safe, but
exp/aud/etc. are NOT checked. Caller is responsible for claim validation.

`VerifyAndValidate` = UnsafeVerify + UnmarshalClaims(claims) + Validator.Validate(claims, now).
Requires `iss.validator != nil`.

## Validator

```go
type Validator struct {
    IgnoreIss      bool
    Iss            string   // rarely needed — Issuer.UnsafeVerify already checks iss
    IgnoreSub      bool
    Sub            string
    IgnoreAud      bool
    Aud            string
    IgnoreExp      bool
    IgnoreJti      bool
    Jti            string
    IgnoreIat      bool
    IgnoreAuthTime bool
    MaxAge         time.Duration
    IgnoreNonce    bool
    Nonce          string
    IgnoreAmr      bool
    RequiredAmrs   []string
    IgnoreAzp      bool
    Azp            string
}

func (v Validator) Validate(claims StandardClaimsSource, now time.Time) ([]string, error)
```

`Validate` calls `claims.GetStandardClaims()` to extract the standard fields, then runs
`ValidateStandardClaims`. The caller does not need to unmarshal separately.

### Standalone validation (no Issuer)

```go
ValidateStandardClaims(claims StandardClaims, v Validator, now time.Time) ([]string, error)
```

## StandardClaimsSource interface (the key design question)

```go
// StandardClaimsSource is implemented for free by any struct that embeds StandardClaims.
type StandardClaimsSource interface {
    GetStandardClaims() StandardClaims
}
```

`StandardClaims` itself implements it:

```go
func (sc StandardClaims) GetStandardClaims() StandardClaims { return sc }
```

Because of Go's method promotion, any embedding struct gets this for free:

```go
type AppClaims struct {
    ajwt.StandardClaims        // promotes GetStandardClaims() — zero boilerplate
    Email string `json:"email"`
    Roles []string `json:"roles"`
}
// AppClaims now satisfies StandardClaimsSource automatically.
```

### Why not generics?

A generic `Issuer[C StandardClaimsSource]` locks one claims type per issuer instance.
In practice, a service uses the same Issuer (created at startup) across different handlers
that may want different claims types. A package-level generic function works too:

```go
// Package-level generic (no generic Issuer needed):
jws, claims, errs, err := ajwt.VerifyAndValidate[AppClaims](iss, tokenStr, time.Now())
```

This avoids the output-parameter form, but Go can't infer C from the return type so
the type argument is always required at the call site. It's a viable option if the
output-parameter form feels awkward.

**Current recommendation:** output-parameter form with `StandardClaimsSource`.
It mirrors `json.Unmarshal` ergonomics and keeps the Issuer non-generic.

```go
var claims AppClaims
jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, time.Now())
// claims is populated AND standard claims are validated
// add custom validation here: if claims.Email == "" { ... }
```

## PublicJWK

```go
type PublicJWK struct {
    Key crypto.PublicKey
    KID string   // key ID from JWKS; set to Thumbprint() if absent in source
    Use string   // "sig", "enc", etc.
}

// Thumbprint computes the RFC 7638 JWK Thumbprint (SHA-256 of canonical key fields).
// Can be used as a KID when none is provided.
func (k PublicJWK) Thumbprint() (string, error)
```

Thumbprint canonical forms (lexicographic field order per RFC 7638):
- EC:  `{"crv":…, "kty":"EC", "x":…, "y":…}`
- RSA: `{"e":…, "kty":"RSA", "n":…}`
- OKP: `{"crv":"Ed25519", "kty":"OKP", "x":…}`

When parsing a JWKS where a key has no `kid` field, auto-populate `KID` from `Thumbprint()`.

Typed accessors (already exist):
```go
func (k PublicJWK) ECDSA() (*ecdsa.PublicKey, bool)
func (k PublicJWK) RSA()   (*rsa.PublicKey, bool)
func (k PublicJWK) EdDSA() (ed25519.PublicKey, bool)
```

## Full flow examples

### With VerifyAndValidate

```go
iss, err := ajwt.NewWithOIDC(ctx, "https://accounts.google.com",
    &ajwt.Validator{Aud: "my-client-id", IgnoreIss: true})

// Per request:
var claims AppClaims
jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, time.Now())
if err != nil { /* hard error: bad sig, expired, etc. */ }
if len(errs) > 0 { /* soft errors: wrong aud, missing amr, etc. */ }
// Custom checks:
if claims.Email == "" { ... }
```

### With UnsafeVerify (custom validation only)

```go
iss, err := ajwt.New("https://example.com", keys, nil)

jws, err := iss.UnsafeVerify(tokenStr)
var claims AppClaims
jws.UnmarshalClaims(&claims)
errs, err := ajwt.ValidateStandardClaims(claims.StandardClaims,
    ajwt.Validator{Aud: "myapp"}, time.Now())
// plus custom checks
```

## Open questions

- Should `VerifyAndValidate` with nil `validator` error, or silently behave like `UnsafeVerify`?
  → Lean toward error: loud failure beats silent no-op.
- Should `Validator.IgnoreIss` default to true when used via `VerifyAndValidate`
  (since `UnsafeVerify` already checks iss)?
  → Document it; don't auto-set — caller controls what they validate.
