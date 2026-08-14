# jwt

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/auth/jwt.svg)](https://pkg.go.dev/github.com/therootcompany/golib/auth/jwt)

Lightweight JWT/JWS/JWK library for JOSE, OIDC, and OAuth 2.1. \
Asymmetric (Ed25519, ECDSA, RSA) and symmetric (HMAC) signing. \
Go 1.26+.

- Issuer: sign tokens, publish JWKS
- Relying Party: verify signatures, validate claims
- Key management: file-based loading, remote JWKS fetching, graceful rotation
- HMAC for legacy systems

## Issuer: Sign and Issue Tokens

Create a signer from private keys, then issue tokens with any claims type.

```go
package main

import (
   "fmt"
   "os"
   "time"

   "github.com/therootcompany/golib/auth/jwt"
   "github.com/therootcompany/golib/auth/jwt/keyfile"
)

func main() {
   privKey, err := keyfile.LoadPrivatePEM("signing-key.pem")
   if err != nil {
      panic(err)
   }

   signer, err := jwt.NewSigner([]*jwt.PrivateKey{privKey})
   if err != nil {
      panic(err)
   }

   // Publish the JWKS endpoint: json.Marshal(&signer.WellKnownJWKs)

   claims := &jwt.TokenClaims{
      Iss: "https://auth.example.com",
      Sub: "user-42",
      Aud: jwt.Listish{"https://api.example.com"},
      Exp: time.Now().Add(time.Hour).Unix(),
      IAt: time.Now().Unix(),
   }

   token, err := signer.SignToString(claims)
   if err != nil {
      panic(err)
   }

   fmt.Println(token)
}
```

## Relying Party: Verify and Validate

Verify the signature, then validate claims (exp, aud, iss, etc.).

```go
package main

import (
   "fmt"
   "os"
   "time"

   "github.com/therootcompany/golib/auth/jwt"
   "github.com/therootcompany/golib/auth/jwt/keyfile"
)

func main() {
   pubKey, err := keyfile.LoadPublicPEM("signing-key.pub")
   if err != nil {
      panic(err)
   }

   verifier, err := jwt.NewVerifier([]jwt.PublicKey{*pubKey})
   if err != nil {
      panic(err)
   }

   jws, err := verifier.VerifyJWT("eyJhbGciOiJFZERTQSIs...")
   if err != nil {
      switch err {
      case jwt.ErrUnknownKID:
         fmt.Println("Unknown signing key")
      case jwt.ErrSignatureInvalid:
         fmt.Println("Invalid signature")
      default:
         panic(err)
      }
      os.Exit(1)
   }

   var claims jwt.TokenClaims
   if err := jws.UnmarshalClaims(&claims); err != nil {
      panic(err)
   }

   validator := jwt.NewAccessTokenValidator(
      []string{"https://auth.example.com"}, // issuers
      []string{"https://api.example.com"},  // audiences
   )
   if err := validator.Validate(nil, &claims, time.Now()); err != nil {
      fmt.Printf("Claims invalid: %v\n", err)
      os.Exit(1)
   }

   fmt.Printf("Valid token for %s\n", claims.Sub)
}
```

## Key Management

For asymmetric keys, KID is auto-computed from the RFC 7638 thumbprint by default.

### Load Keys from Files

```go
privKey, err := keyfile.LoadPrivatePEM("key.pem")
pubKey, err  := keyfile.LoadPublicPEM("key.pub")
privJWK, err := keyfile.LoadPrivateJWK("key.jwk")
pubJWK, err  := keyfile.LoadPublicJWK("key.pub.jwk")
jwks, err    := keyfile.LoadWellKnownJWKs("keys.jwks.json")
```

### Fetch Keys from Remote JWKS Endpoint

```go
fetcher, err := keyfetch.NewKeyFetcher("https://auth.example.com/.well-known/jwks.json")
verifier := fetcher.Verifier()  // verifies with live remote keys
```

### Retired Keys

Pass retired public keys to `NewSigner` so they appear in the JWKS endpoint and can verify tokens signed before key rotation:

```go
oldPubKey, _ := keyfile.LoadPublicPEM("old-signing-key.pub")
newPrivKey, _ := keyfile.LoadPrivatePEM("new-signing-key.pem")

signer, err := jwt.NewSigner([]*jwt.PrivateKey{newPrivKey}, oldPubKey)
```

The retired key is never used for signing but appears in `signer.WellKnownJWKs` and can verify legacy tokens.

## HMAC: Legacy Signing

HMAC-signed JWTs for backwards compatibility. HS256, HS384, HS512.

```go
package main

import (
   "crypto"
   "os"
   "time"

   "github.com/therootcompany/golib/auth/jwt"
)

func main() {
   secret := []byte(os.Getenv("JWT_SECRET"))
   key := jwt.NewSharedSecret(secret, "optional-key-id")

   signer, err := jwt.NewHMACSigner(crypto.SHA256, key)
   if err != nil {
      panic(err)
   }

   token, err := signer.SignToString(&jwt.TokenClaims{
      Iss: "legacy.example.com",
      Sub: "user-42",
      Exp: time.Now().Add(time.Hour).Unix(),
   })
   if err != nil {
      panic(err)
   }

   verifier, err := jwt.NewHMACVerifier(crypto.SHA256, key)
   if err != nil {
      panic(err)
   }
   jws, err := verifier.VerifyJWT(token)
   if err != nil {
      panic(err)
   }

   var claims jwt.TokenClaims
   jws.UnmarshalClaims(&claims)
   println(claims.Sub) // "user-42"
}
```

### Shared Secret from Environment

```sh
export JWT_SECRET=$(openssl rand -base64 32)
```

```go
secret := []byte(os.Getenv("JWT_SECRET"))
ss := jwt.NewSharedSecret(secret, "my-key")
signer, err := jwt.NewHMACSigner(crypto.SHA256, ss)
```

### Load Secret from File

```go
// Raw file contents as secret (KID left unset)
key, err := keyfile.LoadSharedSecretString("secret.txt")

// JWK format (same as asymmetric keys)
key, err := keyfile.LoadSharedSecretJWK("secret.jwk")
```

### Retired Secrets

For key rotation, pass retired secrets to verify tokens signed with older keys:

```go
active := jwt.NewSharedSecret(activeSecret, "active")
retired := jwt.NewSharedSecret(oldSecret, "retired")

verifier, err := jwt.NewHMACVerifier(crypto.SHA256, active, retired)
```

The verifier tries the active secret first, then retired secrets. The first successful verification wins.

### Key ID (KID)

For HMAC keys, KID is left unset — you set it explicitly.

```go
key := jwt.NewSharedSecret(secret, "")
// key.KID is empty

// To set KID from the RFC 7638 thumbprint:
key.KID, _ = key.Thumbprint()
```

It's best to leave the Key ID `kid` unset for HMAC secrets unless you have multiple secrets and you know whether using thumbprint or opaque ids is right for your use case.
