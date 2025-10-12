# envauth

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/auth/envauth.svg)](https://pkg.go.dev/github.com/therootcompany/golib/auth/envauth)

Auth utils for single-user environments. \
(standard library only, constant-time)

- Password
- PBKDF2 Digest (sha-256)

```go
creds := envauth.BasicCredentials{
   Username: os.Getenv("BASIC_AUTH_USERNAME"),
   Password: os.Getenv("BASIC_AUTH_PASSWORD"),
}

err := creds.Verify("username", "password")
```

## Basic Credentials: Username + Password

Plain-text username + password, typically something like `api:somereallylongapikey`.

`.env`:

```sh
export BASIC_AUTH_USERNAME="api"
export BASIC_AUTH_PASSWORD="secret"
```

```go
package main

import (
   "os"

   "github.com/therootcompany/golib/auth/envauth"
)

func main() {
   username := os.Getenv("BASIC_AUTH_USERNAME")
   password := os.Getenv("BASIC_AUTH_PASSWORD")

   creds := envauth.BasicCredentials{
      Username: username,
      Password: password,
   }

   if err := creds.Verify("api", "secret"); err != nil {
      switch err {
      case envauth.ErrUnauthorized:
         println("Authentication failed")
      default:
         panic(err)
      }
      os.Exit(1)
   }

   println("Authentication successful")
}
```

## PBKDF2 Derived Key / Digest

Salted and hashed password.

```sh
go run ./cmd/salt/ 8
# url-base64: i63wDd7K-60
```

```sh
go run ./cmd/pbkdf2-sha256/ 'secret' 'i63wDd7K-60'
# derived-key: 553ce8846c2304e93021dab03bacb5ca
```

`.env`:

```sh
export BASIC_AUTH_USERNAME="api"
export BASIC_AUTH_PBKDF256_DERIVED_KEY="553ce8846c2304e93021dab03bacb5ca"
export BASIC_AUTH_PBKDF256_SALT="i63wDd7K-60"
export BASIC_AUTH_PBKDF256_ITERATIONS=1000
```

```go
package main

import (
   "encoding/base64"
   "encoding/hex"
   "os"

   "github.com/therootcompany/golib/auth/envauth"
)

func main() {
   username := os.Getenv("BASIC_AUTH_USERNAME")
   derivedKeyHex := os.Getenv("BASIC_AUTH_PBKDF256_DERIVED_KEY")
   saltBase64 := os.Getenv("BASIC_AUTH_PBKDF256_SALT")
   itersStr := os.Getenv("BASIC_AUTH_PBKDF256_ITERATIONS")

   derivedKey, _ := hex.DecodeString(derivedKeyB64)
   salt, _ := base64.URLEncoding.DecodeString(saltHex)
   iterations, _ := strconv.Atoi(itersStr)

   creds := envauth.PBKDF2Credentials{
      Username: username,
      DerivedKey: derivedKey,
      Salt: salt,
      Iterations: iterations,
   }

   if err := creds.Verify("api", "secret"); err != nil {
      switch err {
      case envauth.ErrUnauthorized:
         println("Authentication failed")
      default:
         panic(err)
      }
      os.Exit(1)
   }

   println("Authentication successful")
}
```
