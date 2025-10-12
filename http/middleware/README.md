# http/middleware

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/http/middleware.svg)](https://pkg.go.dev/github.com/therootcompany/golib/http/middleware)

A simple zero-cost middleware handler for Go's native `net/http` `ServeMux`. \
(only 50 lines long, using only `net/http` and `slices`)

Turns tedious this:

```go
mux.HandleFunc("GET /api/version", logRequests(timeRequests(getVersion)))
mux.HandleFunc("GET /api/data", logRequests(timeRequests(requireAuth(requireAdmin(getData)))))
```

Into organizable this:

```go
mw := middleware.New(logRequests, timeRequests)
mux.HandleFunc("GET /api/version", mw.Handle(getVersion))

authMW := m.Use(requireAuth, requireAdmin)
mux.HandleFunc("GET /api/data", authMW.Handle(getData))
```

Using stdlib this:

```go
type Middleware func(http.HandlerFunc) http.HandlerFunc
```

**Zero-cost** because each invocation of `mv.Handle(handler)` composes the function calls _exactly_ the same way as when done manually. \
(the setup is done during route initialization and has no additional impact on requests)

## Usage

- Create with `middleware.New(middlewares...)`
- Extend with `mw.Use(midlewares...)` (copies and appends)
- Apply with `specific.Handle(handler)`

```go
package main

import (
   "net/http"

   "github.com/therootcompany/golib/middleware"
)

func main() {
   mux := http.NewServeMux()

   mw := middleware.New(logRequests, basicAuth)
   mux.HandleFunc("GET /api/data", mw.Handle(getData))
   mux.HandleFunc("POST /api/data", mw.Handle(postData))

   adminMW := mw.Use(requireAdmin)
   mux.HandleFunc("DELETE /api/data", adminMW.Handle(deleteData))

   http.ListenAndServe(":8080", mux)
}
```

### Example Middleware

Middleware is any function that wraps and returns the built-in `http.HandlerFunc` handler type.

```go
type Middleware func(http.HandlerFunc) http.HandlerFunc
```

#### Example: Request logger

```go
func logRequests(next http.HandlerFunc) http.HandlerFunc {
   return func(w http.ResponseWriter, r *http.Request) {

      start := time.Now()
      next.ServeHTTP(w, r)
      log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
   }
}
```

#### Example: Basic Auth Verifier, using [`envauth`](https://github.com/therootcompany/golib/tree/main/auth/envauth)

```go
import "github.com/therootcompany/golib/auth/envauth"

var creds = envauth.BasicCredentials{
   Username: os.Getenv("BASIC_AUTH_USERNAME"),
   Password: os.Getenv("BASIC_AUTH_PASSWORD"),
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
   return func(w http.ResponseWriter, r *http.Request) {

      user, pass, _ := r.BasicAuth()
      if err := creds.Verify(user, pass); err != nil {
         http.Error(w, "Unauthorized", http.StatusUnauthorized)
         return
      }

      next.ServeHTTP(w, r)
   }
}
```

#### Example: Admin role checker

```go
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
   return func(w http.ResponseWriter, r *http.Request) {

      // Assume JWT in context with roles
      jws := r.Context().Value("jwt").(jwt.JWS)
      if !slices.Contains(jws.Claims.Roles, "admin") {
         http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
         return
      }

      next.ServeHTTP(w, r)
   }
}
```
