# [Auth Proxy](https://github.com/therootcompany/golib/tree/dev/cmd/auth-proxy)

A reverse proxy for putting authentication and route-based authorization in front of services.

I created this for integrations like Google Sheets (both loading and retrieving data), Ollama, and OpenClaw.

1. Setup some users and/or tokens and/or "guest"
   ```sh
   # create the ./credentials.tsv 
   csvauth init

   # create a Basic Auth credential 'my-admin-user' with Full Access
   csvauth store --roles '/' my-admin-user

   # create a Bearer Token credential with the id 'an-admin-token' with Full Access
   csvauth store --roles '/' --token an-admin-token

   # create a limited Guest user (no password) with access to specific routes
   csvauth store --roles 'GET:/public/ POST:/dropbox/' --ask-password guest
   ```
2. Stand up the proxy behind the TLS Proxy \
   (snirouter, [Caddy](https://webinstall.dev/caddy), Traefik, Nginx+certbot, etc)
   ```sh
   auth-proxy --port 8080 --target-proxy http://localhost:11343
   ```
3. Enjoy protected access!

## Table of Contents

- Installation
- Supported Authentication Methods \
  (all "basic" types - no signature verification)
- Credential Management
   - By Hand
   - By `csvauth`
   - "guest" to skip auth
- Permission Pattern Matching
   - `/` (full access)
   - `GET:example.com/api/endpoint` (granular access)
   - `GET:/endpoint/{$}` (exact path match)

## Installation

For right now, it's just `go install`

```sh
# csvauth (optional, but recommended)
go install github.com/therootcompany/golib/auth/csvauth/cmd/csvauth@v1

# auth-proxy (this thing)
go install github.com/therootcompany/golib/cmd/auth-proxy@v1
```

Later I'll add this to GitHub Releases and [webi](https://webinstall.dev).

If you don't have `go`:

```sh
curl https://webi.sh/go | sh
source ~/.config/envman/PATH.env
```

(installs safely to `~/.local/opt/go` and `~/go/`)

## Supported Methods

Authentication is checked for in this order:

| 1.  | Basic Auth (user)  | `Authorization: Basic <base64(user:pass)>`   |
| --- | ------------------ | -------------------------------------------- |
| 2.  | Basic Auth (token) | `Authorization: Basic <base64(empty:token)>` |
| 3.  | Bearer Tokens      | `Authorization: <Scheme> <token>`            |
| 4.  | API Key Header     | `X-API-Key: <token>`                         |
| 5.  | Access Token Param | `?access_token=<token>`                      |
| 6.  | Public (fallback)  | `Authorization: Basic <base64("guest":"")>`  |

The first match wins (even if it has lower privileges).

You can control which methods are allowed:

```text
--token-schemes 'Bearer,Token' # '*' for any
--token-headers 'X-API-Key,X-Auth-Token,X-Access-Token'
--token-params 'access_token,token'
```

Tips:

- Use an empty string `''` or `'none'` to disable that method.
- Set `--token-headers 'Authorization'` for scheme-less `Authorization: <token>`

## Credential Management

Credentials are managed in `credentials.tsv`:

```text
--credentials ./credentials.tsv
--comma "\t"
--aes-128-key ~/.config/csvauth/aes-128.key
```

```sh
# by default this is read from ~/.config/csvauth/aes-128.key
export CSVAUTH_AES_128_KEY=0123456789abcdeffedcba9876543210
```

The AES key is used if reversible algorithms are used, or if tokens are used (as part of deriving an id).
128-bits was chosen for the same reason your browser uses it: [256-bit isn't more secure](https://www.schneier.com/blog/archives/2009/07/another_new_aes.html).

### Plain Text by Hand

Create a comma-separated list of credentials with the `plain` algorithm:

```csv
purpose,name,algo,salt,derived,roles,extra
login,guest,plain,,,GET:/{$},
login,tom,plain,,my-plain-text-password,/,
login,harry,plain,,another-plain-password,GET:/ POST:/logs,
```

You need to set the delimiter back to comma to manage this way by hand (it's tab by default).

```sh
--comma ","
```

Password / token comparisons will still be done via timing-safe hashes, even when the algorithm is `plain`.

### Secure with csvauth

This create a tab-separated list of credentials (default: `pdfkdf2` for 'login', aes-128-gcm for 'token')

```sh
csvauth init
```

You _MUST_ supply space-delimited `--roles` in the form of `[METHOD:][HOST]/[PATH]`.

```tsv
csvauth store --roles '/' 'my-admin-user'
csvauth store --roles '/' --token 'an-admin-token'
```

The password or token will be **randomly generated** and **printed to the screen** by default.

```sh
--roles '/' # space-delimited patterns
--token # generates a token (no username required)
--ask-password # you'll be asked to type in or paste the password / token
```

Note: `csv store --token <same-name-as-before>` will **NOT replace** the existing token (because their ids are pairwise with their value).
For now you'll have to delete old tokens by hand.

### Public Access

Any routes that you want to make public (no auth protection) should be granted to a user named `guest` and have **NO PASSWORD**.

To do this use `--ask-password` and _hit enter_ instead of giving one.

```sh
csvauth store --roles 'GET:/{$} GET:/public/ POST:/dropbox/' --ask-password 'guest'
```

## Permission Matching

The patterns are based on [Go's ServeMux pattern matching](https://pkg.go.dev/net/http#hdr-Patterns-ServeMux), but using `:` instead of space because `roles` are space-delimited in `csvauth`.

```text
[METHOD:][HOST]/[PATH]
```

Meaning

- Method is optional - _all_ of GET, POST, etc are allowed by default
- Hostname is optional - _any_ domain is allowed by default
- / is _required_ - _**no paths**_ are allowed by default

The syntax looks like this:

```
/
GET:example.com/api
GET:/api
example.com/api
```

Very simple patterns are also supported

- `{x}` for an optional wildcard path component
- `{$}` for an exact match
- `/path` and `/path/` are always considered equal

For example:

| Kind    | Pattern             | Matches                                   |
| ------- | ------------------- | ----------------------------------------- |
| Prefix  | `/`                 | everything                                |
| Prefix  | `GET:/`             | all GETs                                  |
| Prefix  | `GET:example.com/`  | all GETs to example.com                   |
| Prefix  | `/api /assets`      | `/api`, `/api/*`, `/assets`, `/assets/*`  |
| Pattern | `/api/{x}`          | same as `/api` or `/api/`                 |
| Pattern | `/api/{x}/`         | same as `/api/{x}`                        |
| Pattern | `/{x}/download`     | `/foo/download`, `/bar/download/name.mp3` |
| Pattern | `/{x}/download/{$}` | `/foo/download`, `/bar/download`          |
| Pattern | `/path/{$}`         | `/path`, `/path/`, no subpaths            |
| Pattern | `/{$}`              | `/`,                                      |

You can also use vanity wildcards (instead of just `{x}`):

- `/api/users/{userID}/favorites`
- `/api/files/{fullpath...}`
