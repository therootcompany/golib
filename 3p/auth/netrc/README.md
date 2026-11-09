# .netrc parser

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/3p/auth/netrc.svg)](https://pkg.go.dev/github.com/therootcompany/golib/3p/auth/netrc)

A copy of the Go standard library's `.netrc` parser, modified
to export public members.

## Install

```sh
go get github.com/therootcompany/golib/3p/auth/netrc
```

## Usage

Parse a `.netrc` string:

```go
data := `
machine api.github.com
  login user
  password pwd

machine test.host
  login user2
  password pwd2
`
entries := netrc.Parse(data)
for _, e := range entries {
    fmt.Printf("%s: %s / %s\n", e.Machine, e.Login, e.Password)
}
```

Find and read the user's `.netrc` file:

```go
path, err := netrc.Path()
if err != nil {
    log.Fatal(err)
}
entries, err := netrc.Read(path)
if err != nil {
    log.Fatal(err)
}
for _, e := range entries {
    fmt.Printf("%s: %s / %s\n", e.Machine, e.Login, e.Password)
}
```

## Limitations

The Go stdlib implementation differs from the GNU `.netrc` spec in the following ways:

- no quoting: double-quoted values (e.g. `password "my secret"`), are mangled
- no `default`: only `machine` values match - `default` is ignored

## API

| Function / Type | Description |
|---|---|
| `Entry` | Struct with `Machine`, `Login`, `Password` fields. |
| `Parse(data string) []Entry` | Parse a `.netrc` string, returning all complete entries. |
| `Path() (string, error)` | Return the path to the `.netrc` file (respects `NETRC` env var). |
| `Read(path string) ([]Entry, error)` | Read and parse the `.netrc` file at the given path. |

## Testing

```sh
go test ./...
```

## License

This is a fork of <https://github.com/golang/go/blob/master/src/cmd/go/internal/auth/netrc.go> to make its members public.
