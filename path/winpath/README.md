# path/winpath

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/path/winpath.svg)](https://pkg.go.dev/github.com/therootcompany/golib/path/winpath)

Windows-style path manipulation that works on any platform.

## Installation

```bash
go get github.com/therootcompany/golib/path/winpath
```

## Usage

```go
import winpath "github.com/therootcompany/golib/path/winpath"

// Clean a Windows path (from any platform)
clean := winpath.Clean(`C:\foo\..\bar`)  // C:\bar

// Join path elements
joined := winpath.Join(`C:\`, "foo", "bar.txt")  // C:\foo\bar.txt

// Split path into directory and file
dir, file := winpath.Split(`C:\foo\bar.txt`)  // C:\foo\, bar.txt

// Get file extension
ext := winpath.Ext(`C:\foo\bar.txt`)  // .txt

// Get base name
base := winpath.Base(`C:\foo\bar.txt`)  // bar.txt

// Get directory
d := winpath.Dir(`C:\foo\bar.txt`)  // C:\foo

// Check if path is absolute
winpath.IsAbs(`C:\foo`)      // true
winpath.IsAbs(`foo\bar`)     // false
winpath.IsAbs(`\foo`)        // false (rooted but no drive)
winpath.IsAbs(`\\server\share`)  // true (UNC)

// Get volume name
vol := winpath.VolumeName(`C:\foo\bar`)  // C:
len := winpath.VolumeNameLen(`C:\foo`)    // 2

// Convert separators
fwd := winpath.ToSlash(`C:\foo\bar`)   // C:/foo/bar
bck := winpath.FromSlash(`C:/foo/bar`) // C:\foo\bar

// Constants
winpath.Separator      // '\'
winpath.ListSeparator  // ';'
winpath.IsPathSeparator('\\')  // true
winpath.IsPathSeparator('/')   // true
```

## Comparison with stdlib

| Feature | `path/filepath` | `path/winpath` |
|---------|-----------------|----------------|
| Platform aware | Yes (uses OS) | No (always Windows) |
| Use alongside `filepath` | N/A | ✅ Works together |

Use `path/filepath` for native OS paths on any platform.
Use `path/winpath` when you need to handle Windows paths on non-Windows platforms (e.g., parsing config files, cross-platform tools).

## Attribution

This package is derived from the Go standard library's `internal/filepathlite` and `path/filepath` packages, adapted from [NextronSystems/universalpath](https://github.com/NextronSystems/universalpath).

### License

The Go Authors. See the [Go license](https://golang.org/LICENSE).

## Syncing from Go stdlib

To update from newer Go versions:

```bash
cd path/winpath
GO_VERSION=go1.22.0 ./sync.sh
```

Run `./sync.sh diff` to regenerate patches after manual edits.