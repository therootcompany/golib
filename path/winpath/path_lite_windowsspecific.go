// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winpath

const (
	Separator     = '\\' // OS-specific path separator
	ListSeparator = ';'  // OS-specific path list separator
)

func IsPathSeparator(c uint8) bool {
	return c == '\\' || c == '/'
}

func toUpper(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func IsAbs(path string) (b bool) {
	l := volumeNameLen(path)
	if l == 0 {
		return false
	}
	if IsPathSeparator(path[0]) && IsPathSeparator(path[1]) {
		return true
	}
	path = path[l:]
	if path == "" {
		return false
	}
	return IsPathSeparator(path[0])
}

func volumeNameLen(path string) int {
	switch {
	case len(path) >= 2 && path[1] == ':':
		return 2

	case len(path) == 0 || !IsPathSeparator(path[0]):
		return 0

	case pathHasPrefixFold(path, `\\.\UNC`):
		return uncLen(path, len(`\\.\UNC\`))

	case pathHasPrefixFold(path, `\\.`) ||
		pathHasPrefixFold(path, `\\?`) || pathHasPrefixFold(path, `\??`):
		if len(path) == 3 {
			return 3
		}
		_, rest, ok := cutPath(path[4:])
		if !ok {
			return len(path)
		}
		return len(path) - len(rest) - 1

	case len(path) >= 2 && IsPathSeparator(path[1]):
		return uncLen(path, 2)
	}
	return 0
}

func pathHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if IsPathSeparator(prefix[i]) {
			if !IsPathSeparator(s[i]) {
				return false
			}
		} else if toUpper(prefix[i]) != toUpper(s[i]) {
			return false
		}
	}
	if len(s) > len(prefix) && !IsPathSeparator(s[len(prefix)]) {
		return false
	}
	return true
}

func uncLen(path string, prefixLen int) int {
	count := 0
	for i := prefixLen; i < len(path); i++ {
		if IsPathSeparator(path[i]) {
			count++
			if count == 2 {
				return i
			}
		}
	}
	return len(path)
}

func cutPath(path string) (before, after string, found bool) {
	for i := range path {
		if IsPathSeparator(path[i]) {
			return path[:i], path[i+1:], true
		}
	}
	return path, "", false
}

func postClean(out *lazybuf) {
	if out.volLen != 0 || out.buf == nil {
		return
	}
	for _, c := range out.buf {
		if IsPathSeparator(c) {
			break
		}
		if c == ':' {
			out.prepend('.', Separator)
			return
		}
	}
	if len(out.buf) >= 3 && IsPathSeparator(out.buf[0]) && out.buf[1] == '?' && out.buf[2] == '?' {
		out.prepend(Separator, '.')
	}
}
