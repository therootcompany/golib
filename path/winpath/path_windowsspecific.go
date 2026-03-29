// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winpath

import (
	"os"
	"strings"
)

func Join(elem ...string) string {
	var b strings.Builder
	var lastChar byte
	for _, e := range elem {
		switch {
		case b.Len() == 0:
		case os.IsPathSeparator(lastChar):
			for len(e) > 0 && os.IsPathSeparator(e[0]) {
				e = e[1:]
			}
			if b.Len() == 1 && strings.HasPrefix(e, "??") && (len(e) == len("??") || os.IsPathSeparator(e[2])) {
				b.WriteString(`.\`)
			}
		case lastChar == ':':
		default:
			b.WriteByte('\\')
			lastChar = '\\'
		}
		if len(e) > 0 {
			b.WriteString(e)
			lastChar = e[len(e)-1]
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return Clean(b.String())
}
