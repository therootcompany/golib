// Authored in 2026 by AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package textvars

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var reUnmatchedVars = regexp.MustCompile(`(\{[^}]+\})`)

func GetPlaceholders(tmpl string) []string {
	return reUnmatchedVars.FindAllString(tmpl, -1)
}

func ReplaceVars(text string, vars map[string]string) (string, error) {
	keyIter := maps.Keys(vars)
	keys := slices.Sorted(keyIter)
	for _, key := range keys {
		val := vars[key]
		text = ReplaceVar(text, key, val)
	}

	if tmpls := GetPlaceholders(text); len(tmpls) != 0 {
		return "", fmt.Errorf("leftover template variable(s): %s", strings.Join(tmpls, " "))
	}

	return text, nil
}

func ReplaceVar(text, key, val string) string {
	if val != "" {
		// No special treatment:
		// "Hey {+Name}," => "Hey Doe,"
		// "Bob,{Name}" => "Bob,Doe"
		// "{Name-},Joe" => "Doe,Joe"
		// "Hi {-Name-}, Joe" => "Hi Doe, Joe"
		var reHasVar = regexp.MustCompile(fmt.Sprintf(`\{\+?%s-?\}`, regexp.QuoteMeta(key)))
		return reHasVar.ReplaceAllString(text, val)
	}

	var metaKey = regexp.QuoteMeta(key)

	// "Hey {+Name}," => "Hey ,"
	text = strings.ReplaceAll(text, `{+`+key+`}`, val)

	// "Bob,{Name};" => "Bob;"
	var reEatOneLeft = regexp.MustCompile(fmt.Sprintf(`.?\{%s\}`, metaKey))
	text = reEatOneLeft.ReplaceAllString(text, val)

	// ",{Name-};Joe" => ",Joe"
	var reEatOneRight = regexp.MustCompile(fmt.Sprintf(`\{%s-\}.?`, metaKey))
	text = reEatOneRight.ReplaceAllString(text, val)

	// "Hi {-Name-}, Joe" => "Hi Joe"
	var reEatOneBoth = regexp.MustCompile(fmt.Sprintf(`.?\{-%s-\}.?`, metaKey))
	text = reEatOneBoth.ReplaceAllString(text, val)

	return text
}
