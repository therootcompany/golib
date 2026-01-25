package smstmpl

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/therootcompany/golib/net/smsgw"
	"github.com/therootcompany/golib/net/smsgw/smscsv"
)

var reUnmatchedVars = regexp.MustCompile(`(\{[^}]+\})`)

func RenderAll(messages []smscsv.Message) ([]smscsv.Message, error) {
	var err error
	var warns []smscsv.CSVWarn

	for i, message := range messages {
		rowIndex := i + 1

		message.Text = ReplaceVar(message.Template, "Name", message.Name)
		keyIter := maps.Keys(message.Vars)
		keys := slices.Sorted(keyIter)
		for _, key := range keys {
			val := message.Vars[key]
			message.Text = ReplaceVar(message.Text, key, val)
		}

		message.Number = smsgw.StripFormatting(message.Number)
		message.Number, err = smsgw.PrefixUS10Digit(message.Number)
		if err != nil {
			warns = append(warns, smscsv.CSVWarn{
				Index:   rowIndex,
				Code:    "PhoneInvalid",
				Message: fmt.Sprintf("ignoring row %d (%s): %s", rowIndex, message.Name, err.Error()),
				// Record:  rec,
			})
			continue
		}

		if tmpls := reUnmatchedVars.FindAllString(message.Text, -1); len(tmpls) != 0 {
			return nil, &smscsv.CSVWarn{
				Index: rowIndex,
				Code:  "UnmatchedVars",
				Message: fmt.Sprintf(
					"failing due to row %d (%s): leftover template variable(s): %s",
					rowIndex, message.Name, strings.Join(tmpls, " "),
				),
				// Record: rec,
			}
		}

		messages[i] = message
	}

	// TODO XXX AJ makes sure the copy retains its Text
	return messages, nil
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
	var reEatNone = regexp.MustCompile(fmt.Sprintf(`\{\+%s\}`, metaKey))
	text = reEatNone.ReplaceAllString(text, val)

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
