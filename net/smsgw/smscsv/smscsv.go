package smscsv

import (
	"fmt"
	"io"
	"log"
	"slices"
	"strings"

	"github.com/therootcompany/golib/net/smsgw"
)

type Reader interface {
	Read() ([]string, error)
	// ReadAll() ([][]string, error)
}

type CSVWarn struct {
	Index   int
	Code    string
	Message string
	Record  []string
}

func (w CSVWarn) Error() string {
	return w.Message
}

type Message struct {
	Record   `csv:"*"`
	Number   string `csv:"Phone"`
	Template string `csv:"Message"`
	Text     string `csv:"-"`
}

type Record struct {
	header []string
	fields []string
}

func (r Record) Keys() []string {
	return r.header
}

func (r Record) Get(key string) string {
	// typically there are only a few fields, so indexing is faster than mapping
	i := slices.Index(r.header, key)
	if i < 0 {
		return ""
	}

	return r.fields[i]
}

func (r Record) Map() map[string]string {
	m := make(map[string]string, len(r.header))
	for i, k := range r.header {
		m[k] = r.fields[i]
	}
	return m
}

// TODO XXX AJ pass in column name mapping
func ReadOrIgnoreAll(csvr Reader, labelKey string) (messages []Message, warns []CSVWarn, err error) {
	dec, err := csvutil.NewDecoder(csvr)
	if err != nil {
		return nil, nil, err
		// fmt.Fprintf(os.Stderr, "\n%sError%s: %v\n", textErr, textReset, err)
		// os.Exit(1)
	}

	header := dec.Header()
	if GetFieldIndex(header, "Phone") == -1 || GetFieldIndex(header, "Message") == -1 {
		return nil, nil, fmt.Errorf("header is missing one or more of 'Name', 'Phone', and/or 'Message'")
	}

	var unusedHeader []string
	rowIndex := 1 // 1-index, start at header
	for {
		rowIndex++

		m := Record(header)
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		// TODO we can't use this optimization when the fields have different lengths
		if unusedHeader == nil {
			ids := dec.Unused()
			unusedHeader = make([]string, len(ids))
		}
		m.Fields = Record{
			header: unusedHeader,
			fields: make([]string, len(unusedHeader)),
		}
		for _, i := range dec.Unused() {
			m.Fields.fields[i] = dec.Record()[i]
		}

		m.Number = smsgw.StripFormatting(m.Number)
		m.Number, err = smsgw.PrefixUS10Digit(m.Number)
		if err != nil {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "PhoneInvalid",
				Message: fmt.Sprintf("ignoring row %d (%s): %s", rowIndex, m.Fields.Get(labelKey), err.Error()),
				// Record:  rec,
			})
			continue
		}
		messages = append(messages, m)
	}

	return messages, warns, nil
}

func GetFieldIndex(header []string, name string) int {
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i
		}
	}
	return -1
}
