package smscsv

import (
	"fmt"
	"io"
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
	header   []string
	indices  map[string]int
	fields   []string
	name     string
	Number   string
	template string
	Vars     map[string]string
	text     string
}

func (m Message) Name() string {
	return m.name
}

func (m Message) Template() string {
	return m.template
}

func (m Message) Text() string {
	return m.text
}

func (m *Message) SetText(text string) {
	m.text = text
}

func (m Message) Size() int {
	return len(m.fields)
}

func (m Message) Get(key string) string {
	index, ok := m.indices[key]
	if !ok {
		return ""
	}

	if len(m.fields) >= 1+index {
		return m.fields[index]
	}

	return ""
}

// TODO XXX AJ pass in column name mapping
func ReadOrIgnoreAll(csvr Reader) (messages []Message, warns []CSVWarn, err error) {
	header, err := csvr.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("header could not be parsed: %w", err)
	}

	FIELD_NAME := GetFieldIndex(header, "Name")
	FIELD_PHONE := GetFieldIndex(header, "Phone")
	FIELD_MESSAGE := GetFieldIndex(header, "Message")
	if FIELD_NAME == -1 || FIELD_PHONE == -1 || FIELD_MESSAGE == -1 {
		return nil, nil, fmt.Errorf("header is missing one or more of 'Name', 'Phone', and/or 'Message'")
	}
	FIELD_MIN := 1 + slices.Max([]int{FIELD_NAME, FIELD_PHONE, FIELD_MESSAGE})

	rowIndex := 1 // 1-index, start at header
	for {
		rowIndex++
		rec, err := csvr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse row %d (and all following rows): %w", rowIndex, err)
		}

		// TODO XXX AJ create an abstraction around the header []string and the record []string
		// the idea is to return the same thing for valid and invalid rows
		vars := make(map[string]string)
		n := min(len(header), len(rec))
		for i := range n {
			switch i {
			case FIELD_NAME, FIELD_PHONE, FIELD_MESSAGE:
				continue
			default:
				key := header[i]
				val := rec[i]
				vars[key] = val
			}
		}

		if len(rec) < FIELD_MIN {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "TooFewFields",
				Message: fmt.Sprintf("ignoring row %d: too few fields (want %d, have %d)", rowIndex, FIELD_MIN, len(rec)),
				Record:  rec,
			})
			continue
		}

		message := Message{
			// Index:    rowIndex,
			name:     strings.TrimSpace(rec[FIELD_NAME]),
			Number:   strings.TrimSpace(rec[FIELD_PHONE]),
			template: strings.TrimSpace(rec[FIELD_MESSAGE]),
			Vars:     vars,
		}

		message.Number = smsgw.StripFormatting(message.Number)
		message.Number, err = smsgw.PrefixUS10Digit(message.Number)
		if err != nil {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "PhoneInvalid",
				Message: fmt.Sprintf("ignoring row %d (%s): %s", rowIndex, message.Name(), err.Error()),
				// Record:  rec,
			})
			continue
		}

		messages = append(messages, message)
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
