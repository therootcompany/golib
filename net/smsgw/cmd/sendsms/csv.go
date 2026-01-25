package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/therootcompany/golib/net/smsgw"
)

func GetFieldIndex(header []string, name string) int {
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i
		}
	}
	return -1
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

func (cfg *MainConfig) LaxParseCSV(csvr *csv.Reader) (messages []smsgw.Message, warns []CSVWarn, err error) {
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

		if len(rec) < FIELD_MIN {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "TooFewFields",
				Message: fmt.Sprintf("ignoring row %d: too few fields (want %d, have %d)", rowIndex, FIELD_MIN, len(rec)),
				Record:  rec,
			})
			continue
		}

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

		message := smsgw.Message{
			// Index:    rowIndex,
			Name:     strings.TrimSpace(rec[FIELD_NAME]),
			Number:   strings.TrimSpace(rec[FIELD_PHONE]),
			Template: strings.TrimSpace(rec[FIELD_MESSAGE]),
			Vars:     vars,
		}

		message.Number = smsgw.StripFormatting(message.Number)
		message.Number, err = smsgw.PrefixUS10Digit(message.Number)
		if err != nil {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "PhoneInvalid",
				Message: fmt.Sprintf("ignoring row %d (%s): %s", rowIndex, message.Name, err.Error()),
				Record:  rec,
			})
			continue
		}

		messages = append(messages, message)
	}

	return messages, warns, nil
}
