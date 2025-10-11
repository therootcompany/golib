// Authored in 2025 by AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package gsheet2csv

import (
	"encoding/csv"
	"errors"
	"io"
	"strings"
)

type Reader struct {
	*csv.Reader
	QuotedComments bool
	TrimEmpty      bool
	r              io.Reader
}

func NewReader(r io.Reader) *Reader {
	csvr := csv.NewReader(r)
	csvr.Comma = ','
	csvr.Comment = '#'
	csvr.FieldsPerRecord = -1
	csvr.LazyQuotes = false
	csvr.TrimLeadingSpace = false
	csvr.ReuseRecord = false
	return &Reader{
		Reader:         csvr,
		QuotedComments: true,
		TrimEmpty:      true,
		r:              r,
	}
}

func (r *Reader) Read() ([]string, error) {
	for {
		record, err := r.Reader.Read()
		if err != nil {
			return nil, err
		}

		if len(record) > 0 {
			if r.QuotedComments && strings.HasPrefix(record[0], `"#`) {
				continue
			}
			return record, nil
		} else if !r.TrimEmpty {
			return record, nil
		}
	}
}

func (r *Reader) ReadAll() ([][]string, error) {
	var records [][]string

	for {
		record, err := r.Reader.Read()
		if nil != err {
			if errors.Is(err, io.EOF) {
				return records, nil
			}
			return records, err
		}
		records = append(records, record)
	}
}

func ParseIDs(urlStr string) (docid string, gid string) {
	// Find key: look for /spreadsheets/d/{key}
	const prefix = "/spreadsheets/d/"
	startIdx := strings.Index(urlStr, prefix)
	if startIdx == -1 {
		return "", gid
	}
	startIdx += len(prefix)

	// Find end of key (next / or end of string)
	endIdx := strings.Index(urlStr[startIdx:], "/")
	if endIdx == -1 {
		endIdx = len(urlStr)
	} else {
		endIdx += startIdx
	}

	docid = urlStr[startIdx:endIdx]
	if docid == "" {
		return "", ""
	}

	// Find gid: look for gid= and take until #, &, ?, /, or end
	gidIdx := strings.Index(urlStr, "gid=")
	if gidIdx != -1 {
		gidStart := gidIdx + len("gid=")
		endChars := "#&?/"
		gidEnd := strings.IndexAny(urlStr[gidStart:], endChars)
		if gidEnd == -1 {
			gid = urlStr[gidStart:]
		} else {
			gid = urlStr[gidStart : gidStart+gidEnd]
		}
	}

	if len(gid) == 0 {
		gid = "0"
	}
	return docid, gid
}
