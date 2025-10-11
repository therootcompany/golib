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
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

var ErrHTTPGet = errors.New("did not get 200 OK when downloading from URL")

// For mocking for tests
var httpGet = http.Get

type Reader struct {
	*csv.Reader
	QuotedComments bool
	r              io.Reader
	resp           *http.Response
	close          bool
	err            error
}

func NewReaderFromURL(url string) *Reader {
	docid, gid := ParseIDs(url)

	return NewReaderFromIDs(docid, gid)
}

func NewReaderFromIDs(docid, gid string) *Reader {
	resp, err := getSheet(docid, gid)
	if err != nil {
		r := NewReader(nil)
		r.err = err
		return r
	}

	r := NewReader(resp.Body)
	r.resp = resp
	r.close = true
	return r
}

func getSheet(docid, gid string) (*http.Response, error) {
	downloadURL := fmt.Sprintf("https://docs.google.com/spreadsheets/d/%s/export?format=csv&usp=sharing&gid=%s", docid, gid)

	resp, err := httpGet(downloadURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, ErrHTTPGet
	}

	return resp, nil
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
		r:              r,
	}
}

func (r *Reader) Read() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}

	for {
		record, err := r.Reader.Read()
		if err != nil {
			if r.close {
				_ = r.resp.Body.Close()
			}
			return nil, err
		}

		if r.QuotedComments && len(record[0]) > 0 {
			runeValue, _ := utf8.DecodeRuneInString(record[0])
			if runeValue == r.Comment {
				fmt.Println("DEBUG: skipped quoted comment")
				continue
			}
		}
		return record, nil
	}
}

func (r *Reader) ReadAll() ([][]string, error) {
	var records [][]string

	for {
		record, err := r.Read()
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
