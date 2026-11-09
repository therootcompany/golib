// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netrc

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var testNetrc = `
machine incomplete
password none

machine api.github.com
  login user
  password pwd

machine incomlete.host
  login justlogin

machine test.host
login user2
password pwd2

machine oneline login user3 password pwd3

machine ignore.host macdef ignore
  login nobody
  password nothing

machine hasmacro.too macdef ignore-next-lines login user4 password pwd4
  login nobody
  password nothing

default
login anonymous
password gopher@golang.org

machine after.default
login oops
password too-late-in-file
`

func TestParseNetrc(t *testing.T) {
	lines := Parse(testNetrc)
	want := []Entry{
		{Machine: "api.github.com", Login: "user", Password: "pwd"},
		{Machine: "test.host", Login: "user2", Password: "pwd2"},
		{Machine: "oneline", Login: "user3", Password: "pwd3"},
		{Machine: "hasmacro.too", Login: "user4", Password: "pwd4"},
	}

	if !reflect.DeepEqual(lines, want) {
		t.Errorf("Parse:\nhave %v\nwant %v", lines, want)
	}
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".netrc")

	// Missing file returns empty, not an error.
	entries, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty, got %v", entries)
	}

	// Write a valid netrc and read it back.
	os.WriteFile(path, []byte(testNetrc), 0600)
	entries, err = Read(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Machine: "api.github.com", Login: "user", Password: "pwd"},
		{Machine: "test.host", Login: "user2", Password: "pwd2"},
		{Machine: "oneline", Login: "user3", Password: "pwd3"},
		{Machine: "hasmacro.too", Login: "user4", Password: "pwd4"},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("Read:\nhave %v\nwant %v", entries, want)
	}
}
