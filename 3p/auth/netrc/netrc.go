// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netrc

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Entry holds a single machine entry from a .netrc file.
type Entry struct {
	Machine  string
	Login    string
	Password string
}

// Parse parses .netrc-format data and returns all complete entries
// (those with machine, login, and password).
func Parse(data string) []Entry {
	// See https://www.gnu.org/software/inetutils/manual/html_node/The-_002enetrc-file.html
	// for documentation on the .netrc format.
	var nrc []Entry
	var l Entry
	inMacro := false
	for line := range strings.SplitSeq(data, "\n") {
		if inMacro {
			if line == "" {
				inMacro = false
			}
			continue
		}

		f := strings.Fields(line)
		i := 0
		for ; i < len(f)-1; i += 2 {
			// Reset at each "machine" token.
			// "The auto-login process searches the .netrc file for a machine token
			// that matches […]. Once a match is made, the subsequent .netrc tokens
			// are processed, stopping when the end of file is reached or another
			// machine or a default token is encountered."
			switch f[i] {
			case "machine":
				l = Entry{Machine: f[i+1]}
			case "default":
				break
			case "login":
				l.Login = f[i+1]
			case "password":
				l.Password = f[i+1]
			case "macdef":
				// "A macro is defined with the specified name; its contents begin with
				// the next .netrc line and continue until a null line (consecutive
				// new-line characters) is encountered."
				inMacro = true
			}
			if l.Machine != "" && l.Login != "" && l.Password != "" {
				nrc = append(nrc, l)
				l = Entry{}
			}
		}

		if i < len(f) && f[i] == "default" {
			// "There can be only one default token, and it must be after all machine tokens."
			break
		}
	}

	return nrc
}

// Path returns the path to the .netrc file for the current user.
// It respects the NETRC environment variable, falls back to .netrc in
// the user's home directory, and on Windows prefers _netrc if present.
func Path() (string, error) {
	if env := os.Getenv("NETRC"); env != "" {
		return env, nil
	}
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Prioritize _netrc on Windows for compatibility.
	if runtime.GOOS == "windows" {
		legacyPath := filepath.Join(dir, "_netrc")
		_, err := os.Stat(legacyPath)
		if err == nil {
			return legacyPath, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}

	}
	// Use the .netrc file (fall back to it if we're on Windows).
	return filepath.Join(dir, ".netrc"), nil
}

// Read reads and parses the .netrc file at the given path.
// Missing files are treated as empty (no error).
func Read(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return nil, err
	}

	return Parse(string(data)), nil
}
