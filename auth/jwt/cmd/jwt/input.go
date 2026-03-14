package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// readInput resolves a positional argument to its content string.
//
//  1. If arg is "" or "-", read from stdin.
//  2. If arg is a file path that exists on disk, read the file.
//  3. Otherwise treat arg as a literal string.
func readInput(arg string) (string, error) {
	if arg == "" || arg == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Try as file path first.
	if _, err := os.Stat(arg); err == nil {
		data, err := os.ReadFile(arg)
		if err != nil {
			return "", fmt.Errorf("read file %q: %w", arg, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Treat as literal string.
	return arg, nil
}
