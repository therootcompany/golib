// envtocsv - Converts one or more .env files into a merged, sorted CSV
//
// Authored in 2026 by AJ ONeal <aj@therootcompany.com> w/ Grok (https://grok.com).
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/joho/godotenv"
)

type MainConfig struct {
	outputPath string
	useTab     bool
}

func main() {
	cfg := MainConfig{}

	flag.StringVar(&cfg.outputPath, "o", "-", "output path ('-' = stdout)")
	flag.BoolVar(&cfg.useTab, "tab", false, "use tab-delimited output instead of comma-separated")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		files = []string{".env"}
	}

	multiFile := len(files) > 1

	var allRows [][]string

	for _, path := range files {
		envMap, err := godotenv.Read(path)
		if err != nil {
			log.Printf("Warning: skipping %s: %v", path, err)
			continue
		}

		rows := make([][]string, 0, len(envMap))
		for k, v := range envMap {
			if multiFile {
				rows = append(rows, []string{k, v, path})
			} else {
				rows = append(rows, []string{k, v})
			}
		}

		// Sort this file's rows by key
		slices.SortFunc(rows, func(a, b []string) int {
			return strings.Compare(a[0], b[0])
		})

		allRows = append(allRows, rows...)
	}

	if len(allRows) == 0 {
		log.Println("No valid key-value pairs found in any input file")
		return
	}

	// Deduplicate: keep the last occurrence of each key (override behavior)
	seen := make(map[string]int) // key → index of latest occurrence
	for i, row := range allRows {
		seen[row[0]] = i
	}

	// Build final list (only the winning rows)
	finalRows := make([][]string, 0, len(seen))
	for _, idx := range seen {
		finalRows = append(finalRows, allRows[idx])
	}

	// Final sort by key for stable, readable output
	slices.SortFunc(finalRows, func(a, b []string) int {
		return strings.Compare(a[0], b[0])
	})

	// Output writer setup
	var w *csv.Writer
	if cfg.outputPath == "-" {
		w = csv.NewWriter(os.Stdout)
	} else {
		f, err := os.Create(cfg.outputPath)
		if err != nil {
			log.Fatalf("Failed to create output file %s: %v", cfg.outputPath, err)
		}
		defer f.Close()
		w = csv.NewWriter(f)
	}

	// Configure delimiter based on -tab flag
	if cfg.useTab {
		w.Comma = '\t'
		w.UseCRLF = false // keep LF even on Windows for consistency
	} else {
		w.Comma = ','
	}

	defer w.Flush()

	// Header — conditional on multi-file
	header := []string{"key", "value"}
	if multiFile {
		header = append(header, "source")
	}
	if err := w.Write(header); err != nil {
		log.Fatalf("Failed to write header: %v", err)
	}

	// Write rows
	for _, row := range finalRows {
		if err := w.Write(row); err != nil {
			log.Fatalf("Failed to write to %s: %v", cfg.outputPath, err)
		}
	}

	if cfg.outputPath != "-" {
		fmt.Fprintf(os.Stderr, "Wrote %d unique keys to %s (%s-delimited)\n",
			len(finalRows), cfg.outputPath, map[bool]string{true: "tab", false: "comma"}[cfg.useTab])
	} else {
		fmt.Fprintf(os.Stderr, "(%d unique keys written to stdout, %s-delimited)\n",
			len(finalRows), map[bool]string{true: "tab", false: "comma"}[cfg.useTab])
	}
}
