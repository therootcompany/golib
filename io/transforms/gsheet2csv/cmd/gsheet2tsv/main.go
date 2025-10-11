package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"

	"github.com/therootcompany/golib/io/transform/gsheet2csv"
)

func main() {
	// Parse command-line flags
	outputFile := flag.String("o", "", "Output TSV file (default: stdout)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <google-sheet-url>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Converts a Google Sheet to TSV format.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s -o output.tsv 'https://docs.google.com/spreadsheets/d/1KdNsc63pk0QRerWDPcIL9cMnGQlG-9Ue9Jlf0PAAA34/edit?gid=559037238#gid=559037238'\n", os.Args[0])
	}
	flag.Parse()

	// Check for URL argument
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "Error: exactly one Google Sheet URL is required\n")
		flag.Usage()
		os.Exit(1)
	}
	url := flag.Args()[0]

	// Create a reader for the Google Sheet
	reader := gsheet2csv.NewReaderFromURL(url)

	// Prepare output writer
	var out *os.File
	{
		if *outputFile != "" {
			var err error
			out, err = os.Create(*outputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = out.Close() }()
		} else {
			out = os.Stdout
		}
	}

	// Create TSV writer
	writer := csv.NewWriter(out)
	{
		writer.Comma = '\t' // Set delimiter to tab for TSV

		// Read all records and write as TSV
		records, err := reader.ReadAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CSV: %v\n", err)
			os.Exit(1)
		}

		for _, record := range records {
			if err := writer.Write(record); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing TSV: %v\n", err)
				os.Exit(1)
			}
		}

		// Flush the writer to ensure all data is written
		writer.Flush()
		if err := writer.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "Error flushing TSV writer: %v\n", err)
			os.Exit(1)
		}
	}
}
