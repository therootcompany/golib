package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/therootcompany/golib/io/transforms/gsheet2csv"
)

func isValidKey(key string) bool {
	for _, c := range key {
		isUpperWord := (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
		if !isUpperWord {
			return false
		}
	}
	return true
}

func main() {
	noShebang := flag.Bool("no-shebang", false, "don't begin the file with #!/bin/sh")
	noHeader := flag.Bool("no-header", false, "treat all non-comment rows as ENVs - don't expect a header")
	noExport := flag.Bool("no-export", false, "disable export prefix")
	outputFile := flag.String("o", "-", "path to output env file (default: stdout)")
	flag.Parse()

	// Require Google Sheet URL as argument
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "Error: exactly one Google Sheet URL or path is required\n")
		flag.Usage()
		os.Exit(1)
	}
	gsheetURLOrPath := flag.Args()[0]

	// Prepare output writer
	var out *os.File
	if len(*outputFile) > 0 && *outputFile != "-" {
		var err error
		out, err = os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
			return
		}
		defer func() { _ = out.Close() }()
	} else {
		out = os.Stdout
	}

	gsr := gsheet2csv.NewReaderFrom(gsheetURLOrPath)
	// preserves comment-looking data (and actual comments)
	gsr.Comment = 0
	gsr.FieldsPerRecord = -1

	if !*noShebang {
		if _, err := out.Write([]byte("#!/bin/sh\n\n")); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
			return
		}
	}

	if err := convert(gsr, out, *noHeader, *noExport); err != nil {
		fmt.Fprintf(os.Stderr, "Error converting CSV to ENV: %v\n", err)
		os.Exit(1)
	}

	if out != os.Stdout {
		fmt.Fprintf(os.Stderr, "wrote %s\n", *outputFile)
	}
}

func convert(gsr *gsheet2csv.Reader, out io.Writer, noHeader bool, noExport bool) error {
	consumedHeader := noHeader
	for {
		row, err := gsr.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		var key string
		if len(row) >= 1 {
			key = strings.TrimSpace(row[0])
			if len(key) == 0 {
				if _, err := fmt.Fprintln(out); err != nil {
					return err
				}
				continue
			}

			// Preserve but ignore proper comments
			if keyComment, exists := strings.CutPrefix(key, "#"); exists {
				keyComment = strings.TrimSpace(keyComment)
				if len(keyComment) == 0 {
					if _, err := fmt.Fprintln(out, "#"); err != nil {
						return err
					}
					continue
				}

				saniComment := sanitizeComment(keyComment)
				if _, err := fmt.Fprintf(out, "%s", saniComment); err != nil {
					return err
				}
				continue
			}
		}

		var value string
		if len(row) >= 2 {
			value = strings.TrimSpace(row[1])
		}

		var saniComment string
		if len(row) >= 3 {
			saniComment = sanitizeComment(row[2])
		}

		if !consumedHeader {
			consumedHeader = true
			continue
		}

		// Error on invalid keys
		if !isValidKey(key) {
			return fmt.Errorf("invalid key in record %s", strings.Join(row, ","))
		}

		// Escape single quotes in value for shell compatibility
		value = strings.ReplaceAll(value, "'", "'\"'\"'")

		// Output the ENV line
		prefix := ""
		if !noExport {
			prefix = "export "
		}
		if _, err := fmt.Fprintf(out, "%s%s%s='%s'\n", saniComment, prefix, key, value); err != nil {
			return err
		}
	}

	return nil
}

func sanitizeComment(comment string) string {
	var formatted []string

	comment = strings.TrimSpace(comment)
	lines := strings.FieldsFuncSeq(comment, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	for line := range lines {
		trimmed := strings.TrimSpace(line)
		formatted = append(formatted, "# "+trimmed)
	}

	comment = strings.Join(formatted, "\n")
	if len(comment) > 0 {
		comment += "\n"
	}
	return comment
}
