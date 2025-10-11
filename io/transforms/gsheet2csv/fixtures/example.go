package main

import (
	"fmt"
	"os"

	"github.com/therootcompany/golib/io/transform/gsheet2csv"
)

func main() {
	switch len(os.Args) {
	case 2:
		break
	case 1:
		fmt.Fprintf(os.Stderr, "Usage: %s <url>\n", os.Args[0])
		os.Exit(1)
	}
	urlOrPath := os.Args[1]

	gsr := gsheet2csv.NewReaderFrom(urlOrPath)
	records, err := gsr.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from %s: %v\n", gsr.URL, err)
		os.Exit(1)
	}

	csvw := gsheet2csv.NewWriter(os.Stdout)
	csvw.Comment = gsr.Comment
	if err := csvw.WriteAll(records); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing csv %v\n", err)
		os.Exit(1)
	}
}
