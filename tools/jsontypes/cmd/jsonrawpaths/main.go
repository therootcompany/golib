package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/therootcompany/golib/tools/jsontypes"
)

func main() {
	var input *os.File
	if len(os.Args) > 1 && os.Args[1] != "-" {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		input = f
	} else {
		input = os.Stdin
	}

	var data any
	dec := json.NewDecoder(input)
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	for _, path := range jsontypes.RawPaths(data) {
		fmt.Println(path)
	}
}
