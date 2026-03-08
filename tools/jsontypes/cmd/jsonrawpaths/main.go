package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/therootcompany/golib/tools/jsontypes"
)

func main() {
	samples := flag.Int("samples", 0, "show sample values truncated to this length (0 = type names)")
	flag.Parse()

	var input *os.File
	if flag.NArg() > 0 && flag.Arg(0) != "-" {
		f, err := os.Open(flag.Arg(0))
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

	cfg := jsontypes.RawPathsConfig{SampleLen: *samples}
	for _, path := range jsontypes.RawPathsWithConfig(data, cfg) {
		fmt.Println(path)
	}
}
