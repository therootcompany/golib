package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/therootcompany/golib/tools/jsontypes"
)

func main() {
	maxStr := flag.Int("maxstr", 40, "max string length before truncation (0 = no limit)")
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

	cfg := jsontypes.SampleConfig{MaxStringLen: *maxStr}
	for _, line := range jsontypes.SampleWithConfig(data, cfg) {
		fmt.Println(line)
	}
}
