package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/therootcompany/golib/tools/jsontypes"
)

const description = "Show raw JSON paths from a JSON document."

// Replaced by goreleaser / ldflags at build time.
var (
	name         = "jsonrawpaths"
	version      = "0.0.0-dev"
	commit       = "0000000"
	date         = "0001-01-01"
	licenseYear  = "2024"
	licenseOwner = "The Root Company"
	licenseType  = "CC0-1.0"
)

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
	_, _ = fmt.Fprintf(w, "%s\n", description)
}

type mainConfig struct {
	samples int
	format  string
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout)
			fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	cfg := mainConfig{}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.IntVar(&cfg.samples, "samples", 0, "show sample values truncated to this length (0 = type names)")
	fs.StringVar(&cfg.format, "format", "", "output format: pretty, tsv, csv, json (default: auto)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if fs.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "error: too many arguments\n")
		os.Exit(1)
	}

	var input *os.File
	if fs.NArg() > 0 && fs.Arg(0) != "-" {
		var err error
		input, err = os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer input.Close()
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

	cfgs := jsontypes.RawPathsConfig{SampleLen: cfg.samples}
	for _, path := range jsontypes.RawPathsWithConfig(data, cfgs) {
		fmt.Println(path)
	}
}
