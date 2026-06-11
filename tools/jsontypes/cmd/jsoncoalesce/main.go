package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/therootcompany/golib/tools/jsontypes"
)

const description = "Coalesce raw JSON paths into a flat list."

// Replaced by goreleaser / ldflags at build time.
var (
	name         = "jsoncoalesce"
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

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

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

	var lines []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}

	for _, line := range jsontypes.Coalesce(lines) {
		fmt.Println(line)
	}
}
