package main

import (
	"bufio"
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
