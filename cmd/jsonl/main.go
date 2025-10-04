package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	decoder := json.NewDecoder(os.Stdin)

	var err error
	for decoder.More() {
		var data any
		if err = decoder.Decode(&data); err != nil {
			break
		}
		fmt.Printf("Decoded: %#v\n\n", data)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding JSON: %v\n\n", err)
	}

	fmt.Printf("Done\n")
}
