package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var version = "v1.0.0"
var help = "salt [size=16]"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "version", "-version", "--version":
			fmt.Println(version)
			return
		case "help", "-help", "--help":
			fmt.Println("Usage:", help)
			os.Exit(0)
			return
		}
	}

	var err error
	var size int

	switch len(os.Args) {
	case 1:
		size = 16
	case 2:
		size, err = strconv.Atoi(os.Args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Usage: %s\n", help)
			return
		}
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s\n", help)
		return
	}

	salt := make([]byte, size)
	_, _ = rand.Read(salt)
	fmt.Printf("hex       : %s\n", hex.EncodeToString(salt))
	fmt.Printf("HEX       : %s\n", strings.ToUpper(hex.EncodeToString(salt)))
	fmt.Printf("url-base64: %s\n", base64.RawURLEncoding.EncodeToString(salt))
	fmt.Printf("rfc-base64: %s\n", base64.StdEncoding.EncodeToString(salt))
}
