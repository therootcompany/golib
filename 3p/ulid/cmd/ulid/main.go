package main

import (
	cryptorand "crypto/rand"
	"flag"
	"fmt"
	mathrand "math/rand"
	"os"
	"strings"
	"time"

	"github.com/therootcompany/golib/3p/ulid/v3"
)

const (
	defaultms = "Mon Jan 02 15:04:05.999 MST 2006"
	rfc3339ms = "2006-01-02T15:04:05.000Z07:00"
)

func main() {
	fs := flag.NewFlagSet("", flag.ExitOnError)
	var (
		format = fs.String("format", "default", "when parsing, show times in this format: default, rfc3339, unix, ms, <format>")
		local  = fs.Bool("local", false, "when parsing, show local time instead of UTC")
		quick  = fs.Bool("quick", false, "when generating, use non-crypto-grade entropy")
		zero   = fs.Bool("zero", false, "when generating, fix entropy to all-zeroes")
	)

	var args []string
	if len(os.Args) > 0 {
		args = os.Args[1:]
	}
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var formatFunc func(time.Time) string
	switch strings.ToLower(*format) {
	case "default":
		formatFunc = func(t time.Time) string { return t.Format(defaultms) }
	case "rfc3339":
		formatFunc = func(t time.Time) string { return t.Format(rfc3339ms) }
	case "unix":
		formatFunc = func(t time.Time) string { return fmt.Sprint(t.Unix()) }
	case "ms":
		formatFunc = func(t time.Time) string { return fmt.Sprint(t.UnixNano() / 1e6) }
	default:
		fmt.Fprintf(os.Stderr, "invalid --format %s\n", *format)
		os.Exit(1)
	}

	switch args := fs.Args(); len(args) {
	case 0:
		generate(*quick, *zero)
	default:
		parse(args[0], *local, formatFunc)
	}
}

func generate(quick, zero bool) {
	entropy := cryptorand.Reader
	if quick {
		seed := time.Now().UnixNano()
		source := mathrand.NewSource(seed)
		entropy = mathrand.New(source)
	}
	if zero {
		entropy = zeroReader{}
	}

	id, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "%s\n", id)
}

func parse(s string, local bool, f func(time.Time) string) {
	id, err := ulid.ParseStrict(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	t := ulid.Time(id.Time())
	if !local {
		t = t.UTC()
	}
	fmt.Fprintf(os.Stderr, "%s\n", f(t))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
