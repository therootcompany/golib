// ipcohort-contains checks whether one or more IP addresses appear in a set
// of cohort files (plain text, one IP/CIDR per line).
//
// Usage:
//
//	ipcohort-contains [flags] <file>... -- <ip>...
//	ipcohort-contains [flags] --ip <ip> <file>...
//	echo "<ip>" | ipcohort-contains <file>...
//
// Exit code: 0 if all queried IPs are found, 1 if any are not found, 2 on error.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/therootcompany/golib/net/ipcohort"
)

// Replaced by goreleaser / ldflags at build time.
var (
	name         = "ipcohort-contains"
	version      = "0.0.0-dev"
	commit       = "0000000"
	date         = "0001-01-01"
	licenseYear  = "2021-present"
	licenseOwner = "AJ ONeal <aj@therootcompany.com>"
	licenseType  = "MPL-2.0"
)

type Config struct {
	IP     string
	Format string
}

func main() {
	cfg := Config{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.IP, "ip", "", "IP address to check (alternative to -- separator)")
	fs.StringVar(&cfg.Format, "format", "", "output format: pretty, tsv, csv, json (default: auto)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <file>... -- <ip>...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --ip <ip> <file>...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       echo <ip> | %s <file>...\n", os.Args[0])
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "Exit: 0=all found, 1=not found, 2=error")
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout, "")
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	filePaths, ips := splitArgs(fs.Args(), cfg.IP)
	if len(filePaths) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one file path required")
		fs.Usage()
		os.Exit(2)
	}

	cohort := loadCohort(filePaths)

	if len(ips) == 0 {
		var err error
		ips, err = readIPsFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
			os.Exit(2)
		}
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "error: no IP addresses to check")
		fs.Usage()
		os.Exit(2)
	}

	fmt.Fprintln(os.Stderr)

	format, err := parseFormat(cfg.Format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	results, allFound := check(cohort, ips)
	if err := writeTable(format, results); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if !allFound {
		os.Exit(1)
	}
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

// splitArgs separates positional args into file paths and IPs, using either
// the --ip flag (single IP) or a `--` separator (multiple IPs). When neither
// is set, all args are file paths and IPs come from stdin.
func splitArgs(args []string, ipFlag string) (filePaths, ips []string) {
	if ipFlag != "" {
		return args, []string{ipFlag}
	}
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func loadCohort(filePaths []string) *ipcohort.Cohort {
	fmt.Fprint(os.Stderr, "Loading cohort... ")
	t := time.Now()
	cohort, err := ipcohort.LoadFiles(filePaths...)
	if cohort == nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "%s (entries=%s)\n",
		time.Since(t).Round(time.Millisecond),
		commafy(cohort.Size()),
	)
	return cohort
}

func readIPsFromStdin() ([]string, error) {
	var ips []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line)
	}
	return ips, sc.Err()
}

func check(cohort *ipcohort.Cohort, ips []string) (results []result, allFound bool) {
	results = make([]result, 0, len(ips))
	allFound = true
	for _, ip := range ips {
		found, err := cohort.Contains(ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		results = append(results, result{IP: ip, Found: found})
		if !found {
			allFound = false
		}
	}
	return results, allFound
}
