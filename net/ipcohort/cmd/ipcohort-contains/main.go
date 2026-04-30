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
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/therootcompany/golib/net/ipcohort"
)

const version = "dev"

func commafy(n int) string {
	s := strconv.Itoa(n)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	if len(s) <= 3 {
		return neg + s
	}
	var b strings.Builder
	head := len(s) % 3
	if head > 0 {
		b.WriteString(s[:head])
		b.WriteByte(',')
	}
	for i := head; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return neg + b.String()
}

type Config struct {
	IP     string
	Format string
}

const (
	formatPretty = "pretty"
	formatTSV    = "tsv"
	formatCSV    = "csv"
	formatJSON   = "json"
)

func parseFormat(s string) (string, error) {
	switch s {
	case "":
		if term.IsTerminal(int(os.Stdout.Fd())) {
			return formatPretty, nil
		}
		return formatTSV, nil
	case formatPretty, formatTSV, formatCSV, formatJSON:
		return s, nil
	default:
		return "", fmt.Errorf("unknown format %q (want pretty, tsv, csv, json)", s)
	}
}

type result struct {
	IP    string `json:"ip"`
	Found bool   `json:"found"`
}

func writeResults(format string, results []result) error {
	switch format {
	case formatPretty:
		w := 0
		for _, r := range results {
			if len(r.IP) > w {
				w = len(r.IP)
			}
		}
		for _, r := range results {
			status := "NOT FOUND"
			if r.Found {
				status = "FOUND"
			}
			fmt.Printf("%-*s  %s\n", w, r.IP, status)
		}
	case formatTSV:
		for _, r := range results {
			status := "NOT FOUND"
			if r.Found {
				status = "FOUND"
			}
			fmt.Printf("%s\t%s\n", r.IP, status)
		}
	case formatCSV:
		cw := csv.NewWriter(os.Stdout)
		_ = cw.Write([]string{"ip", "status"})
		for _, r := range results {
			status := "NOT FOUND"
			if r.Found {
				status = "FOUND"
			}
			if err := cw.Write([]string{r.IP, status}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	case formatJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	return nil
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
			fmt.Fprintf(os.Stdout, "ipcohort-contains %s\n", version)
			os.Exit(0)
		case "help", "-help", "--help":
			fmt.Fprintf(os.Stdout, "ipcohort-contains %s\n\n", version)
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

	args := fs.Args()
	var filePaths, ips []string
	switch {
	case cfg.IP != "":
		filePaths = args
		ips = []string{cfg.IP}
	default:
		sep := -1
		for i, a := range args {
			if a == "--" {
				sep = i
				break
			}
		}
		if sep >= 0 {
			filePaths = args[:sep]
			ips = args[sep+1:]
		} else {
			filePaths = args
		}
	}

	if len(filePaths) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one file path required")
		fs.Usage()
		os.Exit(2)
	}

	fmt.Fprint(os.Stderr, "Loading cohort... ")
	t := time.Now()
	cohort, err := ipcohort.LoadFiles(filePaths...)
	if err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "%s (entries=%s)\n",
		time.Since(t).Round(time.Millisecond),
		commafy(cohort.Size()),
	)

	if len(ips) == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
				ips = append(ips, line)
			}
		}
		if err := sc.Err(); err != nil {
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

	results := make([]result, 0, len(ips))
	allFound := true
	for _, ip := range ips {
		found := cohort.Contains(ip)
		results = append(results, result{IP: ip, Found: found})
		if !found {
			allFound = false
		}
	}
	if err := writeResults(format, results); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if !allFound {
		os.Exit(1)
	}
}
