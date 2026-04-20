// ipcohort-contains checks whether one or more IP addresses appear in a set
// of cohort files (plain text, one IP/CIDR per line).
//
// Usage:
//
//	ipcohort-contains [flags] <file>... -- <ip>...
//	ipcohort-contains [flags] -ip <ip> <file>...
//
// Examples:
//
//	ipcohort-contains networks.txt single_ips.txt -- 1.2.3.4 5.6.7.8
//	ipcohort-contains -ip 1.2.3.4 single_ips.txt
//	echo "1.2.3.4" | ipcohort-contains networks.txt
//
// Exit code: 0 if all queried IPs are found, 1 if any are not found, 2 on error.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/therootcompany/golib/net/ipcohort"
)

func main() {
	ipFlag := flag.String("ip", "", "IP address to check (alternative to -- separator)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <file>... -- <ip>...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s -ip <ip> <file>...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       echo <ip> | %s <file>...\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "Exit: 0=all found, 1=not found, 2=error")
	}
	flag.Parse()

	args := flag.Args()
	var filePaths, ips []string

	switch {
	case *ipFlag != "":
		filePaths = args
		ips = []string{*ipFlag}
	default:
		// Split args at "--"
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
		flag.Usage()
		os.Exit(2)
	}

	cohort, err := ipcohort.LoadFiles(filePaths...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	// If no IPs from flags/args, read from stdin.
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
		flag.Usage()
		os.Exit(2)
	}

	allFound := true
	for _, ip := range ips {
		found := cohort.Contains(ip)
		if found {
			fmt.Printf("%s\tFOUND\n", ip)
		} else {
			fmt.Printf("%s\tNOT FOUND\n", ip)
			allFound = false
		}
	}

	if !allFound {
		os.Exit(1)
	}
}
