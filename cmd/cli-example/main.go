// cli-example - A demonstrates of common patterns for CLI utilities
//
// Authored in 2026 by AJ ONeal <aj@therootcompany.com> w/ Grok (https://grok.com).
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package main

import (
	"flag"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	name         = "smtp-test"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal"
	licenseType  = "CC0-1.0"
)

// set by GoReleaser via ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01T00:00:00Z"
)

func printVersion() {
	if len(commit) > 7 {
		commit = commit[:7]
	}
	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, commit, date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

type CLIConfig struct {
	showVersion bool
	user        string
	from        string
	to          string
	host        string // e.g. smtp.mailgun.org:587 or smtp.gmail.com:587
	subject     string
	body        string
}

func main() {
	cfg := CLIConfig{
		subject: "smtp-test - connectivity check",
		body:    "This is a test message from smtp-test.\nIf you received this, SMTP auth + send worked.",
	}

	mainFlags := flag.NewFlagSet("", flag.ContinueOnError)

	mainFlags.BoolVar(&cfg.showVersion, "version", false, "Print version and exit")
	mainFlags.StringVar(&cfg.user, "user", os.Getenv("SMTP_USER"), "Auth email e.g. 'you@gmail.com' or set SMTP_USER")
	mainFlags.StringVar(&cfg.from, "from", os.Getenv("SMTP_FROM"), "Sender email, e.g. 'you@gmail.com' or set SMTP_FROM")
	mainFlags.StringVar(&cfg.to, "to", os.Getenv("SMTP_TO"), "Recipient email, e.g. 'test@yourdomain.com' or set SMTP_TO")
	mainFlags.StringVar(&cfg.host, "host", os.Getenv("SMTP_HOST"), "SMTP server + port, e.g. 'smtp.gmail.com:587' or set SMTP_HOST")
	mainFlags.StringVar(&cfg.subject, "subject", cfg.subject, "Subject line (default: connectivity check)")
	mainFlags.StringVar(&cfg.body, "body", cfg.body, "Plain text body (default: test message)")

	mainFlags.Usage = func() {
		printVersion()
		out := mainFlags.Output()
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, "USAGE\n")
		fmt.Fprintf(out, "   smtp-test [options]\n")
		fmt.Fprintf(out, "   (or provide most values via environment variables)\n\n")
		mainFlags.PrintDefaults()
		fmt.Fprintf(out, "\nExamples:\n")
		fmt.Fprintf(out, "   SMTP_HOST=smtp.mailgun.org:587 SMTP_FROM=you@mg.domain SMTP_TO=you@gmail.com smtp-test\n")
		fmt.Fprintf(out, "   smtp-test -host smtp.gmail.com:587 -from you@gmail.com -to debug@yourself.com\n")
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "version", "-version", "--version":
			printVersion()
			return
		case "help", "-help", "--help":
			mainFlags.SetOutput(os.Stdout)
			mainFlags.Usage()
			return
		}
	}

	if err := mainFlags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		mainFlags.SetOutput(os.Stderr)
		mainFlags.Usage()
		os.Exit(1)
	}

	if cfg.showVersion {
		printVersion()
		return
	}

	// Required fields
	if cfg.from == "" || cfg.to == "" || cfg.host == "" {
		fmt.Fprintln(os.Stderr, "Missing required parameters: --from, --to, --host (or matching env vars)")
		mainFlags.Usage()
		os.Exit(1)
	}

	user := cfg.user                           // usually same as from for plain auth
	pass, hasPass := os.LookupEnv("SMTP_PASS") // SMTP_PASS to be consistent style with your SMB_PASSWORD
	if !hasPass {
		fmt.Fprintf(os.Stderr, "SMTP_PASS is not set → ")
		fmt.Print("Password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read password: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\n")
		pass = strings.TrimRight(string(password), "\r\n \t")
	}

	fmt.Printf("Trying to send from %s → %s via %s ...\n", cfg.from, cfg.to, cfg.host)

	trySMTP(cfg.host, cfg.from, user, pass, cfg.to, cfg.subject, cfg.body)
	fmt.Println("")
}

func trySMTP(addr, from, username, password, to, subject, body string) {
	// Most modern SMTP servers expect 587 + STARTTLS (not native 465 SSL)
	// net/smtp.SendMail automatically attempts STARTTLS when available.
	auth := smtp.PlainAuth("", username, password, strings.Split(addr, ":")[0])

	// Build minimal RFC-compliant message
	msg := (fmt.Appendf(
		[]byte{},
		"To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: %s\r\n"+
			"\r\n"+
			"%s\r\n",
		to, from, subject, body,
	))

	err := smtp.SendMail(addr, auth, from, []string{to}, msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SMTP error: %v\n", err)
		// Common helpful hints
		if strings.Contains(err.Error(), "535") || strings.Contains(err.Error(), "authentication") {
			fmt.Fprintln(os.Stderr, "→ Check username/password (Gmail may need app password)")
		}
		if strings.Contains(err.Error(), "STARTTLS") || strings.Contains(err.Error(), "TLS") {
			fmt.Fprintln(os.Stderr, "→ Server may require TLS — try port 587 instead of 465, or vice versa")
		}
		return
	}

	fmt.Printf("Success! Email sent:\n%s\n", string(msg))
}
