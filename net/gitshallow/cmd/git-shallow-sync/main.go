// git-shallow-sync syncs a shallow git clone at the given local path,
// cloning on first run and fetching + hard-resetting on subsequent runs.
//
// Usage:
//
//	git-shallow-sync <repository-url> <local-path>
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
)

// Replaced by goreleaser / ldflags at build time.
var (
	name         = "git-shallow-sync"
	version      = "0.0.0-dev"
	commit       = "0000000"
	date         = "0001-01-01"
	licenseYear  = "2021-present"
	licenseOwner = "AJ ONeal <aj@therootcompany.com>"
	licenseType  = "MPL-2.0"
)

type Config struct {
	Depth  int
	Branch string
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

func main() {
	cfg := Config{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.IntVar(&cfg.Depth, "depth", 1, "clone/fetch depth (-1 for full history)")
	fs.StringVar(&cfg.Branch, "branch", "", "branch to track (empty: remote default)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <repository-url> <local-path>\n", os.Args[0])
		fs.PrintDefaults()
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
		os.Exit(1)
	}

	args := fs.Args()
	if len(args) != 2 {
		fs.Usage()
		os.Exit(1)
	}
	url := args[0]
	path := args[1]

	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: resolve home: %v\n", err)
			os.Exit(1)
		}
		path = filepath.Join(home, path[1:])
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid path: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "Syncing %s -> %s... ", url, absPath)
	t := time.Now()
	repo := gitshallow.New(url, absPath, cfg.Depth, cfg.Branch)
	updated, err := repo.Fetch(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "error: sync: %v\n", err)
		os.Exit(1)
	}
	state := "already up to date"
	if updated {
		state = "updated"
	}
	fmt.Fprintf(os.Stderr, "%s (%s)\n", time.Since(t).Round(time.Millisecond), state)
}
