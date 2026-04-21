// git-shallow-sync syncs a shallow git clone at the given local path,
// cloning on first run and fetching + hard-resetting on subsequent runs.
//
// Usage:
//
//	git-shallow-sync <repository-url> <local-path>
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
)

const version = "dev"

type Config struct {
	Depth  int
	Branch string
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
			fmt.Fprintf(os.Stdout, "git-shallow-sync %s\n", version)
			os.Exit(0)
		case "help", "-help", "--help":
			fmt.Fprintf(os.Stdout, "git-shallow-sync %s\n\n", version)
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

	fmt.Fprintf(os.Stderr, "Syncing %s -> %s... ", url, absPath)
	t := time.Now()
	repo := gitshallow.New(url, absPath, cfg.Depth, cfg.Branch)
	updated, err := repo.Sync()
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
