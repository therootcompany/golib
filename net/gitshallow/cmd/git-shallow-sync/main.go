// git-shallow-sync is a simple CLI tool to synchronize a shallow git repository
// using the github.com/therootcompany/golib/net/gitshallow package.
//
// Usage:
//
//	git-shallow-sync <repository-url> <local-path>
//
// Example:
//
//	git-shallow-sync git@github.com:bitwire-it/ipblocklist.git ~/srv/app/ipblocklist
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/therootcompany/golib/net/gitshallow"
)

const (
	defaultDepth  = 1     // shallow by default
	defaultBranch = ""    // empty = default branch + --single-branch
	laxGC         = false // false = --aggressive
	lazyPrune     = false // false = --prune=now
)

func main() {
	if len(os.Args) != 3 {
		name := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage: %s <repository-url> <local-path>\n", name)
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  %s git@github.com:bitwire-it/ipblocklist.git ~/srv/app/ipblocklist\n", name)
		os.Exit(1)
	}

	url := os.Args[1]
	path := os.Args[2]

	// Expand ~ to home directory for Windows
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get home directory: %v\n", err)
			os.Exit(1)
		}
		path = filepath.Join(home, path[1:])
	}

	// Make path absolute
	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid path: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Syncing repository:\n")
	fmt.Printf("  URL:  %s\n", url)
	fmt.Printf("  Path: %s\n", absPath)

	repo := gitshallow.New(url, absPath, defaultDepth, defaultBranch)

	updated, err := repo.Sync(laxGC, lazyPrune)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sync failed: %v\n", err)
		os.Exit(1)
	}

	if updated {
		fmt.Println("Repository was updated (new commits fetched).")
	} else {
		fmt.Println("Repository is already up to date.")
	}

	fmt.Println("Sync complete.")
}
