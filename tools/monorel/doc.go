// monorel - Monorepo Release Tool
//
// Pass any number of paths to Go main packages. monorel walks up from each
// path to find its go.mod (stopping at .git so it never crosses the repo
// boundary), groups binaries by their module root, and performs the requested
// subcommand.
//
// Subcommands:
//
//	monorel release <binary-path>...
//	    Generate .goreleaser.yaml and print a ready-to-review bash release script.
//
//	monorel bump [-r major|minor|patch] <binary-path>...
//	    Create a new semver tag at the module's latest commit (default: patch).
//
//	monorel init <binary-path>...
//	    Write .goreleaser.yaml, commit it, and run bump patch for each module
//	    (processed in the order their paths appear on the command line).
//
// Install:
//
//	go install github.com/therootcompany/golib/tools/monorel@latest
package main
