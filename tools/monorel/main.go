// monorel: Monorepo Release Tool
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

import (
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// stopMarkers are the directory entries that mark the top of a git repository.
// findModuleRoot stops walking upward when it encounters one of these entries
// as a DIRECTORY, so it never crosses into a parent repository.
// A .git FILE (not a directory) means we are inside a submodule — the real
// repository root is further up, so we keep looking.
// Adjust this slice if you ever need to search across repository boundaries.
var stopMarkers = []string{".git"}

// ── Types ──────────────────────────────────────────────────────────────────

// binary describes one Go main package to build and release.
type binary struct {
	name     string // last path component, e.g. "gsheet2csv"
	mainPath string // path relative to module root, e.g. "./cmd/gsheet2csv" or "."
}

// moduleGroup is all the binaries that share one module root.
type moduleGroup struct {
	root string // absolute path to the directory containing go.mod
	bins []binary
}

// ── Entry point ────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "release":
		runRelease(os.Args[2:])
	case "bump":
		runBump(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "monorel: unknown subcommand %q\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Run 'monorel help' for usage.")
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "monorel: Monorepo Release Tool")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  monorel <subcommand> [options] <binary-path>...")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  release   Write .goreleaser.yaml and print a bash release script")
	fmt.Fprintln(os.Stderr, "  bump      Create a new semver tag at HEAD (default: patch)")
	fmt.Fprintln(os.Stderr, "  init      Write .goreleaser.yaml, commit it, and bump patch")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Each <binary-path> points to a Go main package directory. monorel")
	fmt.Fprintln(os.Stderr, "walks up from each path to find the module root (go.mod), stopping")
	fmt.Fprintln(os.Stderr, "at the repository boundary (.git directory).")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run 'monorel <subcommand> --help' for subcommand-specific usage.")
}

// ── Subcommand: release ────────────────────────────────────────────────────

func runRelease(args []string) {
	fs := flag.NewFlagSet("monorel release", flag.ExitOnError)
	var recursive, all bool
	fs.BoolVar(&recursive, "recursive", false, "find all main packages recursively under each path")
	fs.BoolVar(&all, "A", false, "include dot/underscore-prefixed directories; warn rather than error on failures")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: monorel release [options] <binary-path>...")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Writes .goreleaser.yaml next to each module's go.mod and prints a")
		fmt.Fprintln(os.Stderr, "ready-to-review bash release script to stdout.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  monorel release .                          # single binary at module root")
		fmt.Fprintln(os.Stderr, "  monorel release ./cmd/foo ./cmd/bar        # multiple binaries, same module")
		fmt.Fprintln(os.Stderr, "  monorel release auth/csvauth/cmd/csvauth   # from repo root")
		fmt.Fprintln(os.Stderr, "  monorel release -recursive .               # all modules under current directory")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	binPaths := fs.Args()
	if len(binPaths) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	allPaths, err := expandPaths(binPaths, recursive, all)
	if err != nil {
		fatalf("%v", err)
	}
	if len(allPaths) == 0 {
		fatalf("no main packages found under the given paths")
	}
	groups, err := groupByModule(allPaths)
	if err != nil {
		fatalf("%v", err)
	}

	cwd, _ := os.Getwd()

	// Emit the bash header exactly once.
	fmt.Println("#!/usr/bin/env bash")
	fmt.Println("# Generated by monorel — review carefully before running!")
	fmt.Println("set -euo pipefail")

	for i, group := range groups {
		if i > 0 {
			fmt.Fprintln(os.Stderr)
		}
		printGroupHeader(cwd, group)
		relPath, _ := filepath.Rel(cwd, group.root)
		relPath = filepath.ToSlash(relPath)
		processModule(group, relPath)
	}
}

// ── Subcommand: bump ───────────────────────────────────────────────────────

func runBump(args []string) {
	fs := flag.NewFlagSet("monorel bump", flag.ExitOnError)
	var component string
	var recursive, all, force, dryRun bool
	fs.StringVar(&component, "r", "patch", "version component to bump: major, minor, or patch")
	fs.BoolVar(&recursive, "recursive", false, "find all main packages recursively under each path")
	fs.BoolVar(&all, "A", false, "include dot/underscore-prefixed directories; warn rather than error on failures")
	fs.BoolVar(&force, "force", false, "if no new commits, create an empty bump commit and tag it")
	fs.BoolVar(&dryRun, "dry-run", false, "print what would happen without creating commits or tags")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: monorel bump [options] <binary-path>...")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Creates a new semver git tag at the module's latest commit.")
		fmt.Fprintln(os.Stderr, "The tag is created locally; push it with 'git push --tags'.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  monorel bump ./cmd/csvauth                  # bump patch (default)")
		fmt.Fprintln(os.Stderr, "  monorel bump -r minor ./cmd/csvauth         # bump minor")
		fmt.Fprintln(os.Stderr, "  monorel bump -r major ./cmd/csvauth         # bump major")
		fmt.Fprintln(os.Stderr, "  monorel bump -recursive .                   # bump patch for all modules")
		fmt.Fprintln(os.Stderr, "  monorel bump -force ./cmd/csvauth           # bump even with no new commits")
		fmt.Fprintln(os.Stderr, "  monorel bump -dry-run -recursive .          # preview tags without creating them")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	switch component {
	case "major", "minor", "patch":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "monorel bump: -r must be major, minor, or patch (got %q)\n", component)
		os.Exit(2)
	}

	binPaths := fs.Args()
	if len(binPaths) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	allPaths, err := expandPaths(binPaths, recursive, all)
	if err != nil {
		fatalf("%v", err)
	}
	if len(allPaths) == 0 {
		fatalf("no main packages found under the given paths")
	}
	groups, err := groupByModule(allPaths)
	if err != nil {
		fatalf("%v", err)
	}
	cwd, _ := os.Getwd()
	for i, group := range groups {
		if i > 0 {
			fmt.Fprintln(os.Stderr)
		}
		printGroupHeader(cwd, group)
		newTag := bumpModuleTag(group, component, force, dryRun)
		switch {
		case newTag == "":
			// skipped: already printed a skip message
		case dryRun:
			fmt.Fprintf(os.Stderr, "[dry-run] would create tag: %s\n", newTag)
		default:
			fmt.Fprintf(os.Stderr, "created tag: %s\n", newTag)
		}
	}
}

// ── Subcommand: init ───────────────────────────────────────────────────────

func runInit(args []string) {
	fs := flag.NewFlagSet("monorel init", flag.ExitOnError)
	var recursive, all, dryRun, cmd bool
	fs.BoolVar(&recursive, "recursive", false, "find all main packages recursively under each path")
	fs.BoolVar(&all, "A", false, "include dot/underscore-prefixed directories; warn rather than error on failures")
	fs.BoolVar(&dryRun, "dry-run", false, "print what would happen without writing files, creating commits, or tags")
	fs.BoolVar(&cmd, "cmd", false, "for each cmd/ child with package main, run go mod init+tidy (suggests a commit at the end)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: monorel init [options] <binary-path>...")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "For each module (in command-line order):")
		fmt.Fprintln(os.Stderr, "  1. Writes .goreleaser.yaml next to go.mod")
		fmt.Fprintln(os.Stderr, "  2. Commits it (skipped if file is unchanged)")
		fmt.Fprintln(os.Stderr, "  3. Creates an initial version tag (equivalent to 'bump patch')")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "With -cmd, first scans for cmd/ subdirectories and runs go mod init+tidy")
		fmt.Fprintln(os.Stderr, "for each direct child that contains package main but has no go.mod yet.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  monorel init ./auth/csvauth/cmd/csvauth")
		fmt.Fprintln(os.Stderr, "  monorel init -recursive .               # init all modules under current directory")
		fmt.Fprintln(os.Stderr, "  monorel init -cmd -recursive .          # make cmd/ children independently versioned")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	binPaths := fs.Args()
	if len(binPaths) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	if cmd {
		initCmdModules(binPaths, dryRun)
	}

	allPaths, err := expandPaths(binPaths, recursive, all)
	if err != nil {
		fatalf("%v", err)
	}
	if len(allPaths) == 0 {
		fatalf("no main packages found under the given paths")
	}
	groups, err := groupByModule(allPaths)
	if err != nil {
		fatalf("%v", err)
	}
	cwd, _ := os.Getwd()
	for i, group := range groups {
		if i > 0 {
			fmt.Fprintln(os.Stderr)
		}
		printGroupHeader(cwd, group)
		initModuleGroup(group, dryRun)
	}
}

// initModuleGroup writes .goreleaser.yaml, commits it (if changed), and
// creates an initial version tag (bump patch) for one module group.
// When dryRun is true no files are written and no git mutations are made.
func initModuleGroup(group *moduleGroup, dryRun bool) {
	modRoot := group.root
	bins := group.bins

	prefix := mustRunIn(modRoot, "git", "rev-parse", "--show-prefix")
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		fmt.Fprintf(os.Stderr, "monorel: skip: %s is at the repository root; binaries at the repo root cannot have prefixed tags\n", modRoot)
		return
	}

	// Guard: skip if the module has uncommitted changes (files inside child
	// module directories — those with their own go.mod on disk — are excluded
	// so that a freshly-run --cmd step does not block the parent module).
	if hasUncommittedChanges(modRoot) {
		fmt.Fprintf(os.Stderr, "monorel: skip: %s has uncommitted changes; commit or stash them first\n", modRoot)
		return
	}

	prefixParts := strings.Split(prefix, "/")
	projectName := prefixParts[len(prefixParts)-1]

	// 1. Write .goreleaser.yaml.
	yamlContent := goreleaserYAML(projectName, bins)
	yamlPath := filepath.Join(modRoot, ".goreleaser.yaml")
	if dryRun {
		fmt.Fprintf(os.Stderr, "[dry-run] would write %s\n", yamlPath)
	} else {
		if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
			fatalf("writing %s: %v", yamlPath, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", yamlPath)

		// 2. Stage and commit if the file changed.
		mustRunIn(modRoot, "git", "add", ".goreleaser.yaml")
		if status := runIn(modRoot, "git", "status", "--porcelain", "--", ".goreleaser.yaml"); status != "" {
			commitMsg := "chore(release): add .goreleaser.yaml for " + projectName
			mustRunIn(modRoot, "git", "commit", "-m", commitMsg)
			fmt.Fprintf(os.Stderr, "committed: %s\n", commitMsg)
		} else {
			fmt.Fprintf(os.Stderr, "note: .goreleaser.yaml unchanged, skipping commit\n")
		}
	}

	// 3. Bump patch — but only when the goreleaser.yaml commit is the sole new
	// commit since the last stable tag (the common "first setup" scenario).
	// If other commits are already waiting to be tagged the user should choose
	// the right semver component with an explicit 'monorel bump'.
	shouldBump := true
	if !dryRun {
		latestStable := findLatestStableTag(modRoot, prefix)
		if latestStable != "" {
			logOut := strings.TrimSpace(runIn(modRoot, "git", "log", "--oneline", latestStable+"..HEAD", "--", "."))
			count := 0
			if logOut != "" {
				count = len(strings.Split(logOut, "\n"))
			}
			if count > 1 {
				fmt.Fprintf(os.Stderr,
					"note: %d commits since %s; skipping auto-bump — run 'monorel bump' when ready\n",
					count, latestStable)
				shouldBump = false
			}
		}
	}

	if shouldBump {
		newTag := bumpModuleTag(group, "patch", false, dryRun)
		switch {
		case newTag == "":
			// same-commit guard fired
		case dryRun:
			fmt.Fprintf(os.Stderr, "[dry-run] would create tag: %s\n", newTag)
		default:
			fmt.Fprintf(os.Stderr, "created tag: %s\n", newTag)
		}
	}
}

// ── Bump helpers ───────────────────────────────────────────────────────────

// findLatestStableTag returns the latest stable (no pre-release) tag for the
// given module prefix, or "" if none exists.
func findLatestStableTag(modRoot, prefix string) string {
	rawTags := runIn(modRoot, "git", "tag", "--list", prefix+"/v*")
	var stableTags []string
	for _, t := range strings.Split(rawTags, "\n") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		ver := strings.TrimPrefix(t, prefix+"/")
		if !strings.Contains(ver, "-") { // pre-releases have a "-" suffix
			stableTags = append(stableTags, t)
		}
	}
	sort.Slice(stableTags, func(i, j int) bool {
		vi := strings.TrimPrefix(stableTags[i], prefix+"/")
		vj := strings.TrimPrefix(stableTags[j], prefix+"/")
		return semverLess(vi, vj)
	})
	if n := len(stableTags); n > 0 {
		return stableTags[n-1]
	}
	return ""
}

// bumpModuleTag finds the latest stable tag for the module, computes the next
// version by bumping the given component (major, minor, or patch), creates the
// git tag at the module's latest commit, and returns the new tag name.
//
// If the module's latest commit is already tagged by the previous stable tag,
// bumpModuleTag prints a skip message and returns "". With force=true it
// instead creates an empty bump commit and tags that. With dryRun=true no git
// mutations are made; the computed tag name is returned so the caller can
// report what would have happened.
func bumpModuleTag(group *moduleGroup, component string, force, dryRun bool) string {
	modRoot := group.root

	prefix := mustRunIn(modRoot, "git", "rev-parse", "--show-prefix")
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		fmt.Fprintf(os.Stderr, "monorel: skip: %s is at the repository root; binaries at the repo root cannot have prefixed tags\n", modRoot)
		return ""
	}

	latestStable := findLatestStableTag(modRoot, prefix)

	newTag := computeBumpTag(prefix, latestStable, component)
	newVersion := strings.TrimPrefix(newTag, prefix+"/")

	// Tag the most recent commit that touched this module's directory, which
	// may be behind HEAD if other modules have been updated more recently.
	commitSHA := mustRunIn(modRoot, "git", "log", "--format=%H", "-1", "--", ".")
	if commitSHA == "" {
		fatalf("no commits found in %s", modRoot)
	}

	// Guard: skip (or force-bump) when the module's latest commit is already tagged.
	if latestStable != "" {
		prevCommit := mustRunIn(modRoot, "git", "rev-list", "-n", "1", latestStable)
		if prevCommit == commitSHA {
			if !force {
				fmt.Fprintf(os.Stderr, "monorel: skip: no new commits in %s since %s\n",
					prefix, latestStable)
				return ""
			}
			// Create an empty commit so we have something new to tag.
			commitMsg := "chore(release): bump to " + newVersion
			if dryRun {
				fmt.Fprintf(os.Stderr, "[dry-run] would create empty commit: %s\n", commitMsg)
			} else {
				mustRunIn(modRoot, "git", "commit", "--allow-empty", "-m", commitMsg)
				fmt.Fprintf(os.Stderr, "created empty commit: %s\n", commitMsg)
				commitSHA = mustRunIn(modRoot, "git", "rev-parse", "HEAD")
			}
		}
	}

	if dryRun {
		return newTag
	}
	mustRunIn(modRoot, "git", "tag", newTag, commitSHA)
	return newTag
}

// computeBumpTag returns the new full tag string for the given bump component,
// starting from latestStableTag (empty string = no prior stable tags).
func computeBumpTag(prefix, latestStableTag, component string) string {
	if latestStableTag == "" {
		switch component {
		case "major":
			return prefix + "/v1.0.0"
		default: // minor, patch
			return prefix + "/v0.1.0"
		}
	}

	semver := strings.TrimPrefix(latestStableTag, prefix+"/v")
	dp := strings.SplitN(semver, ".", 3)
	for len(dp) < 3 {
		dp = append(dp, "0")
	}
	major, _ := strconv.Atoi(dp[0])
	minor, _ := strconv.Atoi(dp[1])
	patch, _ := strconv.Atoi(dp[2])

	switch component {
	case "major":
		major++
		minor, patch = 0, 0
	case "minor":
		minor++
		patch = 0
	default: // patch
		patch++
	}
	return fmt.Sprintf("%s/v%d.%d.%d", prefix, major, minor, patch)
}

// ── Module discovery ───────────────────────────────────────────────────────

// expandPaths returns paths unchanged when recursive is false.  When true, it
// replaces each path with all main-package directories found beneath it.
// all mirrors the -A flag: include dot/underscore-prefixed directories and
// warn on errors instead of failing.
func expandPaths(paths []string, recursive, all bool) ([]string, error) {
	if !recursive {
		return paths, nil
	}
	var result []string
	for _, p := range paths {
		found, err := findMainPackages(p, all)
		if err != nil {
			return nil, fmt.Errorf("searching %s: %w", p, err)
		}
		result = append(result, found...)
	}
	return result, nil
}

// findMainPackages recursively walks root and returns the absolute path of
// every directory that contains a Go main package.  It stops descending into
// any directory listed in stopMarkers (e.g. .git directories), preventing
// the walk from crossing into a parent repository.
//
// Only directories that contain at least one git-tracked file are visited;
// untracked directories (dist/, vendor/, node_modules/, build artifacts, etc.)
// are skipped automatically.
//
// By default directories whose names begin with '.' or '_' are also skipped
// (they are conventionally hidden or disabled).  Pass all=true (the -A flag)
// to include them; in that mode ReadDir failures are downgraded to warnings so
// that a single unreadable directory doesn't abort the whole walk.
func findMainPackages(root string, all bool) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", root, err)
	}
	// Build the set of directories that contain at least one tracked file.
	// Nil means git is unavailable; in that case we fall back to walking
	// everything (pre-existing behaviour).
	trackedDirs := buildTrackedDirs(abs)

	var paths []string
	var walk func(dir string) error
	walk = func(dir string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if all {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", dir, err)
				return nil
			}
			return err
		}
		if checkPackageMain(dir) == nil {
			paths = append(paths, dir)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			// Honour stopMarkers: skip .git directories (repo boundary).
			// A .git FILE (submodule pointer) is not a directory, so it is
			// not matched here and we keep descending — consistent with
			// findModuleRoot's behaviour.
			skip := false
			for _, stop := range stopMarkers {
				if name == stop {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			// Skip dot- and underscore-prefixed directories unless -A is set.
			if !all && len(name) > 0 && (name[0] == '.' || name[0] == '_') {
				continue
			}
			child := filepath.Join(dir, name)
			// Stop at directories with their own go.mod — they are independent
			// module roots and should not be included in this module's walk.
			if _, err := os.Stat(filepath.Join(child, "go.mod")); err == nil {
				continue
			}
			// Skip directories that contain no git-tracked files.
			if trackedDirs != nil && !trackedDirs[child] {
				continue
			}
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return paths, walk(abs)
}

// buildTrackedDirs runs "git ls-files" from dir and returns the set of all
// directories (absolute paths) that contain at least one tracked file.
// Returns nil if dir is not inside a git repository or git is unavailable,
// in which case the caller proceeds without git-tracking filtering.
func buildTrackedDirs(dir string) map[string]bool {
	cmd := exec.Command("git", "ls-files")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	dirs := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		abs := filepath.Join(dir, filepath.FromSlash(line))
		// Mark every ancestor directory up to (but not including) dir.
		for d := filepath.Dir(abs); d != dir; d = filepath.Dir(d) {
			if dirs[d] {
				break // already added this path and all its ancestors
			}
			dirs[d] = true
		}
	}
	return dirs
}

// readModulePath returns the module path declared in the go.mod file at
// modRoot, or "" if the file cannot be read or the module line is absent.
func readModulePath(modRoot string) string {
	data, err := os.ReadFile(filepath.Join(modRoot, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// findChildModuleRoots returns the absolute paths of all subdirectories of
// modRoot that have their own go.mod on disk (even if untracked by git).
// It stops recursing past the first go.mod it finds in any subtree.
func findChildModuleRoots(modRoot string) []string {
	var roots []string
	var scan func(dir string)
	scan = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			child := filepath.Join(dir, e.Name())
			if _, err := os.Stat(filepath.Join(child, "go.mod")); err == nil {
				roots = append(roots, child)
				continue // don't recurse past a submodule
			}
			scan(child)
		}
	}
	scan(modRoot)
	return roots
}

// hasUncommittedChanges reports whether modRoot contains modified or untracked
// files according to "git status --porcelain".  Files inside child module
// directories (subdirectories with their own go.mod on disk, even if untracked)
// are excluded from the check.
func hasUncommittedChanges(modRoot string) bool {
	status := runIn(modRoot, "git", "status", "--porcelain", "--", ".")
	if status == "" {
		return false
	}
	childRoots := findChildModuleRoots(modRoot)
	for _, line := range strings.Split(status, "\n") {
		if len(line) < 4 {
			continue
		}
		relFile := strings.TrimSpace(line[3:])
		abs := filepath.Join(modRoot, filepath.FromSlash(relFile))
		inChild := false
		for _, cr := range childRoots {
			if abs == cr || strings.HasPrefix(abs, cr+string(filepath.Separator)) {
				inChild = true
				break
			}
		}
		if !inChild {
			return true
		}
	}
	return false
}

// initCmdModules scans each of roots recursively, and for every direct child
// of a directory named "cmd" that contains a Go main package but has no go.mod
// yet, runs "go mod init <path>" and "go mod tidy".  At the end it prints a
// suggested git command to commit the new files.
func initCmdModules(roots []string, dryRun bool) {
	var initialized []string
	seen := make(map[string]bool)

	var scan func(dir string)
	scan = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			isStop := false
			for _, stop := range stopMarkers {
				if name == stop {
					isStop = true
					break
				}
			}
			if isStop || (len(name) > 0 && (name[0] == '.' || name[0] == '_')) {
				continue
			}
			child := filepath.Join(dir, name)
			if name == "cmd" {
				// Inspect each direct child of this cmd/ directory.
				cmdEntries, err := os.ReadDir(child)
				if err == nil {
					for _, ce := range cmdEntries {
						if !ce.IsDir() {
							continue
						}
						target := filepath.Join(child, ce.Name())
						if seen[target] {
							continue
						}
						seen[target] = true
						// Already has its own module — skip.
						if _, err := os.Stat(filepath.Join(target, "go.mod")); err == nil {
							continue
						}
						// Not a main package — skip.
						if checkPackageMain(target) != nil {
							continue
						}
						// Compute new module path from the parent module.
						modRoot, err := findModuleRoot(target)
						if err != nil {
							fmt.Fprintf(os.Stderr, "warning: --cmd: no module root for %s: %v\n", target, err)
							continue
						}
						parentModPath := readModulePath(modRoot)
						if parentModPath == "" {
							fmt.Fprintf(os.Stderr, "warning: --cmd: cannot read module path from %s\n", modRoot)
							continue
						}
						rel, _ := filepath.Rel(modRoot, target)
						newModPath := parentModPath + "/" + filepath.ToSlash(rel)
						if dryRun {
							fmt.Fprintf(os.Stderr, "[dry-run] would init module %s\n", newModPath)
							fmt.Fprintf(os.Stderr, "[dry-run] would run go mod tidy in %s\n", target)
						} else {
							fmt.Fprintf(os.Stderr, "init module %s\n", newModPath)
							runPrintIn(target, "go", "mod", "init", newModPath)
							runPrintIn(target, "go", "mod", "tidy")
						}
						initialized = append(initialized, target)
					}
				}
			}
			scan(child) // always recurse into children
		}
	}

	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: --cmd: resolving %s: %v\n", root, err)
			continue
		}
		scan(abs)
	}

	if len(initialized) > 0 {
		fmt.Fprintln(os.Stderr)
		if dryRun {
			fmt.Fprintf(os.Stderr, "[dry-run] %d cmd module(s) would be initialised\n", len(initialized))
		} else {
			fmt.Fprintf(os.Stderr, "note: initialised %d cmd module(s); to commit them, run:\n", len(initialized))
			fmt.Fprintf(os.Stderr, "  git add '**/cmd/**/go.*' && git commit -m \"chore(release): independently versioned modules for all\"\n")
		}
	} else if !dryRun {
		fmt.Fprintln(os.Stderr, "note: --cmd: no uninitialised cmd modules found")
	}
}

// findModuleRoot walks upward from absDir looking for a directory that
// contains go.mod.  It stops (with an error) if it encounters a stopMarker
// (default: ".git") before finding go.mod, preventing searches from crossing
// into a parent repository.
func findModuleRoot(absDir string) (string, error) {
	dir := absDir
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		for _, stop := range stopMarkers {
			info, err := os.Stat(filepath.Join(dir, stop))
			// A .git FILE means submodule — keep looking up the chain.
			// Only a .git DIRECTORY marks the true repository root.
			if err == nil && info.IsDir() {
				return "", fmt.Errorf(
					"no go.mod found between %s and the repository root (%s)",
					absDir, dir)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", absDir)
		}
		dir = parent
	}
}

// checkPackageMain returns an error if dir does not contain a Go main package.
// It only parses the package clause of each file (PackageClauseOnly mode is
// fast: it reads just the first few tokens of every .go file).
func checkPackageMain(dir string) error {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, parser.PackageClauseOnly)
	if err != nil {
		return fmt.Errorf("parsing Go files in %s: %w", dir, err)
	}
	if len(pkgs) == 0 {
		return fmt.Errorf("no Go source files in %s", dir)
	}
	if _, ok := pkgs["main"]; ok {
		return nil
	}
	// Collect non-test package names for the error message.
	var names []string
	for name := range pkgs {
		if !strings.HasSuffix(name, "_test") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no non-test Go source files in %s", dir)
	}
	return fmt.Errorf("%s is package %q, not a main package", dir, strings.Join(names, ", "))
}

// groupByModule resolves each binary path to an absolute directory, finds its
// module root via findModuleRoot, and groups binaries by that root.  Groups
// are returned in first-occurrence order (preserving the order of args).
func groupByModule(args []string) ([]*moduleGroup, error) {
	groupMap := make(map[string]*moduleGroup)
	var order []string

	for _, arg := range args {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", arg, err)
		}
		// If the path is a file (not a directory), start from its parent.
		absDir := abs
		if info, err := os.Stat(abs); err == nil && !info.IsDir() {
			absDir = filepath.Dir(abs)
		}

		if err := checkPackageMain(absDir); err != nil {
			return nil, err
		}

		modRoot, err := findModuleRoot(absDir)
		if err != nil {
			return nil, err
		}

		// mainPath = path from module root to the binary directory.
		rel, err := filepath.Rel(modRoot, absDir)
		if err != nil {
			return nil, fmt.Errorf("computing relative path for %s: %w", arg, err)
		}
		rel = filepath.ToSlash(rel)

		var name, mainPath string
		if rel == "." {
			name = filepath.Base(modRoot) // e.g. "tcpfwd" or "gsheet2csv"
			mainPath = "."
		} else {
			name = filepath.Base(rel) // last component
			mainPath = "./" + rel     // e.g. "./cmd/gsheet2csv"
		}

		if _, ok := groupMap[modRoot]; !ok {
			groupMap[modRoot] = &moduleGroup{root: modRoot}
			order = append(order, modRoot)
		}
		groupMap[modRoot].bins = append(groupMap[modRoot].bins, binary{name: name, mainPath: mainPath})
	}

	groups := make([]*moduleGroup, len(order))
	for i, root := range order {
		groups[i] = groupMap[root]
	}
	return groups, nil
}

// ── Per-module processing ──────────────────────────────────────────────────

// printGroupHeader writes "found binary …" and "found module …" lines to
// stderr before each module is processed, providing progress feedback during
// recursive operations.
func printGroupHeader(cwd string, group *moduleGroup) {
	modRel, _ := filepath.Rel(cwd, group.root)
	modRel = filepath.ToSlash(modRel)
	for _, bin := range group.bins {
		suffix := strings.TrimPrefix(bin.mainPath, "./")
		var binPath string
		if suffix == "." || suffix == "" {
			binPath = "./" + modRel
		} else {
			binPath = "./" + filepath.ToSlash(filepath.Join(modRel, suffix))
		}
		fmt.Fprintf(os.Stderr, "found binary %s\n", binPath)
	}
	modLabel := "./" + modRel
	if !strings.HasSuffix(modLabel, "/") {
		modLabel += "/"
	}
	fmt.Fprintf(os.Stderr, "found module %s\n", modLabel)
}

// processModule writes .goreleaser.yaml and emits the release-script section
// for one module group.  relPath is the path from the caller's CWD to the
// module root; it is used in the script for all paths so that the script can
// be run from the directory where monorel was invoked.
func processModule(group *moduleGroup, relPath string) {
	modRoot := group.root
	bins := group.bins

	// Module prefix within the repo (e.g. "io/transform/gsheet2csv").
	// This is also the git-tag prefix: "io/transform/gsheet2csv/v1.2.3".
	prefix := mustRunIn(modRoot, "git", "rev-parse", "--show-prefix")
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		fmt.Fprintf(os.Stderr, "monorel: skip: %s is at the repository root; binaries at the repo root cannot have prefixed tags\n", modRoot)
		return
	}

	prefixParts := strings.Split(prefix, "/")
	projectName := prefixParts[len(prefixParts)-1]

	rawURL := mustRunIn(modRoot, "git", "remote", "get-url", "origin")
	repoPath := normalizeGitURL(rawURL)

	// 1. Write .goreleaser.yaml (always regenerate).
	// Track whether this is a first-time creation: auto-commit and auto-tag
	// only apply when the file is new.  If it already exists, just update it
	// on disk and leave committing to the user.
	yamlContent := goreleaserYAML(projectName, bins)
	yamlPath := filepath.Join(modRoot, ".goreleaser.yaml")
	isNewFile := true
	if existing, err := os.ReadFile(yamlPath); err == nil {
		isNewFile = false
		// Warn if a stock {{ .ProjectName }} template is in use.
		hasProjectName := strings.Contains(string(existing), "{{ .ProjectName }}") ||
			strings.Contains(string(existing), "{{.ProjectName}}")
		gitInfo, gitErr := os.Stat(filepath.Join(modRoot, ".git"))
		atGitRoot := gitErr == nil && gitInfo.IsDir()
		if hasProjectName && !atGitRoot {
			fmt.Fprintf(os.Stderr, "warning: %s: contains {{ .ProjectName }} but module is a monorepo subdirectory;\n", yamlPath)
			fmt.Fprintf(os.Stderr, "  replacing stock goreleaser config with monorel-generated config.\n")
		}
	}
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
		fatalf("writing %s: %v", yamlPath, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", yamlPath)

	// 2. Auto-commit + auto-tag — only when the file was newly created.
	if isNewFile {
		mustRunIn(modRoot, "git", "add", ".goreleaser.yaml")
		if status := runIn(modRoot, "git", "status", "--porcelain", "--", ".goreleaser.yaml"); status != "" {
			commitMsg := "chore(release): add .goreleaser.yaml for " + projectName
			mustRunIn(modRoot, "git", "commit", "-m", commitMsg)
			fmt.Fprintf(os.Stderr, "committed: %s\n", commitMsg)
		}
		// Auto-tag patch if the yaml commit is the sole new commit since the
		// last stable tag — same heuristic as 'monorel init'.
		latestStable := findLatestStableTag(modRoot, prefix)
		shouldBump := true
		if latestStable != "" {
			logOut := strings.TrimSpace(runIn(modRoot, "git", "log", "--oneline", latestStable+"..HEAD", "--", "."))
			count := 0
			if logOut != "" {
				count = len(strings.Split(logOut, "\n"))
			}
			if count > 1 {
				fmt.Fprintf(os.Stderr,
					"note: %d commits since %s; skipping auto-bump — run 'monorel bump' when ready\n",
					count, latestStable)
				shouldBump = false
			}
		}
		if shouldBump {
			if newTag := bumpModuleTag(group, "patch", false, false); newTag != "" {
				fmt.Fprintf(os.Stderr, "created tag: %s\n", newTag)
			}
		}
	}

	// 3. Collect and semver-sort tags — done after yaml commit + auto-tag so
	// the version computation reflects any tag just created above.
	rawTags := runIn(modRoot, "git", "tag", "--list", prefix+"/v*")
	var tags []string
	for _, t := range strings.Split(rawTags, "\n") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	sort.Slice(tags, func(i, j int) bool {
		vi := strings.TrimPrefix(tags[i], prefix+"/")
		vj := strings.TrimPrefix(tags[j], prefix+"/")
		return semverLess(vi, vj)
	})

	var latestTag, prevStableTag string
	if n := len(tags); n > 0 {
		latestTag = tags[n-1]
		if n > 1 {
			prevStableTag = tags[n-2]
		}
	}

	isDirty := runIn(modRoot, "git", "status", "--porcelain", "--", ".") != ""

	var commitCount int
	if latestTag != "" {
		logOut := runIn(modRoot, "git", "log", "--oneline", latestTag+"..HEAD", "--", ".")
		if logOut != "" {
			commitCount = len(strings.Split(logOut, "\n"))
		}
	}

	version, currentTag, isPreRelease, needsNewTag := computeVersion(
		prefix, latestTag, commitCount, isDirty,
	)

	prevTag := prevStableTag
	if isPreRelease {
		prevTag = latestTag
	}

	// 4. Pre-compute release notes so the script contains the actual commit list.
	var releaseNotes string
	if prevTag != "" {
		releaseNotes = runIn(modRoot, "git", "--no-pager", "log", prevTag+"..HEAD",
			"--pretty=format:- %h %s", "--", ".")
	} else {
		releaseNotes = runIn(modRoot, "git", "--no-pager", "log",
			"--pretty=format:- %h %s", "--", ".")
	}

	headSHA := mustRunIn(modRoot, "git", "rev-parse", "HEAD")
	printModuleScript(relPath, projectName, bins,
		version, currentTag, prevTag, repoPath, headSHA,
		releaseNotes, isPreRelease, needsNewTag, isDirty)
}

// ── Version computation ────────────────────────────────────────────────────

// computeVersion returns (version, fullTag, isPreRelease, needsNewTag).
//
// Examples:
//
//	At "cmd/tcpfwd/v1.1.0", clean   → ("1.1.0",           "cmd/tcpfwd/v1.1.0",           false, false)
//	3 commits past v1.1.0, clean    → ("1.1.1-pre3",       "cmd/tcpfwd/v1.1.1-pre3",       true,  true)
//	dirty, 0 new commits            → ("1.1.1-pre1.dirty", "cmd/tcpfwd/v1.1.1-pre1.dirty", true,  false)
func computeVersion(prefix, latestTag string, commitCount int, isDirty bool) (version, currentTag string, isPreRelease, needsNewTag bool) {
	if latestTag == "" {
		return "0.1.0", prefix + "/v0.1.0", false, true
	}

	tagSemver := strings.TrimPrefix(latestTag, prefix+"/")

	if commitCount == 0 && !isDirty {
		version = strings.TrimPrefix(tagSemver, "v")
		return version, latestTag, false, false
	}

	base := strings.TrimPrefix(tagSemver, "v")
	if idx := strings.Index(base, "-"); idx >= 0 {
		base = base[:idx]
	}
	dp := strings.SplitN(base, ".", 3)
	patch, _ := strconv.Atoi(dp[2])
	patch++

	preN := commitCount
	if preN == 0 {
		preN = 1
	}
	preLabel := fmt.Sprintf("pre%d", preN)
	if isDirty {
		preLabel += ".dirty"
	}

	version = fmt.Sprintf("%s.%s.%d-%s", dp[0], dp[1], patch, preLabel)
	currentTag = prefix + "/v" + version
	needsNewTag = !isDirty
	return version, currentTag, true, needsNewTag
}

// ── Semver helpers ─────────────────────────────────────────────────────────

func semverLess(a, b string) bool {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	var aPre, bPre string
	if idx := strings.Index(a, "-"); idx >= 0 {
		aPre, a = a[idx+1:], a[:idx]
	}
	if idx := strings.Index(b, "-"); idx >= 0 {
		bPre, b = b[idx+1:], b[:idx]
	}

	aP, bP := semverInts(a), semverInts(b)
	for i := range aP {
		if aP[i] != bP[i] {
			return aP[i] < bP[i]
		}
	}
	if aPre == bPre {
		return false
	}
	if aPre == "" {
		return false
	}
	if bPre == "" {
		return true
	}
	return preNum(aPre) < preNum(bPre)
}

func semverInts(v string) [3]int {
	p := strings.SplitN(v, ".", 3)
	var r [3]int
	for i := 0; i < len(p) && i < 3; i++ {
		r[i], _ = strconv.Atoi(p[i])
	}
	return r
}

func preNum(s string) int {
	s = strings.TrimPrefix(s, "pre")
	if idx := strings.IndexAny(s, ".+"); idx >= 0 {
		s = s[:idx]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}

// ── goreleaser YAML generation ─────────────────────────────────────────────

// goreleaserYAML returns .goreleaser.yaml content for one or more binaries.
//
// Key decisions:
//   - {{.Env.VERSION}} is used everywhere so the prefixed monorepo tag never
//     appears in artifact filenames.
//   - Each binary gets its own build (id) and archive (ids) for separate tarballs.
//   - release.disable: true — we use `gh release` instead (goreleaser Pro
//     would be needed to publish via a prefixed tag).
func goreleaserYAML(projectName string, bins []binary) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s) }
	wf := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# yaml-language-server: $schema=https://goreleaser.com/static/schema.json\n")
	w("# vim: set ts=2 sw=2 tw=0 fo=cnqoj\n")
	w("# Generated by monorel (github.com/therootcompany/golib/tools/monorel)\n")
	w("\nversion: 2\n")
	w("\nbefore:\n  hooks:\n    - go mod tidy\n    - go generate ./...\n")

	w("\nbuilds:\n")
	for _, bin := range bins {
		wf("  - id: %s\n", bin.name)
		wf("    binary: %s\n", bin.name)
		if bin.mainPath != "." {
			wf("    main: %s\n", bin.mainPath)
		}
		w("    env:\n      - CGO_ENABLED=0\n")
		w("    ldflags:\n")
		w("      - -s -w" +
			" -X main.version={{.Env.VERSION}}" +
			" -X main.commit={{.Commit}}" +
			" -X main.date={{.Date}}" +
			" -X main.builtBy=goreleaser\n")
		w("    goos:\n      - linux\n      - windows\n      - darwin\n")
	}

	w("\narchives:\n")
	for _, bin := range bins {
		wf("  - id: %s\n", bin.name)
		wf("    ids: [%s]\n", bin.name)
		w("    formats: [tar.gz, tar.zst]\n")
		w("    # name_template uses VERSION env var so the prefixed monorepo tag\n")
		w("    # doesn't appear in archive filenames.\n")
		w("    name_template: >-\n")
		wf("      %s_{{ .Env.VERSION }}_\n", bin.name)
		w("      {{- title .Os }}_\n")
		w("      {{- if eq .Arch \"amd64\" }}x86_64\n")
		w("      {{- else if eq .Arch \"386\" }}i386\n")
		w("      {{- else }}{{ .Arch }}{{ end }}\n")
		w("      {{- if .Arm }}v{{ .Arm }}{{ end }}\n")
		w("    format_overrides:\n")
		w("      - goos: windows\n")
		w("        formats: [zip, tar.gz]\n")
	}

	w("\nchangelog:\n  sort: asc\n  filters:\n    exclude:\n")
	w("      - \"^docs:\"\n      - \"^test:\"\n")

	w("\nchecksum:\n")
	wf("  name_template: \"%s_{{ .Env.VERSION }}_checksums.txt\"\n", projectName)
	w("  disable: false\n")

	w("\n# Release is disabled: goreleaser Pro is required to publish with a\n")
	w("# prefixed monorepo tag. We use 'gh release' instead (see release script).\n")
	w("release:\n  disable: true\n")

	return b.String()
}

// ── Release script generation ──────────────────────────────────────────────

// printModuleScript emits one module's release steps to stdout.
//
// All paths in the generated script are relative to relPath so that the
// script can be run from the directory where monorel was invoked:
//   - git commands use relPath/ as the pathspec (instead of ./)
//   - goreleaser is wrapped in ( cd "relPath" && goreleaser ... ) when needed
//   - artifact globs use relPath/dist/ instead of ./dist/
//
// When relPath is "." (monorel was run from the module root), ./ paths are
// used and no cd is required for any command.
func printModuleScript(
	relPath string,
	projectName string, bins []binary,
	version, currentTag, prevTag, repoPath, headSHA string,
	releaseNotes string,
	isPreRelease, needsNewTag, isDirty bool,
) {
	line := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	blank := func() { fmt.Println() }
	section := func(title string) {
		blank()
		fmt.Printf("# ── %s ", title)
		fmt.Println(strings.Repeat("─", max(0, 52-len(title))))
	}

	// Paths used in the generated script, all relative to the invoking CWD.
	var distDir string
	if relPath == "." {
		distDir = "./dist"
	} else {
		distDir = relPath + "/dist"
	}

	// Safe bash variable name for the release-notes capture (no export needed).
	notesVar := strings.ReplaceAll(projectName, "-", "_") + "_release_notes"

	// Module header.
	blank()
	rule := strings.Repeat("═", 54)
	fmt.Printf("# %s\n", rule)
	modLabel := relPath
	if modLabel == "." {
		modLabel = projectName + " (current directory)"
	}
	fmt.Printf("# Module: %s\n", modLabel)
	fmt.Printf("# %s\n", rule)

	if isDirty {
		blank()
		line("# ⚠  WARNING: working tree has uncommitted changes.")
		line("# Commit or stash them before releasing for a reproducible build.")
		line("# A .dirty suffix has been appended to the version below.")
	}

	blank()
	if len(bins) == 1 {
		line("# %-16s %s", "Binary:", bins[0].name)
	} else {
		names := make([]string, len(bins))
		for i, bin := range bins {
			names[i] = bin.name
		}
		line("# %-16s %s", "Binaries:", strings.Join(names, ", "))
	}
	line("# %-16s %s", "VERSION:", version)
	line("# %-16s %s", "Current tag:", currentTag)
	if prevTag != "" {
		line("# %-16s %s", "Previous tag:", prevTag)
	} else {
		line("# %-16s (none — first release)", "Previous tag:")
	}
	line("# %-16s %s", "Repo:", repoPath)

	section("Step 1: Environment variables")
	line("export VERSION=%q", version)

	if needsNewTag {
		section("Step 2: Create git tag")
		line("git tag %q", currentTag)
		line("# To undo:  git tag -d %q", currentTag)
	}

	section("Step 3: Push commits and tags to remote")
	line("git push && git push --tags")

	section("Step 4: Build with goreleaser")
	line("# release.disable=true in .goreleaser.yaml; goreleaser only builds.")
	if relPath == "." {
		line("goreleaser release --clean --skip=validate,announce")
	} else {
		line("(")
		line("  cd %q", relPath)
		line("  goreleaser release --clean --skip=validate,announce")
		line(")")
	}

	section("Step 5: Release notes")
	line("%s=%s", notesVar, shellSingleQuote(releaseNotes))

	section("Step 6: Create draft GitHub release")
	tagVersion := currentTag[strings.LastIndex(currentTag, "/")+1:]
	title := projectName + " " + tagVersion
	line("gh release create %q \\", currentTag)
	line("  --title %q \\", title)
	line("  --notes \"${%s}\" \\", notesVar)
	if isPreRelease {
		line("  --prerelease \\")
	}
	line("  --draft \\")
	line("  --target %q", headSHA)

	section("Step 7: Upload artifacts")
	line("gh release upload %q \\", currentTag)
	for _, bin := range bins {
		line("  %s/%s_*.tar.gz \\", distDir, bin.name)
		line("  %s/%s_*.tar.zst \\", distDir, bin.name)
		line("  %s/%s_*.zip \\", distDir, bin.name)
	}
	line("  \"%s/%s_%s_checksums.txt\" \\", distDir, projectName, version)
	line("  --clobber")

	section("Step 8: Publish release (remove draft)")
	line("gh release edit %q --draft=false", currentTag)

	blank()
}

// ── Helpers ────────────────────────────────────────────────────────────────

// shellSingleQuote wraps s in bash single quotes, escaping any literal single
// quotes inside s as '\''.  For example: it's → 'it'\''s'.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func normalizeGitURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimSuffix(rawURL, ".git")
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rawURL = rawURL[idx+3:]
		if idx2 := strings.Index(rawURL, "@"); idx2 >= 0 {
			rawURL = rawURL[idx2+1:]
		}
		return rawURL
	}
	if idx := strings.Index(rawURL, "@"); idx >= 0 {
		rawURL = rawURL[idx+1:]
	}
	return strings.ReplaceAll(rawURL, ":", "/")
}

func mustRunIn(dir, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		fatalf("running %q %v in %s: %v", name, args, dir, err)
	}
	return strings.TrimSpace(string(out))
}

func runIn(dir, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

// runPrintIn runs name with args in dir, forwarding its stdout and stderr to
// the current process's stderr so that build-tool output (go mod tidy, etc.)
// is visible in the terminal.
func runPrintIn(dir, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s %v in %s: %v\n", name, args, dir, err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "monorel: error: "+format+"\n", args...)
	os.Exit(1)
}
