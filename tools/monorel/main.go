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
	"bufio"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	name         = "monorel"
	desc         = "Monorepo Release Tool"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)"
	licenseType  = "MPL-2.0"
)

// replaced by goreleaser / ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "%s\n", desc)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

// stopMarkers are the directory entries that mark the top of a git repository.
// findModuleRoot stops walking upward when it encounters one of these entries
// as a DIRECTORY, so it never crosses into a parent repository.
// A .git FILE (not a directory) means we are inside a submodule — the real
// repository root is further up, so we keep looking.
// Adjust this slice if you ever need to search across repository boundaries.
var stopMarkers = []string{".git"}

// defaultGoos is the conservative CGO_ENABLED=0 goos list used in generated
// .goreleaser.yaml files.  Use --almost-all to widen the net.
// Platforms requiring CGO or special toolchains (ios, android) are handled
// separately via the --ios and --android-ndk flags.
var defaultGoos = []string{
	"darwin", "freebsd", "js", "linux",
	"netbsd", "openbsd", "wasip1", "windows",
}

// almostAllGoos extends defaultGoos with less-commonly-targeted CGO_ENABLED=0 platforms.
var almostAllGoos = []string{
	"aix", "darwin", "dragonfly", "freebsd", "illumos",
	"js", "linux", "netbsd", "openbsd", "plan9",
	"solaris", "wasip1", "windows",
}

// defaultGoarch is the conservative architecture list for generated builds.
var defaultGoarch = []string{
	"amd64", "arm", "arm64", "mips64le", "mipsle", "ppc64le", "riscv64", "wasm",
}

// almostAllGoarch extends defaultGoarch with less-common architectures.
var almostAllGoarch = []string{
	"386",
	"amd64", "arm", "arm64",
	"loong64", "mips", "mips64", "mips64le", "mipsle",
	"ppc64", "ppc64le", "riscv64", "s390x", "wasm",
}

// defaultGoarm is the ARM sub-architecture list (ARMv6 and ARMv7).
// Included whenever "arm" appears in the goarch list.
var defaultGoarm = []string{"6", "7"}

// defaultGoamd64 is the amd64 micro-architecture level list used with --almost-all.
var defaultGoamd64 = []string{"v1", "v2"}

// almostAllGoamd64 is the amd64 micro-architecture level list used with --almost-all.
var almostAllGoamd64 = []string{"v1", "v2", "v3", "v4"}

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

// releaseStep is one interactive action in the release flow.
type releaseStep struct {
	title   string   // section heading, e.g. "Create git tag"
	prompt  string   // interactive prompt text, e.g. "create tag auth/csvauth/v1.2.5"
	display []string // command lines shown to the user before the prompt
	skip    bool     // pre-determined to be skipped (e.g. tag already exists)
	run     func() error
}

// buildOptions controls which platforms and features are included in the
// generated .goreleaser.yaml.
type buildOptions struct {
	almostAll  bool // include esoteric goos/goarch targets and goamd64 sub-versions
	ios        bool // generate active iOS build (requires CGO_ENABLED=1 + Xcode)
	androidNDK bool // generate active Android NDK build (requires CGO_ENABLED=1 + NDK)
}

// ── Entry point ────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// Handle version/help before subcommand dispatch.
	switch os.Args[1] {
	case "-V", "version", "-version", "--version":
		printVersion(os.Stdout)
		os.Exit(0)
	case "help", "-help", "--help":
		printVersion(os.Stdout)
		fmt.Fprintln(os.Stdout, "")
		usage()
		os.Exit(0)
	case "release":
		runRelease(os.Args[2:])
	case "bump":
		runBump(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "monorel: unknown subcommand %q\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Run 'monorel help' for usage.")
		os.Exit(2)
	}
}

func usage() {
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
	var showVersion bool
	var recursive, all, dryRun, yes, force, draft, prerelease bool
	var almostAll, ios, androidNDK bool
	fs.BoolVar(&showVersion, "version", false, "show version and exit")
	fs.BoolVar(&recursive, "recursive", false, "find all main packages recursively under each path")
	fs.BoolVar(&all, "A", false, "include dot/underscore-prefixed directories; warn rather than error on failures")
	fs.BoolVar(&dryRun, "dry-run", false, "show each step without running it")
	fs.BoolVar(&yes, "yes", false, "run all steps without prompting")
	fs.BoolVar(&force, "force", false, "overwrite .goreleaser.yaml without prompting even if it has been modified")
	fs.BoolVar(&draft, "draft", false, "keep the GitHub release in draft state after uploading (default: publish)")
	fs.BoolVar(&prerelease, "prerelease", false, "keep the GitHub release marked as pre-release even for clean tags (default: promote clean tags to stable)")
	fs.BoolVar(&almostAll, "almost-all", false, "widen build matrix to include esoteric goos/goarch targets and goamd64 v1-v4")
	fs.BoolVar(&ios, "ios", false, "add an iOS build entry to the generated .goreleaser.yaml (requires CGO_ENABLED=1 and Xcode)")
	fs.BoolVar(&androidNDK, "android-ndk", false, "add an Android NDK build entry to the generated .goreleaser.yaml (requires CGO_ENABLED=1 and NDK)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: monorel release [options] <binary-path>...")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Updates .goreleaser.yaml next to each module's go.mod and runs the")
		fmt.Fprintln(os.Stderr, "release steps interactively (prompt per step by default).")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  monorel release .                          # single binary at module root")
		fmt.Fprintln(os.Stderr, "  monorel release ./cmd/foo ./cmd/bar        # multiple binaries, same module")
		fmt.Fprintln(os.Stderr, "  monorel release auth/csvauth/cmd/csvauth   # from repo root")
		fmt.Fprintln(os.Stderr, "  monorel release -recursive .               # all modules under current directory")
		fmt.Fprintln(os.Stderr, "")
		fs.PrintDefaults()
	}
	if len(args) > 0 && args[0] == "-V" {
		printVersion(os.Stdout)
		os.Exit(0)
	}
	_ = fs.Parse(args)
	if showVersion {
		printVersion(os.Stdout)
		os.Exit(0)
	}
	printVersion(os.Stderr)
	fmt.Fprintln(os.Stderr, "")
	binPaths := fs.Args()
	if len(binPaths) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	opts := buildOptions{almostAll: almostAll, ios: ios, androidNDK: androidNDK}

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
		relPath, _ := filepath.Rel(cwd, group.root)
		relPath = filepath.ToSlash(relPath)
		processModule(group, relPath, dryRun, yes, force, draft, prerelease, opts)
	}
}

// ── Subcommand: bump ───────────────────────────────────────────────────────

func runBump(args []string) {
	fs := flag.NewFlagSet("monorel bump", flag.ExitOnError)
	var showVersion bool
	var component string
	var recursive, all, force, dryRun bool
	fs.BoolVar(&showVersion, "version", false, "show version and exit")
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
	if len(args) > 0 && args[0] == "-V" {
		printVersion(os.Stdout)
		os.Exit(0)
	}
	_ = fs.Parse(args)
	if showVersion {
		printVersion(os.Stdout)
		os.Exit(0)
	}
	printVersion(os.Stderr)
	fmt.Fprintln(os.Stderr, "")

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

	var groups []*moduleGroup
	if recursive {
		// Recursive: find every main package under the given paths, then group
		// by module.  This implicitly discovers all modules that contain at
		// least one binary, which is the common case.
		allPaths, err := expandPaths(binPaths, true, all)
		if err != nil {
			fatalf("%v", err)
		}
		if len(allPaths) == 0 {
			fatalf("no main packages found under the given paths")
		}
		groups, err = groupByModule(allPaths)
		if err != nil {
			fatalf("%v", err)
		}
	} else {
		// Non-recursive: bump operates on modules, not binaries, so any path
		// inside a module (or a module root itself) is accepted — no package
		// main required.
		var err error
		groups, err = groupModuleRoots(binPaths)
		if err != nil {
			fatalf("%v", err)
		}
		if len(groups) == 0 {
			fatalf("no modules found under the given paths")
		}
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
	var showVersion bool
	var recursive, all, dryRun, cmd bool
	var almostAll, ios, androidNDK bool
	fs.BoolVar(&showVersion, "version", false, "show version and exit")
	fs.BoolVar(&recursive, "recursive", false, "find all main packages recursively under each path")
	fs.BoolVar(&all, "A", false, "include dot/underscore-prefixed directories; warn rather than error on failures")
	fs.BoolVar(&dryRun, "dry-run", false, "print what would happen without writing files, creating commits, or tags")
	fs.BoolVar(&cmd, "cmd", false, "for each cmd/ child with package main, run go mod init+tidy (suggests a commit at the end)")
	fs.BoolVar(&almostAll, "almost-all", false, "widen build matrix to include esoteric goos/goarch targets and goamd64 v1-v4")
	fs.BoolVar(&ios, "ios", false, "add an iOS build entry to the generated .goreleaser.yaml (requires CGO_ENABLED=1 and Xcode)")
	fs.BoolVar(&androidNDK, "android-ndk", false, "add an Android NDK build entry to the generated .goreleaser.yaml (requires CGO_ENABLED=1 and NDK)")
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
	if len(args) > 0 && args[0] == "-V" {
		printVersion(os.Stdout)
		os.Exit(0)
	}
	_ = fs.Parse(args)
	if showVersion {
		printVersion(os.Stdout)
		os.Exit(0)
	}
	printVersion(os.Stderr)
	fmt.Fprintln(os.Stderr, "")
	binPaths := fs.Args()
	if len(binPaths) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	opts := buildOptions{almostAll: almostAll, ios: ios, androidNDK: androidNDK}

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
		initModuleGroup(group, dryRun, opts)
	}
}

// initModuleGroup writes .goreleaser.yaml, commits it (if changed), and
// creates an initial version tag (bump patch) for one module group.
// When dryRun is true no files are written and no git mutations are made.
func initModuleGroup(group *moduleGroup, dryRun bool, opts buildOptions) {
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

	// 1. Write .goreleaser.yaml only when the content has changed.
	yamlContent := goreleaserYAML(projectName, bins, opts)
	yamlPath := filepath.Join(modRoot, ".goreleaser.yaml")
	existing, readErr := os.ReadFile(yamlPath)
	isNewFile := readErr != nil
	isChanged := isNewFile || !yamlLooksCorrect(string(existing), bins)
	if dryRun {
		if isChanged {
			fmt.Fprintf(os.Stderr, "[dry-run] would write %s\n", yamlPath)
		} else {
			fmt.Fprintf(os.Stderr, "found config %s with monorepo support\n", cwdRelPath(yamlPath))
		}
	} else if isChanged {
		if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
			fatalf("writing %s: %v", yamlPath, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", yamlPath)

		// 2. Auto-commit — only when the file was newly created.
		// Updates to an existing file require manual review and commit.
		if isNewFile {
			mustRunIn(modRoot, "git", "add", ".goreleaser.yaml")
			if status := runIn(modRoot, "git", "status", "--porcelain", "--", ".goreleaser.yaml"); status != "" {
				commitMsg := "chore(" + prefix + "): add .goreleaser.yaml"
				mustRunIn(modRoot, "git", "commit", "-m", commitMsg)
				fmt.Fprintf(os.Stderr, "committed: %s\n", commitMsg)
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "found config %s with monorepo support\n", cwdRelPath(yamlPath))
	}

	// 3. Bump patch — but only when the goreleaser.yaml commit is the sole new
	// commit since the last stable tag (the common "first setup" scenario).
	// If other commits are already waiting to be tagged the user should choose
	// the right semver component with an explicit 'monorel bump'.
	// Auto-bump only applies when the yaml was newly created.
	shouldBump := isNewFile
	if !dryRun && isNewFile {
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
//
// For the bump subcommand (which operates on modules, not binaries) use
// groupModuleRoots instead — it accepts any path inside a module without
// requiring package main.
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
			skip := slices.Contains(stopMarkers, name)
			if skip {
				continue
			}
			// Skip dot- and underscore-prefixed directories unless -A is set.
			if !all && len(name) > 0 && (name[0] == '.' || name[0] == '_') {
				continue
			}
			child := filepath.Join(dir, name)
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
		if str, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(str)
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
			isStop := slices.Contains(stopMarkers, name)
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
	return fmt.Errorf("%s is package %q, not a main package\n\thint: use --recursive to search for main packages inside this directory", dir, strings.Join(names, ", "))
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

// groupModuleRoots resolves each path to its nearest module root (the
// directory containing go.mod) and returns one moduleGroup per unique root,
// in first-occurrence order.  Unlike groupByModule it does not require paths
// to contain package main — any path inside a module (or a module root
// itself) is accepted.  Used by the bump subcommand, which operates on
// modules rather than binaries.
func groupModuleRoots(paths []string) ([]*moduleGroup, error) {
	groupMap := make(map[string]*moduleGroup)
	var order []string

	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", p, err)
		}
		// If the path is a file, start from its parent directory.
		if info, err := os.Stat(abs); err == nil && !info.IsDir() {
			abs = filepath.Dir(abs)
		}
		modRoot, err := findModuleRoot(abs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if _, ok := groupMap[modRoot]; !ok {
			groupMap[modRoot] = &moduleGroup{root: modRoot}
			order = append(order, modRoot)
		}
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
func processModule(group *moduleGroup, relPath string, dryRun, yes, force, draft, prerelease bool, opts buildOptions) {
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

	// 1. Write .goreleaser.yaml when necessary.
	// For release, the file is considered compatible if it has no stock
	// {{ .ProjectName }} template and at least one binary uses the VERSION env
	// var — local edits that add extra binaries etc. are preserved.
	// Auto-commit and auto-tag only apply when the file is brand new.
	yamlContent := goreleaserYAML(projectName, bins, opts)
	yamlPath := filepath.Join(modRoot, ".goreleaser.yaml")
	existing, readErr := os.ReadFile(yamlPath)
	isNewFile := readErr != nil
	isChanged := isNewFile || !yamlIsCompatible(string(existing), bins)
	if !isNewFile && isChanged {
		// Warn if a stock {{ .ProjectName }} template is in use.
		hasProjectName := strings.Contains(string(existing), "{{ .ProjectName }}") ||
			strings.Contains(string(existing), "{{.ProjectName}}")
		gitInfo, gitErr := os.Stat(filepath.Join(modRoot, ".git"))
		atGitRoot := gitErr == nil && gitInfo.IsDir()
		if hasProjectName && !atGitRoot {
			fmt.Fprintf(os.Stderr, "warning: %s: contains {{ .ProjectName }} but module is a monorepo subdirectory;\n", yamlPath)
			fmt.Fprintf(os.Stderr, "  replacing stock goreleaser config with monorel-generated config.\n")
		}
		// Prompt before overwriting a modified file. --yes does not apply;
		// use --force to skip the prompt. If stdin is not a terminal and
		// --force is not set, refuse rather than silently clobber.
		if !force {
			fi, statErr := os.Stdin.Stat()
			isTTY := statErr == nil && fi.Mode()&os.ModeCharDevice != 0
			if !isTTY {
				fatalf("%s needs updating but stdin is not a terminal; use --force to overwrite", cwdRelPath(yamlPath))
			}
			fmt.Fprintf(os.Stderr, "%s needs updating; overwrite? [Y/n] ", cwdRelPath(yamlPath))
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			if resp := strings.ToLower(strings.TrimSpace(line)); resp == "n" || resp == "no" {
				fmt.Fprintf(os.Stderr, "skipped %s\n", cwdRelPath(yamlPath))
				return
			}
		}
	}
	if isChanged {
		if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
			fatalf("writing %s: %v", yamlPath, err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", yamlPath)
	} else {
		fmt.Fprintf(os.Stderr, "found config %s with monorepo support\n", cwdRelPath(yamlPath))
	}

	// 2. Auto-commit + auto-tag — only when the file was newly created.
	if isNewFile {
		mustRunIn(modRoot, "git", "add", ".goreleaser.yaml")
		if status := runIn(modRoot, "git", "status", "--porcelain", "--", ".goreleaser.yaml"); status != "" {
			commitMsg := "chore(" + prefix + "): add .goreleaser.yaml"
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

	printModuleHeader(relPath, projectName, bins,
		version, currentTag, prevTag, repoPath, isDirty)

	steps := buildModuleSteps(
		modRoot, relPath, projectName, bins,
		version, currentTag, repoPath, headSHA,
		releaseNotes, needsNewTag, isPreRelease, draft, prerelease,
	)
	if err := runSteps(steps, dryRun, yes); err != nil {
		fmt.Fprintf(os.Stderr, "monorel: %v\n", err)
	}
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
func goreleaserYAML(projectName string, bins []binary, opts buildOptions) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s) }
	wf := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# This file is generated by monorel (github.com/therootcompany/golib/tools/monorel).\n")
	w("# Make sure to check the documentation at https://goreleaser.com\n")
	w("\n# The lines below are called `modelines`. See `:help modeline`\n")
	w("# Feel free to remove those if you don't want/need to use them.\n")
	w("# yaml-language-server: $schema=https://goreleaser.com/static/schema.json\n")
	w("# vim: set ts=2 sw=2 tw=0 fo=cnqoj\n")
	w("\nversion: 2\n")
	w("\nbefore:\n  hooks:\n    - go mod tidy\n")
	w("    # you may remove this if you don't need go generate\n")
	w("    - go generate ./...\n")

	// Select goos/goarch lists based on options.
	goos := defaultGoos
	goarch := defaultGoarch
	goamd64 := defaultGoamd64
	if opts.almostAll {
		goos = almostAllGoos
		goarch = almostAllGoarch
		goamd64 = almostAllGoamd64
	}

	// When multiple binaries share a module, define the common build options
	// once with a YAML anchor on the first build and merge them into the rest.
	// Single-binary modules use plain fields (no anchor overhead).
	multibin := len(bins) > 1

	// writeBuildDefaults emits env, ldflags, goos, goarch, goarm, and (if
	// --almost-all) goamd64 at the given indent level (2 or 4 spaces of extra
	// indent relative to the builds list item).
	writeBuildDefaults := func(indent string) {
		wf("%senv:\n%s  - CGO_ENABLED=0\n", indent, indent)
		wf("%sldflags:\n", indent)
		wf("%s  - -s -w"+
			" -X main.version={{.Env.VERSION}}"+
			" -X main.commit={{.Commit}}"+
			" -X main.date={{.Date}}"+
			" -X main.builtBy=goreleaser\n", indent)
		wf("%sgoos:\n", indent)
		for _, g := range goos {
			wf("%s  - %s\n", indent, g)
		}
		wf("%sgoarch:\n", indent)
		for _, a := range goarch {
			wf("%s  - %s\n", indent, a)
		}
		wf("%sgoarm:\n", indent)
		for _, v := range defaultGoarm {
			wf("%s  - %s\n", indent, v)
		}
		wf("%sgoamd64:\n", indent)
		for _, v := range goamd64 {
			wf("%s  - %s\n", indent, v)
		}
	}

	w("\nbuilds:\n")
	for i, bin := range bins {
		wf("  - id: %s\n", bin.name)
		wf("    binary: %s\n", bin.name)
		if bin.mainPath != "." {
			wf("    main: %s\n", bin.mainPath)
		}

		// Shared build options — defined once via anchor, merged into the rest.
		switch {
		case !multibin:
			// Single binary: plain fields.
			writeBuildDefaults("    ")
		case i == 0:
			// First of multiple binaries: define the anchor, content indented
			// one extra level so it is nested under the merge key.
			w("    <<: &build_defaults\n")
			writeBuildDefaults("      ")
		default:
			// Subsequent binaries: reference the anchor.
			w("    <<: *build_defaults\n")
		}

		// iOS build — only when --ios is set.
		if opts.ios {
			w("  # iOS build — requires CGO_ENABLED=1 and the Xcode toolchain.\n")
			wf("  - id: %s-ios\n", bin.name)
			wf("    binary: %s\n", bin.name)
			if bin.mainPath != "." {
				wf("    main: %s\n", bin.mainPath)
			}
			w("    env:\n      - CGO_ENABLED=1\n")
			w("    goos:\n      - ios\n")
			w("    goarch:\n      - arm64\n")
		}

		// Android NDK build — only when --android-ndk is set.
		if opts.androidNDK {
			w("  # Android NDK build — requires CGO_ENABLED=1 and the Android NDK.\n")
			wf("  - id: %s-android\n", bin.name)
			wf("    binary: %s\n", bin.name)
			if bin.mainPath != "." {
				wf("    main: %s\n", bin.mainPath)
			}
			w("    env:\n      - CGO_ENABLED=1\n")
			w("    goos:\n      - android\n")
			w("    goarch:\n      - arm64\n")
		}
	}

	w("\narchives:\n")
	for _, bin := range bins {
		wf("  - id: %s\n", bin.name)
		wf("    ids: [%s]\n", bin.name)
		w("    formats: [tar.gz, tar.zst]\n")
		w("    # this name template makes the OS and Arch compatible with the results of `uname`.\n")
		w("    # it uses the VERSION env var so the prefixed monorepo tag doesn't appear in archive filenames.\n")
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

// yamlIsCompatible is the looser check used by the release subcommand.
// It returns true when the file has no stock {{ .ProjectName }} template and
// at least one binary already uses the VERSION env var in its archive name.
// This preserves hand-edited files that add extra binaries or tweak settings,
// where yamlLooksCorrect would demand every declared binary be present.
func yamlIsCompatible(content string, bins []binary) bool {
	if strings.Contains(content, "{{ .ProjectName }}") ||
		strings.Contains(content, "{{.ProjectName}}") {
		return false
	}
	for _, bin := range bins {
		if strings.Contains(content, bin.name+"_{{ .Env.VERSION }}_") {
			return true
		}
	}
	return false
}

// yamlLooksCorrect returns true when content appears to be a valid monorel-
// generated (or compatible) .goreleaser.yaml for the given binaries:
//
//   - `-X main.version={{.Env.VERSION}}` is present (version injection)
//   - `<binname>_{{ .Env.VERSION }}_` is present for every binary (archive naming)
//   - `{{ .ProjectName }}` / `{{.ProjectName}}` are absent (stock goreleaser template)
//
// When these hold the file is left untouched so that compatible local edits
// (e.g. adding extra build targets or tweaking flags) are preserved.
func yamlLooksCorrect(content string, bins []binary) bool {
	if !strings.Contains(content, "-X main.version={{.Env.VERSION}}") {
		return false
	}
	for _, bin := range bins {
		if !strings.Contains(content, bin.name+"_{{ .Env.VERSION }}_") {
			return false
		}
	}
	if strings.Contains(content, "{{ .ProjectName }}") ||
		strings.Contains(content, "{{.ProjectName}}") {
		return false
	}
	return true
}

// ── Release step runner ────────────────────────────────────────────────────

// printModuleHeader writes the informational header block for one module to
// stdout.  It is always shown regardless of dry-run / yes mode.
func printModuleHeader(
	relPath, projectName string, bins []binary,
	version, currentTag, prevTag, repoPath string,
	isDirty bool,
) {
	line := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	blank := func() { fmt.Println() }

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
	blank()
}

// buildModuleSteps constructs the ordered list of release steps for one module.
func buildModuleSteps(
	modRoot, relPath, projectName string, bins []binary,
	version, currentTag, repoPath, headSHA string,
	releaseNotes string,
	needsNewTag, isPreRelease, draft, prerelease bool,
) []releaseStep {
	distDir := filepath.Join(modRoot, "dist")
	var distRelDir string
	if relPath == "." {
		distRelDir = "./dist"
	} else {
		distRelDir = relPath + "/dist"
	}

	tagVersion := currentTag[strings.LastIndex(currentTag, "/")+1:]
	title := projectName + " " + tagVersion

	var steps []releaseStep

	// Step: Create git tag (skipped when tag already exists).
	steps = append(steps, releaseStep{
		title:  "Create git tag",
		prompt: "create tag " + currentTag,
		display: []string{
			fmt.Sprintf("git tag %q", currentTag),
			fmt.Sprintf("# To undo: git tag -d %q", currentTag),
		},
		skip: !needsNewTag,
		run: func() error {
			return execIn(modRoot, "git", "tag", currentTag)
		},
	})

	// Step: Push commits and tags.
	steps = append(steps, releaseStep{
		title:   "Push commits and tags to remote",
		prompt:  "push commits and tags to remote",
		display: []string{"git push && git push --tags"},
		run: func() error {
			if err := execIn(modRoot, "git", "push"); err != nil {
				return err
			}
			return execIn(modRoot, "git", "push", "--tags")
		},
	})

	// Step: Build with goreleaser.
	var gorelDisplay []string
	if relPath == "." {
		gorelDisplay = []string{"goreleaser release --clean --skip=validate,announce"}
	} else {
		gorelDisplay = []string{
			"(",
			fmt.Sprintf("  cd %q", relPath),
			"  goreleaser release --clean --skip=validate,announce",
			")",
		}
	}
	steps = append(steps, releaseStep{
		title:   "Build with goreleaser",
		prompt:  "run goreleaser to build assets",
		display: gorelDisplay,
		run: func() error {
			return execInEnv(modRoot, []string{"VERSION=" + version},
				"goreleaser", "release", "--clean", "--skip=validate,announce")
		},
	})

	// Step: Create GitHub release — always as draft+prerelease so artifacts
	// can be uploaded before visibility is determined.
	ghCreateDisplay := []string{
		fmt.Sprintf("gh release create %q \\", currentTag),
		fmt.Sprintf("  --title %q \\", title),
		fmt.Sprintf("  --notes %s \\", shellSingleQuote(releaseNotes)),
		"  --draft \\",
		"  --prerelease \\",
		fmt.Sprintf("  --target %q", headSHA),
	}
	steps = append(steps, releaseStep{
		title:   "Create GitHub release",
		prompt:  fmt.Sprintf("create GitHub release %s (draft, pre-release)", currentTag),
		display: ghCreateDisplay,
		run: func() error {
			return execIn(modRoot, "gh", "release", "create", currentTag,
				"--title", title,
				"--notes", releaseNotes,
				"--draft",
				"--prerelease",
				"--target", headSHA,
			)
		},
	})

	// Step: Upload artifacts (globs expanded at run time after goreleaser).
	var uploadDisplay []string
	uploadDisplay = append(uploadDisplay, fmt.Sprintf("gh release upload %q \\", currentTag))
	for _, bin := range bins {
		uploadDisplay = append(uploadDisplay,
			fmt.Sprintf("  %s/%s_*.tar.gz \\", distRelDir, bin.name),
			fmt.Sprintf("  %s/%s_*.tar.zst \\", distRelDir, bin.name),
			fmt.Sprintf("  %s/%s_*.zip \\", distRelDir, bin.name),
		)
	}
	uploadDisplay = append(uploadDisplay,
		fmt.Sprintf("  %q \\", distRelDir+"/"+projectName+"_"+version+"_checksums.txt"),
		"  --clobber",
	)
	steps = append(steps, releaseStep{
		title:   "Upload artifacts",
		prompt:  fmt.Sprintf("upload artifacts for %s", currentTag),
		display: uploadDisplay,
		run: func() error {
			ghArgs := []string{"release", "upload", currentTag}
			for _, bin := range bins {
				for _, pat := range []string{
					bin.name + "_*.tar.gz",
					bin.name + "_*.tar.zst",
					bin.name + "_*.zip",
				} {
					matches, _ := filepath.Glob(filepath.Join(distDir, pat))
					ghArgs = append(ghArgs, matches...)
				}
			}
			checksum := filepath.Join(distDir, projectName+"_"+version+"_checksums.txt")
			ghArgs = append(ghArgs, checksum, "--clobber")
			return execIn(modRoot, "gh", ghArgs...)
		},
	})

	// Step: Finalise release visibility.
	// Always created as draft+prerelease; this step removes whichever flags
	// should not remain after uploading:
	//   --draft=false     unless --draft was given (keep as draft)
	//   --prerelease=false unless --prerelease was given OR the tag itself is a
	//                     pre-release (has a suffix like -pre3 or .dirty)
	needRemoveDraft := !draft
	needRemovePrerelease := !prerelease && !isPreRelease
	if needRemoveDraft || needRemovePrerelease {
		var editDisplay []string
		var editArgs []string
		editDisplay = append(editDisplay, fmt.Sprintf("gh release edit %q \\", currentTag))
		if needRemoveDraft {
			editDisplay = append(editDisplay, "  --draft=false \\")
			editArgs = append(editArgs, "--draft=false")
		}
		if needRemovePrerelease {
			editDisplay = append(editDisplay, "  --prerelease=false")
			editArgs = append(editArgs, "--prerelease=false")
		} else {
			// trim trailing backslash-space from last display line
			editDisplay[len(editDisplay)-1] = strings.TrimSuffix(editDisplay[len(editDisplay)-1], " \\")
		}
		allEditArgs := append([]string{"release", "edit", currentTag}, editArgs...)
		steps = append(steps, releaseStep{
			title:   "Finalise release visibility",
			prompt:  fmt.Sprintf("finalise release %s", currentTag),
			display: editDisplay,
			run: func() error {
				return execIn(modRoot, "gh", allEditArgs...)
			},
		})
	}

	return steps
}

// runSteps iterates over steps, displaying each one and either prompting the
// user (default), running without prompting (--yes), or just displaying
// without running (--dry-run).  Skipped steps are silently omitted.
func runSteps(steps []releaseStep, dryRun, yes bool) error {
	section := func(title string) {
		fmt.Printf("\n# ── %s %s\n", title, strings.Repeat("─", max(0, 52-len(title))))
	}
	reader := bufio.NewReader(os.Stdin)

	for _, s := range steps {
		if s.skip {
			continue
		}
		section(s.title)
		for _, l := range s.display {
			fmt.Println(" ", l)
		}
		fmt.Println()

		if dryRun {
			fmt.Println("[dry-run] skipping")
			continue
		}

		if !yes {
			fmt.Printf("%s? [Y/n] ", s.prompt)
			line, _ := reader.ReadString('\n')
			line = strings.ToLower(strings.TrimSpace(line))
			if line == "n" || line == "no" {
				fmt.Println("skipped.")
				continue
			}
		}

		if err := s.run(); err != nil {
			return fmt.Errorf("%s: %w", s.title, err)
		}
	}
	return nil
}

// ── Helpers ────────────────────────────────────────────────────────────────

// shellSingleQuote wraps s in bash single quotes, escaping any literal single
// quotes inside s as '\”.  For example: it's → 'it'\”s'.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// relPath returns path relative to the current working directory, prefixed
// with "./".  Falls back to the absolute path if cwd cannot be determined.
func cwdRelPath(path string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return path
	}
	rel, err := filepath.Rel(cwd, path)
	if err != nil {
		return path
	}
	return "./" + rel
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

// execIn runs name+args in dir, streaming stdout and stderr to the terminal.
// Used by release step run functions.
func execIn(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// execInEnv is like execIn but merges extraEnv into the inherited environment.
func execInEnv(dir string, extraEnv []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "monorel: error: "+format+"\n", args...)
	os.Exit(1)
}
