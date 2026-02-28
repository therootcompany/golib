// monorel: Monorepo Release Tool
//
// Run from a module directory and pass the paths to each binary's main
// package.  Supports both single-binary and multi-binary modules.
//
// Usage:
//
//	# Single binary (path to the main package, or "." for module root)
//	cd cmd/tcpfwd
//	monorel .
//
//	# Multiple binaries under one module
//	cd io/transform/gsheet2csv
//	monorel ./cmd/gsheet2csv ./cmd/gsheet2tsv ./cmd/gsheet2env
//
// Install:
//
//	go install github.com/therootcompany/golib/tools/monorel@latest
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// binary describes one Go main package to build and release.
type binary struct {
	name     string // last path component, e.g. "gsheet2csv"
	mainPath string // path relative to module dir, e.g. "./cmd/gsheet2csv" or "."
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: monorel <binary-path> [<binary-path>...]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run from the module directory (where go.mod lives).")
		fmt.Fprintln(os.Stderr, "Use '.' when the module root is itself the main package.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  monorel .                                  # single binary at root")
		fmt.Fprintln(os.Stderr, "  monorel ./cmd/foo ./cmd/bar ./cmd/baz      # multiple binaries")
		os.Exit(2)
	}

	// Must run from the module directory so goreleaser can find go.mod and
	// so that .goreleaser.yaml is written next to it.
	if _, err := os.Stat("go.mod"); err != nil {
		fatalf("no go.mod in current directory; run monorel from the module root")
	}

	// 1. Parse binary descriptors from positional args.
	bins := parseBinaries(args)

	// 2. Module prefix relative to the .git root (e.g., "io/transform/gsheet2csv").
	//    This is also the tag prefix, e.g. "io/transform/gsheet2csv/v1.2.3".
	prefix := mustRun("git", "rev-parse", "--show-prefix")
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		fatalf("run monorel from a module subdirectory, not the repo root")
	}

	// Project name = last path component (used in checksum filename and release title).
	prefixParts := strings.Split(prefix, "/")
	projectName := prefixParts[len(prefixParts)-1]

	// 3. Normalised GitHub repo path (e.g., "github.com/therootcompany/golib").
	rawURL := mustRun("git", "remote", "get-url", "origin")
	repoPath := normalizeGitURL(rawURL)

	// 4. Collect and semver-sort tags matching "<prefix>/v*".
	rawTags := run("git", "tag", "--list", prefix+"/v*")
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

	// 5. Detect dirty working tree (uncommitted / untracked files under CWD).
	isDirty := run("git", "status", "--porcelain", "--", ".") != ""

	// 6. Count commits since latestTag that touch the module directory.
	var commitCount int
	if latestTag != "" {
		logOut := run("git", "log", "--oneline", latestTag+"..HEAD", "--", ".")
		if logOut != "" {
			commitCount = len(strings.Split(logOut, "\n"))
		}
	}

	// 7. Derive version string, full tag, and release flags.
	version, currentTag, isPreRelease, needsNewTag := computeVersion(
		prefix, latestTag, commitCount, isDirty,
	)

	// For release notes prevTag is the last stable tag before the one we're
	// releasing.  For a pre-release the "stable baseline" is latestTag.
	prevTag := prevStableTag
	if isPreRelease {
		prevTag = latestTag
	}

	// 8. Write .goreleaser.yaml.
	yamlContent := goreleaserYAML(projectName, bins)
	if err := os.WriteFile(".goreleaser.yaml", []byte(yamlContent), 0o644); err != nil {
		fatalf("writing .goreleaser.yaml: %v", err)
	}
	fmt.Fprintln(os.Stderr, "wrote .goreleaser.yaml")

	// 9. Emit the release script to stdout.
	headSHA := mustRun("git", "rev-parse", "HEAD")
	printScript(projectName, bins, version, currentTag, prevTag, repoPath, headSHA,
		isPreRelease, needsNewTag, isDirty)
}

// parseBinaries converts positional CLI arguments into binary descriptors.
//
// Each arg is the path to a Go main package, relative to the module directory.
// "." is special-cased: the binary name is taken from the current working
// directory name rather than from ".".
func parseBinaries(args []string) []binary {
	cwd, _ := os.Getwd()
	bins := make([]binary, 0, len(args))
	for _, arg := range args {
		// Normalise to a clean, forward-slash path.
		clean := filepath.ToSlash(filepath.Clean(arg))

		var name string
		if clean == "." {
			name = filepath.Base(cwd) // e.g., "tcpfwd" from working dir name
		} else {
			name = filepath.Base(clean) // e.g., "gsheet2csv"
		}

		// Restore "./" prefix that filepath.Clean strips, so goreleaser sees
		// an explicit relative path (e.g. "./cmd/gsheet2csv" not "cmd/gsheet2csv").
		mainPath := clean
		if clean != "." && !strings.HasPrefix(clean, "./") && !strings.HasPrefix(clean, "../") {
			mainPath = "./" + clean
		}

		bins = append(bins, binary{name: name, mainPath: mainPath})
	}
	return bins
}

// ── Version computation ────────────────────────────────────────────────────

// computeVersion returns (version, fullTag, isPreRelease, needsNewTag).
//
// Examples:
//
//	At "cmd/tcpfwd/v1.1.0", clean   → ("1.1.0",          "cmd/tcpfwd/v1.1.0",          false, false)
//	3 commits past v1.1.0, clean    → ("1.1.1-pre3",      "cmd/tcpfwd/v1.1.1-pre3",      true,  true)
//	dirty, 0 new commits            → ("1.1.1-pre1.dirty","cmd/tcpfwd/v1.1.1-pre1.dirty", true,  false)
func computeVersion(prefix, latestTag string, commitCount int, isDirty bool) (version, currentTag string, isPreRelease, needsNewTag bool) {
	if latestTag == "" {
		// Very first release – default to v0.1.0.
		return "0.1.0", prefix + "/v0.1.0", false, true
	}

	tagSemver := strings.TrimPrefix(latestTag, prefix+"/") // e.g., "v1.1.0"

	if commitCount == 0 && !isDirty {
		// HEAD is exactly at the tag.
		version = strings.TrimPrefix(tagSemver, "v")
		return version, latestTag, false, false
	}

	// Pre-release: bump patch of the base release version.
	base := strings.TrimPrefix(tagSemver, "v")
	if idx := strings.Index(base, "-"); idx >= 0 {
		base = base[:idx] // drop any existing pre-release label
	}
	dp := strings.SplitN(base, ".", 3)
	patch, _ := strconv.Atoi(dp[2])
	patch++

	preN := commitCount
	if preN == 0 {
		preN = 1 // dirty with no new commits still needs a label
	}
	preLabel := fmt.Sprintf("pre%d", preN)
	if isDirty {
		preLabel += ".dirty"
	}

	version = fmt.Sprintf("%s.%s.%d-%s", dp[0], dp[1], patch, preLabel)
	currentTag = prefix + "/v" + version
	// Only create a new tag for clean (non-dirty) pre-releases.
	needsNewTag = !isDirty
	return version, currentTag, true, needsNewTag
}

// ── Semver helpers ─────────────────────────────────────────────────────────

// semverLess returns true if semver string a < b.
// Handles "vX.Y.Z" and "vX.Y.Z-preN" forms.
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

	// Same base version: pre-release < release.
	if aPre == bPre {
		return false
	}
	if aPre == "" {
		return false // a is release → a > b (pre-release)
	}
	if bPre == "" {
		return true // a is pre-release → a < b (release)
	}
	// Both pre-release: compare numeric suffix of "preN".
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

// preNum extracts the numeric value from a pre-release label like "pre3" or "pre3.dirty".
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
// Design decisions:
//   - Uses {{.Env.VERSION}} instead of {{.Version}} everywhere so a prefixed
//     monorepo tag (e.g. io/transform/gsheet2csv/v1.2.3) never bleeds into
//     artifact filenames.
//   - Each binary gets its own build (with id) and its own archive (with ids)
//     so cross-platform tarballs are separate per tool.
//   - The checksum file is named <projectName>_VERSION_checksums.txt and
//     covers every archive produced in the run.
//   - release.disable: true — goreleaser Pro is required to publish with a
//     prefixed tag; we use `gh release` in the generated script instead.
func goreleaserYAML(projectName string, bins []binary) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s) }
	wf := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# yaml-language-server: $schema=https://goreleaser.com/static/schema.json\n")
	w("# vim: set ts=2 sw=2 tw=0 fo=cnqoj\n")
	w("# Generated by monorel (github.com/therootcompany/golib/tools/monorel)\n")
	w("\nversion: 2\n")
	w("\nbefore:\n  hooks:\n    - go mod tidy\n    - go generate ./...\n")

	// ── builds ──────────────────────────────────────────────────────────────
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

	// ── archives ────────────────────────────────────────────────────────────
	w("\narchives:\n")
	for _, bin := range bins {
		wf("  - id: %s\n", bin.name)
		wf("    ids: [%s]\n", bin.name)
		w("    formats: [tar.gz]\n")
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
		w("        formats: [zip]\n")
	}

	// ── changelog ───────────────────────────────────────────────────────────
	w("\nchangelog:\n  sort: asc\n  filters:\n    exclude:\n")
	w("      - \"^docs:\"\n      - \"^test:\"\n")

	// ── checksum ────────────────────────────────────────────────────────────
	w("\nchecksum:\n")
	wf("  name_template: \"%s_{{ .Env.VERSION }}_checksums.txt\"\n", projectName)
	w("  disable: false\n")

	// ── release ─────────────────────────────────────────────────────────────
	w("\n# Release is disabled: goreleaser Pro is required to publish with a\n")
	w("# prefixed monorepo tag. We use 'gh release' instead (see release script).\n")
	w("release:\n  disable: true\n")

	return b.String()
}

// ── Release script generation ──────────────────────────────────────────────

// printScript writes a numbered, ready-to-review bash release script to stdout.
func printScript(
	projectName string,
	bins []binary,
	version, currentTag, prevTag, repoPath, headSHA string,
	isPreRelease, needsNewTag, isDirty bool,
) {
	line := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	blank := func() { fmt.Println() }
	section := func(title string) {
		blank()
		fmt.Printf("# ── %s ", title)
		fmt.Println(strings.Repeat("─", max(0, 52-len(title))))
	}

	line("#!/usr/bin/env bash")
	line("# Generated by monorel — review carefully before running!")
	line("set -euo pipefail")

	if isDirty {
		blank()
		line("# ⚠  WARNING: working tree has uncommitted changes.")
		line("# Commit or stash them before releasing for a reproducible build.")
		line("# A .dirty suffix has been appended to the version below.")
	}

	// Summary comment block.
	blank()
	if len(bins) == 1 {
		line("# %-16s %s", "Binary:", bins[0].name)
	} else {
		names := make([]string, len(bins))
		for i, b := range bins {
			names[i] = b.name
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

	// Step 1 – env vars.
	section("Step 1: Environment variables")
	line("export VERSION=%q", version)
	line("export GORELEASER_CURRENT_TAG=%q", currentTag)

	// Step 2 – create tag (clean pre-releases and first releases only).
	if needsNewTag {
		section("Step 2: Create git tag")
		line("git tag %q", currentTag)
		line("# To undo:  git tag -d %q", currentTag)
	}

	// Step 3 – build.
	section("Step 3: Build with goreleaser")
	line("# release.disable=true in .goreleaser.yaml; goreleaser only builds.")
	line("goreleaser release --clean --skip=validate,announce")

	// Step 4 – release notes.
	section("Step 4: Generate release notes")
	if prevTag != "" {
		// Path-limited: only commits touching files under the module directory.
		line("RELEASE_NOTES=$(git --no-pager log %q..HEAD \\", prevTag)
		line("  --pretty=format:'- %%h %%s' -- ./)")
	} else {
		line("RELEASE_NOTES=$(git --no-pager log \\")
		line("  --pretty=format:'- %%h %%s' -- ./)")
	}

	// Step 5 – create draft release.
	section("Step 5: Create draft GitHub release")
	tagVersion := currentTag[strings.LastIndex(currentTag, "/")+1:] // strip module prefix
	title := projectName + " " + tagVersion
	line("gh release create %q \\", currentTag)
	line("  --title %q \\", title)
	line("  --notes \"${RELEASE_NOTES}\" \\")
	if isPreRelease {
		line("  --prerelease \\")
	}
	line("  --draft \\")
	line("  --target %q", headSHA)

	// Step 6 – upload artifacts.
	section("Step 6: Upload artifacts")
	line("gh release upload %q \\", currentTag)
	for _, bin := range bins {
		line("  ./dist/%s_*.tar.gz \\", bin.name)
		line("  ./dist/%s_*.zip \\", bin.name)
	}
	line("  \"./dist/%s_%s_checksums.txt\" \\", projectName, version)
	line("  --clobber")

	// Step 7 – publish.
	section("Step 7: Publish release (remove draft)")
	line("gh release edit %q --draft=false", currentTag)
	blank()
}

// ── Helpers ────────────────────────────────────────────────────────────────

// normalizeGitURL strips scheme, credentials, and .git suffix from a remote URL.
//
//	https://github.com/org/repo.git → github.com/org/repo
//	git@github.com:org/repo.git     → github.com/org/repo
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
	// SCP-style: git@github.com:org/repo
	if idx := strings.Index(rawURL, "@"); idx >= 0 {
		rawURL = rawURL[idx+1:]
	}
	return strings.ReplaceAll(rawURL, ":", "/")
}

func mustRun(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		fatalf("running %q %v: %v", name, args, err)
	}
	return strings.TrimSpace(string(out))
}

func run(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "monorel: error: "+format+"\n", args...)
	os.Exit(1)
}
