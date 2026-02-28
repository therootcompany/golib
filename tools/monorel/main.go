// monorel: Monorepo Release Tool
//
// Run from a module subdirectory inside a git repo to:
//   - Generate (or update) .goreleaser.yaml for the module
//   - Print a ready-to-review bash release script to stdout
//
// Usage:
//
//	cd cmd/tcpfwd
//	go run github.com/therootcompany/golib/tools/monorel
//
// Install:
//
//	go install github.com/therootcompany/golib/tools/monorel@latest
package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

func main() {
	// 1. Module prefix relative to .git root (e.g., "cmd/tcpfwd")
	prefix := mustRun("git", "rev-parse", "--show-prefix")
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
		fatalf("run monorel from a module subdirectory, not the repo root")
	}

	// 2. Binary name = last path component of prefix
	prefixParts := strings.Split(prefix, "/")
	binName := prefixParts[len(prefixParts)-1]

	// 3. Normalised GitHub repo path (e.g., "github.com/therootcompany/golib")
	rawURL := mustRun("git", "remote", "get-url", "origin")
	repoPath := normalizeGitURL(rawURL)

	// 4. Collect tags matching "<prefix>/v*" and sort by semver
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

	// 5. Detect dirty working tree (uncommitted / untracked files in this dir)
	isDirty := run("git", "status", "--porcelain", "--", ".") != ""

	// 6. Count commits since latestTag that touch this directory
	var commitCount int
	if latestTag != "" {
		logOut := run("git", "log", "--oneline", latestTag+"..HEAD", "--", ".")
		if logOut != "" {
			commitCount = len(strings.Split(logOut, "\n"))
		}
	}

	// 7. Derive version string, full tag, and release flags
	version, currentTag, isPreRelease, needsNewTag := computeVersion(
		prefix, latestTag, commitCount, isDirty,
	)

	// For release notes: prevTag is the last tag that's not the one we're releasing.
	// When pre-releasing, the last stable tag is latestTag (not prevStableTag).
	prevTag := prevStableTag
	if isPreRelease {
		prevTag = latestTag
	}

	// 8. Write .goreleaser.yaml
	yamlContent := goreleaserYAML(binName)
	if err := os.WriteFile(".goreleaser.yaml", []byte(yamlContent), 0o644); err != nil {
		fatalf("writing .goreleaser.yaml: %v", err)
	}
	fmt.Fprintln(os.Stderr, "wrote .goreleaser.yaml")

	// 9. Emit release script to stdout
	headSHA := mustRun("git", "rev-parse", "HEAD")
	printScript(binName, version, currentTag, prevTag, repoPath, headSHA,
		isPreRelease, needsNewTag, isDirty)
}

// computeVersion returns (version, fullTag, isPreRelease, needsNewTag).
//
// Examples:
//
//	At "cmd/tcpfwd/v1.1.0", no changes → ("1.1.0", "cmd/tcpfwd/v1.1.0", false, false)
//	3 commits past "cmd/tcpfwd/v1.1.0" → ("1.1.1-pre3", "cmd/tcpfwd/v1.1.1-pre3", true, true)
//	dirty, 0 new commits             → ("1.1.1-pre1.dirty", "cmd/tcpfwd/v1.1.1-pre1.dirty", true, false)
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

// goreleaserYAML returns the contents of .goreleaser.yaml for binName.
//
// Key design decisions:
//   - Uses {{.Env.VERSION}} instead of {{.Version}} everywhere so the
//     prefixed monorepo tag (cmd/tcpfwd/v1.1.0) doesn't bleed into filenames.
//   - release.disable: true because we use `gh` to create the GitHub Release
//     (goreleaser Pro is required to publish with a prefixed tag).
//   - Checksum file is named with VERSION so it matches the archive names.
func goreleaserYAML(binName string) string {
	// NOTE: "BINNAME" is our placeholder; goreleaser template markers
	// ({{ ... }}) are kept verbatim – this is NOT a Go text/template.
	const tpl = `# yaml-language-server: $schema=https://goreleaser.com/static/schema.json
# vim: set ts=2 sw=2 tw=0 fo=cnqoj
# Generated by monorel (github.com/therootcompany/golib/tools/monorel)

version: 2

before:
  hooks:
    - go mod tidy
    - go generate ./...

builds:
  - env:
      - CGO_ENABLED=0
    binary: BINNAME
    ldflags:
      - -s -w -X main.version={{.Env.VERSION}} -X main.commit={{.Commit}} -X main.date={{.Date}} -X main.builtBy=goreleaser
    goos:
      - linux
      - windows
      - darwin

archives:
  - formats: [tar.gz]
    # name_template uses VERSION env var so the prefixed monorepo tag
    # (e.g. cmd/tcpfwd/v1.1.0) doesn't appear in archive filenames.
    name_template: >-
      BINNAME_{{ .Env.VERSION }}_
      {{- title .Os }}_
      {{- if eq .Arch "amd64" }}x86_64
      {{- else if eq .Arch "386" }}i386
      {{- else }}{{ .Arch }}{{ end }}
      {{- if .Arm }}v{{ .Arm }}{{ end }}
    format_overrides:
      - goos: windows
        formats: [zip]

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"

checksum:
  name_template: "BINNAME_{{ .Env.VERSION }}_checksums.txt"
  disable: false

# Release is disabled: goreleaser Pro is required to publish with a
# prefixed monorepo tag. We use 'gh release' instead (see release script).
release:
  disable: true
`
	return strings.ReplaceAll(tpl, "BINNAME", binName)
}

// printScript writes a bash release script to stdout.
func printScript(
	binName, version, currentTag, prevTag, repoPath, headSHA string,
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
	line("# %-16s %s", "Binary:", binName)
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

	// Step 2 – create tag (only for clean pre-releases or first release).
	if needsNewTag {
		section("Step 2: Create git tag")
		line("git tag %q", currentTag)
		line("# To undo:  git tag -d %q", currentTag)
	}

	// Step 3 – build.
	section("Step 3: Build with goreleaser")
	line("# release.disable=true is set in .goreleaser.yaml; goreleaser only builds.")
	line("goreleaser release --clean --skip=validate,announce")

	// Step 4 – release notes.
	section("Step 4: Generate release notes")
	if prevTag != "" {
		// Path-limited log: only commits that touched files under this directory.
		line("RELEASE_NOTES=$(git --no-pager log %q..HEAD \\", prevTag)
		line("  --pretty=format:'- %%h %%s' -- ./)")
	} else {
		line("RELEASE_NOTES=$(git --no-pager log \\")
		line("  --pretty=format:'- %%h %%s' -- ./)")
	}

	// Step 5 – create draft release.
	section("Step 5: Create draft GitHub release")
	tagVersion := currentTag[strings.LastIndex(currentTag, "/")+1:] // strip prefix
	title := binName + " " + tagVersion
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
	line("  ./dist/%s_*.tar.gz \\", binName)
	line("  ./dist/%s_*.zip \\", binName)
	line("  \"./dist/%s_%s_checksums.txt\" \\", binName, version)
	line("  --clobber")

	// Step 7 – publish.
	section("Step 7: Publish release (remove draft)")
	line("gh release edit %q --draft=false", currentTag)
	blank()
}

// normalizeGitURL strips scheme, credentials, and .git suffix from a remote URL.
//
//	https://github.com/org/repo.git → github.com/org/repo
//	git@github.com:org/repo.git     → github.com/org/repo
func normalizeGitURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawURL = strings.TrimSuffix(rawURL, ".git")
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rawURL = rawURL[idx+3:]
		// Drop any "user:pass@" prefix.
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

