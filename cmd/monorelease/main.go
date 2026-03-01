// monorelease - Manages releases for code in monorepos.
//
// Authored in 2026 by AJ ONeal <aj@therootcompany.com>, assisted by Grok Ai.
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var verbose = flag.Bool("verbose", false, "")
var ignoreDirty = flag.String("ignore-dirty", "", "ignore dirty states [u n m d]")

func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var b bytes.Buffer
	cmd.Stdout = &b
	err := cmd.Run()
	return strings.TrimSpace(b.String()), err
}

func isVersion(s string) bool {
	re := regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	return re.MatchString(s)
}

func main() {
	flag.Parse()

	ignoreSet := make(map[rune]bool)
	for _, c := range *ignoreDirty {
		ignoreSet[c] = true
	}

	// 1. prefix (relative to root)
	// prefixB, _ := exec.Command("git", "rev-parse", "--show-prefix").Output()
	// prefix := strings.TrimSuffix(strings.TrimSpace(string(prefixB)), "/")

	// 2. cd root
	rootB, _ := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	root := strings.TrimSpace(string(rootB))
	_ = os.Chdir(root)

	// 3. committed files
	ls, _ := runGit("ls-files")
	committed := strings.Split(ls, "\n")

	// 4+6. modules (go + node) + untracked
	type Module struct {
		Path      string
		Type      string
		Untracked bool
	}
	modMap := make(map[string]Module)
	modTypes := map[string]string{"go.mod": "go", "package.json": "node"}

	for _, f := range committed {
		for suf, typ := range modTypes {
			if f == suf || strings.HasSuffix(f, "/"+suf) {
				p := filepath.Dir(f)
				if p == "." {
					p = ""
				}
				modMap[p] = Module{Path: p, Type: typ, Untracked: false}
				break
			}
		}
	}
	untrackedS, _ := runGit("ls-files", "--others", "--exclude-standard")
	for f := range strings.SplitSeq(untrackedS, "\n") {
		if f == "" {
			continue
		}
		for suf, typ := range modTypes {
			if f == suf || strings.HasSuffix(f, "/"+suf) {
				p := filepath.Dir(f)
				if p == "." {
					p = ""
				}
				if _, ok := modMap[p]; !ok {
					modMap[p] = Module{Path: p, Type: typ, Untracked: true}
				}
				break
			}
		}
	}

	modules := make([]Module, 0, len(modMap))
	for _, m := range modMap {
		modules = append(modules, m)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })

	// 5. dirty (porcelain)
	por, _ := runGit("status", "--porcelain", ".")
	porLines := strings.Split(por, "\n")
	dirtyMod := make(map[string]bool)

	modPrefixes := make([]string, 0, len(modules))
	for _, m := range modules {
		if m.Path != "" {
			modPrefixes = append(modPrefixes, m.Path+"/")
		}
	}
	sort.Slice(modPrefixes, func(i, j int) bool { return len(modPrefixes[i]) > len(modPrefixes[j]) })

	for _, line := range porLines {
		if len(line) < 3 || line[2] != ' ' {
			continue
		}
		status := line[0:2]
		fileP := line[3:]

		// classify
		types := []rune{}
		if status == "??" {
			types = append(types, 'u')
		}
		if strings.Contains(status, "A") {
			types = append(types, 'n')
		}
		if strings.Contains(status, "M") || strings.Contains(status, "R") || strings.Contains(status, "C") {
			types = append(types, 'm')
		}
		if strings.Contains(status, "D") {
			types = append(types, 'd')
		}

		thisDirty := false
		for _, t := range types {
			if !ignoreSet[t] {
				thisDirty = true
				break
			}
		}
		if !thisDirty {
			continue
		}

		// assign to module
		matched := false
		for _, pre := range modPrefixes {
			if strings.HasPrefix(fileP, pre) {
				modP := strings.TrimSuffix(pre, "/")
				dirtyMod[modP] = true
				matched = true
				break
			}
		}
		if !matched {
			dirtyMod[""] = true // root
		}
	}

	// 7. tags (highest first)
	tagsS, _ := runGit("tag", "--list", "--sort=-version:refname")
	tags := strings.Split(tagsS, "\n")
	modLatest := make(map[string]string)
	for _, t := range tags {
		if t == "" {
			continue
		}
		matched := false
		for _, m := range modules {
			match := false
			if m.Path == "" {
				if !strings.Contains(t, "/") && isVersion(t) {
					match = true
				}
			} else if strings.HasPrefix(t, m.Path+"/") {
				suf := t[len(m.Path)+1:]
				if isVersion(suf) {
					match = true
				}
			}
			if match {
				if _, ok := modLatest[m.Path]; !ok {
					modLatest[m.Path] = t
				}
				matched = true
				break
			}
		}
		if !matched && *verbose {
			fmt.Printf("unmatched tag: %s\n", t)
		}
	}

	// 8+9. display
	for _, m := range modules {
		d := dirtyMod[m.Path]
		latest := modLatest[m.Path]
		ver := "v0.0.0-1"
		commits := 0
		if latest != "" {
			suf := latest
			if m.Path != "" {
				suf = strings.TrimPrefix(latest, m.Path+"/")
			}
			ver = suf

			pArg := "."
			if m.Path != "" {
				pArg = "./" + m.Path
			}
			cS, _ := runGit("rev-list", "--count", latest+"..", "--", pArg)
			commits, _ = strconv.Atoi(cS)
			if commits > 0 {
				ver += fmt.Sprintf("-%d", commits)
			}
		}
		if d {
			ver += "-dirty"
		}
		if m.Untracked {
			fmt.Printf("./%s (%s, untracked): %s\n", m.Path, m.Type, ver)
		} else {
			fmt.Printf("./%s (%s): %s\n", m.Path, m.Type, ver)
		}
		if *verbose && commits > 0 && latest != "" {
			pArg := "."
			if m.Path != "" {
				pArg = "./" + m.Path
			}
			logS, _ := runGit("log", latest+"..", "--pretty=format:- %h %s", "--", pArg)
			if logS != "" {
				fmt.Println(logS)
			}
		}
	}
}
