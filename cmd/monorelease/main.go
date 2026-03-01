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
	"encoding/json"
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

	// prefixB, _ := exec.Command("git", "rev-parse", "--show-prefix").Output()
	// prefix := strings.TrimSuffix(strings.TrimSpace(string(prefixB)), "/")

	rootB, _ := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	root := strings.TrimSpace(string(rootB))
	_ = os.Chdir(root)
	repoName := filepath.Base(root)

	ls, _ := runGit("ls-files")
	committed := strings.Split(ls, "\n")

	type Module struct {
		Path      string
		Type      string
		Untracked bool
		Bins      map[string]string
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
	for _, f := range strings.Split(untrackedS, "\n") {
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

	goCommS, _ := runGit("ls-files", "--", "*.go")
	goUntrS, _ := runGit("ls-files", "--others", "--exclude-standard", "--", "*.go")
	allGoFiles := []string{}
	for _, s := range []string{goCommS, goUntrS} {
		for _, line := range strings.Split(s, "\n") {
			if line != "" {
				allGoFiles = append(allGoFiles, line)
			}
		}
	}

	modules := make([]Module, 0, len(modMap))
	for _, m := range modMap {
		modules = append(modules, m)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })

	goModulePrefixes := []string{}
	for _, m := range modules {
		if m.Type == "go" {
			if m.Path == "" {
				goModulePrefixes = append(goModulePrefixes, "")
			} else {
				goModulePrefixes = append(goModulePrefixes, m.Path+"/")
			}
		}
	}
	sort.Slice(goModulePrefixes, func(i, j int) bool {
		return len(goModulePrefixes[i]) > len(goModulePrefixes[j])
	})

	goToModule := make(map[string]string)
	for _, gf := range allGoFiles {
		dir := filepath.Dir(gf)
		if dir == "." {
			dir = ""
		}
		matchP := ""
		matched := false
		for _, pre := range goModulePrefixes {
			if pre != "" && strings.HasPrefix(dir+"/", pre) {
				matchP = strings.TrimSuffix(pre, "/")
				matched = true
				break
			} else if pre == "" && !matched {
				matchP = ""
				matched = true
			}
		}
		if matched {
			goToModule[gf] = matchP
		}
	}

	for i := range modules {
		m := &modules[i]
		m.Bins = make(map[string]string)
		if m.Type == "node" {
			pkgFile := "package.json"
			if m.Path != "" {
				pkgFile = filepath.Join(m.Path, "package.json")
			}
			data, err := os.ReadFile(pkgFile)
			if err != nil {
				continue
			}
			var pi struct {
				Name string `json:"name"`
				Bin  any    `json:"bin"`
			}
			if json.Unmarshal(data, &pi) != nil {
				continue
			}
			switch v := pi.Bin.(type) {
			case string:
				if v != "" {
					rel := filepath.Clean(filepath.Join(m.Path, v))
					name := pi.Name
					if name == "" {
						name = strings.TrimSuffix(filepath.Base(v), filepath.Ext(v))
					}
					if name == "" || name == "." {
						name = "bin"
					}
					m.Bins[name] = rel
				}
			case map[string]any:
				for k, vv := range v {
					if s, ok := vv.(string); ok && s != "" {
						rel := filepath.Clean(filepath.Join(m.Path, s))
						m.Bins[k] = rel
					}
				}
			}
		} else if m.Type == "go" {
			mainDirs := make(map[string]bool)
			for _, gf := range allGoFiles {
				if goToModule[gf] != m.Path {
					continue
				}
				if strings.HasSuffix(gf, "_test.go") {
					continue
				}
				data, err := os.ReadFile(gf)
				if err != nil {
					continue
				}
				hasMain := false
				for _, line := range strings.Split(string(data), "\n") {
					if line == "package main" {
						hasMain = true
						break
					}
				}
				if hasMain {
					dir := filepath.Dir(gf)
					if dir == "." {
						dir = ""
					}
					mainDirs[dir] = true
				}
			}
			for dir := range mainDirs {
				var name, fullP string
				if dir == "" || dir == "." {
					name = repoName
					fullP = "."
				} else {
					name = filepath.Base(dir)
					fullP = dir
				}
				m.Bins[name] = fullP
			}
		}
	}

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
			dirtyMod[""] = true
		}
	}

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

		pathShow := m.Path
		if pathShow == "" {
			pathShow = "."
		}
		unStr := ""
		if m.Untracked {
			unStr = ", untracked"
		}
		fmt.Printf("./%s (%s%s): %s\n", pathShow, m.Type, unStr, ver)

		if len(m.Bins) > 0 {
			names := make([]string, 0, len(m.Bins))
			for n := range m.Bins {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				p := m.Bins[n]
				showP := p
				if showP == "" || showP == "." {
					showP = "."
				}
				fmt.Printf("   %s -> ./%s\n", n, showP)
			}
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
