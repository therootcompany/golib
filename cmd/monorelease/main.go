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
	"encoding/csv"
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
var useCSV = flag.Bool("csv", false, "output CSV instead of table")
var csvComma = flag.String("comma", ",", "CSV field separator")

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

type Module struct {
	Path        string
	Type        string
	Untracked   bool
	Name        string
	Bins        map[string]string
	HasRootMain bool
}

type Row struct {
	Status  string
	Typ     string
	Name    string
	Version string
	Tag     string
	Path    string
}

func manifestPath(m Module) string {
	f := "go.mod"
	if m.Type == "node" {
		f = "package.json"
	}
	if m.Path == "" {
		return "./" + f
	}
	return "./" + m.Path + "/" + f
}

func main() {
	flag.Parse()

	ignoreSet := make(map[rune]bool)
	for _, c := range *ignoreDirty {
		ignoreSet[c] = true
	}

	rootB, _ := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	root := strings.TrimSpace(string(rootB))
	_ = os.Chdir(root)
	repoName := filepath.Base(root)

	ls, _ := runGit("ls-files")
	committed := strings.Split(ls, "\n")

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
			pre := m.Path
			if pre != "" {
				pre += "/"
			}
			goModulePrefixes = append(goModulePrefixes, pre)
		}
	}
	sort.Slice(goModulePrefixes, func(i, j int) bool { return len(goModulePrefixes[i]) > len(goModulePrefixes[j]) })

	goToModule := make(map[string]string)
	for _, gf := range allGoFiles {
		dir := filepath.Dir(gf)
		if dir == "." {
			dir = ""
		}
		matchP := ""
		for _, pre := range goModulePrefixes {
			if pre != "" && strings.HasPrefix(dir+"/", pre) {
				matchP = strings.TrimSuffix(pre, "/")
				break
			} else if pre == "" {
				matchP = ""
				break
			}
		}
		if matchP != "" || goToModule[gf] == "" {
			goToModule[gf] = matchP
		}
	}

	for i := range modules {
		m := &modules[i]
		m.Bins = make(map[string]string)
		m.Name = ""
		if m.Type == "node" {
			pkgFile := "package.json"
			if m.Path != "" {
				pkgFile = filepath.Join(m.Path, "package.json")
			}
			data, err := os.ReadFile(pkgFile)
			if err == nil {
				var pi struct {
					Name string `json:"name"`
					Bin  any    `json:"bin"`
				}
				if json.Unmarshal(data, &pi) == nil {
					if pi.Name != "" {
						name := pi.Name
						if idx := strings.LastIndex(name, "/"); idx != -1 {
							name = name[idx+1:]
						}
						m.Name = name
					}
					switch v := pi.Bin.(type) {
					case string:
						if v != "" {
							rel := filepath.Clean(filepath.Join(m.Path, v))
							n := m.Name
							if n == "" {
								n = strings.TrimSuffix(filepath.Base(v), filepath.Ext(v))
							}
							if n == "" || n == "." {
								n = "bin"
							}
							m.Bins[n] = rel
						}
					case map[string]any:
						for k, vv := range v {
							if s, ok := vv.(string); ok && s != "" {
								rel := filepath.Clean(filepath.Join(m.Path, s))
								m.Bins[k] = rel
							}
						}
					}
				}
			}
		} else if m.Type == "go" {
			goModPath := "go.mod"
			if m.Path != "" {
				goModPath = filepath.Join(m.Path, "go.mod")
			}
			if data, err := os.ReadFile(goModPath); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "module ") {
						full := strings.TrimSpace(strings.TrimPrefix(line, "module "))
						m.Name = filepath.Base(full)
						break
					}
				}
			}
			if m.Name == "" {
				if m.Path == "" {
					m.Name = repoName
				} else {
					m.Name = filepath.Base(m.Path)
				}
			}

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
					if strings.TrimSpace(line) == "package main" {
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
				if (dir == "" && m.Path == "") || dir == m.Path {
					m.HasRootMain = true
				}
			}
		}
		if m.Name == "" {
			if m.Path == "" {
				m.Name = repoName
			} else {
				m.Name = filepath.Base(m.Path)
			}
		}
	}

	dirtyReasons := make(map[string]map[rune]bool)
	por, _ := runGit("status", "--porcelain", ".")
	for _, line := range strings.Split(por, "\n") {
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
		modPrefixes := make([]string, 0, len(modules))
		for _, m := range modules {
			if m.Path != "" {
				modPrefixes = append(modPrefixes, m.Path+"/")
			}
		}
		sort.Slice(modPrefixes, func(i, j int) bool { return len(modPrefixes[i]) > len(modPrefixes[j]) })
		for _, pre := range modPrefixes {
			if strings.HasPrefix(fileP, pre) {
				modP := strings.TrimSuffix(pre, "/")
				if dirtyReasons[modP] == nil {
					dirtyReasons[modP] = make(map[rune]bool)
				}
				for _, t := range types {
					dirtyReasons[modP][t] = true
				}
				matched = true
				break
			}
		}
		if !matched {
			if dirtyReasons[""] == nil {
				dirtyReasons[""] = make(map[rune]bool)
			}
			for _, t := range types {
				dirtyReasons[""][t] = true
			}
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

	rows := []Row{}
	for _, m := range modules {
		latest := modLatest[m.Path]
		tagStr := "-"
		if latest != "" {
			tagStr = latest
		}

		pArg := "."
		if m.Path != "" {
			pArg = "./" + m.Path
		}
		var commits int
		ver := "v0.0.0"
		if latest != "" {
			suf := latest
			if m.Path != "" {
				suf = strings.TrimPrefix(latest, m.Path+"/")
			}
			ver = suf
			cS, _ := runGit("rev-list", "--count", latest+"..", "--", pArg)
			commits, _ = strconv.Atoi(cS)
			if commits > 0 {
				ver += fmt.Sprintf("-%d", commits)
			}
		} else {
			cS, _ := runGit("rev-list", "--count", "--", pArg)
			commits, _ = strconv.Atoi(cS)
			if commits > 0 {
				ver = fmt.Sprintf("v0.0.0-%d", commits)
			}
		}

		dirtyStr := ""
		if dr, ok := dirtyReasons[m.Path]; ok && len(dr) > 0 {
			order := []rune{'u', 'n', 'm', 'd'}
			for _, c := range order {
				if dr[c] {
					dirtyStr += string(c)
				}
			}
		}

		status := "current"
		if m.Untracked {
			status = "untracked"
		} else if dirtyStr != "" {
			status = "dirty (" + dirtyStr + ")"
		} else if commits > 0 {
			status = "new commits"
		}

		showModRow := true
		if (m.Type == "go" && m.HasRootMain) || (m.Type == "node" && len(m.Bins) > 0) {
			showModRow = false
		}

		if showModRow {
			rows = append(rows, Row{
				Status:  status,
				Typ:     "mod",
				Name:    m.Name,
				Version: ver,
				Tag:     tagStr,
				Path:    manifestPath(m),
			})
		}

		if len(m.Bins) > 0 {
			names := make([]string, 0, len(m.Bins))
			for n := range m.Bins {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				binLoc := m.Bins[n]
				var binShow string
				if m.Type == "go" {
					if binLoc == "" || binLoc == "." {
						binLoc = m.Path
						if binLoc == "" {
							binLoc = "."
						}
					}
					if binLoc == "." {
						binShow = "."
					} else {
						binShow = binLoc + "/"
					}
				} else {
					binShow = binLoc
				}
				rows = append(rows, Row{
					Status:  status,
					Typ:     "bin",
					Name:    n,
					Version: ver,
					Tag:     tagStr,
					Path:    "./" + binShow,
				})
			}
		}
	}

	if *useCSV {
		c := ','
		if *csvComma != "" && len(*csvComma) > 0 {
			c = rune((*csvComma)[0])
		}
		w := csv.NewWriter(os.Stdout)
		w.Comma = c
		_ = w.Write([]string{"status", "type", "name", "version", "current tag", "path"})
		for _, r := range rows {
			_ = w.Write([]string{r.Status, r.Typ, r.Name, r.Version, r.Tag, r.Path})
		}
		w.Flush()
	} else {
		headers := []string{"status", "type", "name", "version", "current tag", "path"}
		colWidths := make([]int, len(headers))
		for i, h := range headers {
			colWidths[i] = len(h)
		}
		for _, r := range rows {
			if len(r.Status) > colWidths[0] {
				colWidths[0] = len(r.Status)
			}
			if len(r.Typ) > colWidths[1] {
				colWidths[1] = len(r.Typ)
			}
			if len(r.Name) > colWidths[2] {
				colWidths[2] = len(r.Name)
			}
			if len(r.Version) > colWidths[3] {
				colWidths[3] = len(r.Version)
			}
			if len(r.Tag) > colWidths[4] {
				colWidths[4] = len(r.Tag)
			}
			if len(r.Path) > colWidths[5] {
				colWidths[5] = len(r.Path)
			}
		}
		fmt.Print("|")
		for i, h := range headers {
			fmt.Printf(" %-*s |", colWidths[i], h)
		}
		fmt.Println()
		fmt.Print("|")
		for _, w := range colWidths {
			fmt.Printf(" %s |", strings.Repeat("-", w))
		}
		fmt.Println()
		for _, r := range rows {
			fmt.Print("|")
			fmt.Printf(" %-*s |", colWidths[0], r.Status)
			fmt.Printf(" %-*s |", colWidths[1], r.Typ)
			fmt.Printf(" %-*s |", colWidths[2], r.Name)
			fmt.Printf(" %-*s |", colWidths[3], r.Version)
			fmt.Printf(" %-*s |", colWidths[4], r.Tag)
			fmt.Printf(" %-*s |", colWidths[5], r.Path)
			fmt.Println()
		}
	}
}
