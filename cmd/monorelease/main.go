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

var (
	verbose     = flag.Bool("verbose", false, "")
	ignoreDirty = flag.String("ignore-dirty", "", "ignore dirty states [u n m d]")
	csvOut      = flag.Bool("csv", false, "output real CSV")
	comma       = flag.String("comma", ",", "CSV field delimiter")
)

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

type Row struct {
	Status     string
	Type       string
	Name       string
	Version    string
	CurrentTag string
	Path       string
}

func main() {
	flag.Parse()

	ignoreSet := make(map[rune]bool)
	for _, c := range *ignoreDirty {
		ignoreSet[c] = true
	}

	repoDir, _ := runGit("rev-parse", "--show-toplevel")
	_ = os.Chdir(strings.TrimSpace(repoDir))

	repoName := filepath.Base(repoDir)

	gitFiles, _ := runGit("ls-files")
	committed := strings.Split(gitFiles, "\n")

	modTypes := map[string]string{"go.mod": "go", "package.json": "node"}
	modMap := make(map[string]struct {
		Path      string
		Type      string
		Untracked bool
		Bins      map[string]string
	})

	for _, f := range committed {
		for suf, typ := range modTypes {
			if f == suf || strings.HasSuffix(f, "/"+suf) {
				p := filepath.Dir(f)
				if p == "." {
					p = ""
				}
				modMap[p] = struct {
					Path      string
					Type      string
					Untracked bool
					Bins      map[string]string
				}{p, typ, false, make(map[string]string)}
				break
			}
		}
	}

	moreFiles, _ := runGit("ls-files", "--others", "--exclude-standard")
	for _, f := range strings.Split(moreFiles, "\n") {
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
					modMap[p] = struct {
						Path      string
						Type      string
						Untracked bool
						Bins      map[string]string
					}{p, typ, true, make(map[string]string)}
				}
				break
			}
		}
	}

	goFiles, _ := runGit("ls-files", "*.go")
	moreGoFiles, _ := runGit("ls-files", "--others", "--exclude-standard", "*.go")
	allGoFiles := append(
		strings.Split(goFiles, "\n"),
		strings.Split(moreGoFiles, "\n")...,
	)

	// go module prefix matching
	goPrefixes := []string{}
	for p := range modMap {
		if modMap[p].Type == "go" {
			goPrefixes = append(goPrefixes, p+"/")
		}
	}
	if _, ok := modMap[""]; ok && modMap[""].Type == "go" {
		goPrefixes = append(goPrefixes, "")
	}
	sort.Slice(goPrefixes, func(i, j int) bool { return len(goPrefixes[i]) > len(goPrefixes[j]) })

	goModuleOf := make(map[string]string)
	for _, f := range allGoFiles {
		if f == "" {
			continue
		}
		dir := filepath.Dir(f)
		if dir == "." {
			dir = ""
		}
		for _, pre := range goPrefixes {
			if pre == "" || strings.HasPrefix(dir+"/", pre) {
				goModuleOf[f] = strings.TrimSuffix(pre, "/")
				break
			}
		}
	}

	// populate bins
	for p, m := range modMap {
		if m.Type == "node" {
			pkgPath := filepath.Join(p, "package.json")
			if p == "" {
				pkgPath = "package.json"
			}
			data, _ := os.ReadFile(pkgPath)
			var pkg struct {
				Name string         `json:"name"`
				Bin  map[string]any `json:"bin"`
			}
			json.Unmarshal(data, &pkg)
			if pkg.Bin == nil {
				continue
			}
			for name, v := range pkg.Bin {
				if s, ok := v.(string); ok && s != "" {
					rel := filepath.Clean(filepath.Join(p, s))
					m.Bins[name] = rel
				}
			}
		} else if m.Type == "go" {
			mainDirs := make(map[string]struct{})
			for _, f := range allGoFiles {
				if f == "" || goModuleOf[f] != p || strings.HasSuffix(f, "_test.go") {
					continue
				}
				data, _ := os.ReadFile(f)
				if strings.Contains(string(data), "\npackage main\n") || strings.HasPrefix(string(data), "package main\n") {
					d := filepath.Dir(f)
					if d == "." {
						d = ""
					}
					mainDirs[d] = struct{}{}
				}
			}
			for d := range mainDirs {
				name := repoName
				if d != "" {
					name = filepath.Base(d)
				}
				m.Bins[name] = d
			}
		}
		modMap[p] = m
	}

	// dirty
	statusLines, _ := runGit("status", "--porcelain", ".")
	porLines := strings.Split(statusLines, "\n")
	dirty := make(map[string]bool)
	modPrefixes := make([]string, 0, len(modMap))
	for p := range modMap {
		if p != "" {
			modPrefixes = append(modPrefixes, p+"/")
		}
	}
	sort.Slice(modPrefixes, func(i, j int) bool { return len(modPrefixes[i]) > len(modPrefixes[j]) })

	for _, line := range porLines {
		if len(line) < 4 {
			continue
		}
		st := line[:2]
		file := line[3:]
		if st == "  " || st == "!!" {
			continue
		}

		states := []rune{}
		if st == "??" {
			states = append(states, 'u')
		}
		if strings.Contains(st, "A") || strings.Contains(st, "?") {
			states = append(states, 'n')
		}
		if strings.Contains(st, "M") || strings.Contains(st, "R") || strings.Contains(st, "C") {
			states = append(states, 'm')
		}
		if strings.Contains(st, "D") {
			states = append(states, 'd')
		}

		isDirty := false
		for _, r := range states {
			if !ignoreSet[r] {
				isDirty = true
				break
			}
		}
		if !isDirty {
			continue
		}

		found := false
		for _, pre := range modPrefixes {
			if strings.HasPrefix(file, pre) {
				dirty[strings.TrimSuffix(pre, "/")] = true
				found = true
				break
			}
		}
		if !found {
			dirty[""] = true
		}
	}

	// tags
	tagLines, _ := runGit("tag", "--list", "--sort=-version:refname")
	tags := strings.Split(tagLines, "\n")
	latestTag := make(map[string]string)
	for _, t := range tags {
		if t == "" {
			continue
		}
		for p := range modMap {
			if p == "" {
				if !strings.Contains(t, "/") && isVersion(t) {
					if _, ok := latestTag[p]; !ok {
						latestTag[p] = t
					}
					break
				}
			} else if strings.HasPrefix(t, p+"/") && isVersion(strings.TrimPrefix(t, p+"/")) {
				if _, ok := latestTag[p]; !ok {
					latestTag[p] = t
				}
				break
			}
		}
	}

	// rows
	var rows []Row
	for p, m := range modMap {
		tag := latestTag[p]
		suf := tag
		if p != "" {
			suf = strings.TrimPrefix(tag, p+"/")
		}

		ver := "v0.0.0"
		if tag != "" {
			ver = suf
		}
		commits := 0
		if tag != "" {
			scope := "."
			if p != "" {
				scope = "./" + p
			}
			n, _ := runGit("rev-list", "--count", tag+"..", "--", scope)
			c, _ := strconv.Atoi(n)
			commits = c
			if commits > 0 {
				ver += fmt.Sprintf("-%d", commits)
			}
		} else {
			ver += "-1"
		}
		if dirty[p] {
			ver += "-dirty"
		}

		pathShow := "."
		if p != "" {
			pathShow = "./" + p
		}

		statusParts := []string{}
		if m.Untracked {
			statusParts = append(statusParts, "untracked")
		}
		if dirty[p] {
			var ds []string
			s, _ := runGit("status", "--porcelain", pathShow)
			if strings.Contains(s, " M") {
				ds = append(ds, "m")
			}
			s, _ = runGit("status", "--porcelain", pathShow)
			if strings.Contains(s, "??") {
				ds = append(ds, "u")
			}
			// simplified; can expand later
			if len(ds) > 0 {
				statusParts = append(statusParts, fmt.Sprintf("dirty (%s)", strings.Join(ds, "")))
			}
		}
		if commits > 0 {
			statusParts = append(statusParts, "new commits")
		}
		if len(statusParts) == 0 {
			statusParts = append(statusParts, "current")
		}
		status := strings.Join(statusParts, ", ")

		// module row
		rows = append(rows, Row{
			Status:     status,
			Type:       "mod",
			Name:       filepath.Base(pathShow),
			Version:    ver,
			CurrentTag: tag,
			Path:       filepath.Join(pathShow, m.Type+".mod"),
		})

		// bin rows
		binNames := make([]string, 0, len(m.Bins))
		for n := range m.Bins {
			binNames = append(binNames, n)
		}
		sort.Strings(binNames)

		for _, name := range binNames {
			binPath := m.Bins[name]
			binShow := "."
			if binPath != "" {
				binShow = "./" + binPath
			}
			rows = append(rows, Row{
				Status:     status,
				Type:       "bin",
				Name:       name,
				Version:    ver,
				CurrentTag: tag,
				Path:       binShow + "/",
			})
		}
	}

	// output
	if *csvOut {
		w := csv.NewWriter(os.Stdout)
		w.Comma = rune((*comma)[0])
		w.Write([]string{"status", "type", "name", "version", "current tag", "path"})
		for _, r := range rows {
			w.Write([]string{r.Status, r.Type, r.Name, r.Version, r.CurrentTag, r.Path})
		}
		w.Flush()
		return
	}

	// aligned table
	var max [6]int
	for _, r := range rows {
		l := []string{r.Status, r.Type, r.Name, r.Version, r.CurrentTag, r.Path}
		for i, s := range l {
			if len(s) > max[i] {
				max[i] = len(s)
			}
		}
	}

	fmt.Printf("%-*s | %-*s | %-*s | %-*s | %-*s | %s\n",
		max[0], "status",
		max[1], "type",
		max[2], "name",
		max[3], "version",
		max[4], "current tag",
		"path",
	)
	fmt.Printf("%s-+-%s-+-%s-+-%s-+-%s-+-%s\n",
		strings.Repeat("-", max[0]),
		strings.Repeat("-", max[1]),
		strings.Repeat("-", max[2]),
		strings.Repeat("-", max[3]),
		strings.Repeat("-", max[4]),
		strings.Repeat("-", max[5]),
	)

	for _, r := range rows {
		fmt.Printf("%-*s | %-*s | %-*s | %-*s | %-*s | %s\n",
			max[0], r.Status,
			max[1], r.Type,
			max[2], r.Name,
			max[3], r.Version,
			max[4], r.CurrentTag,
			r.Path,
		)
	}
}
