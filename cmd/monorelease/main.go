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
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var b bytes.Buffer
	cmd.Stdout = &b
	err := cmd.Run()
	return strings.TrimSpace(b.String()), err
}

func RunGoFrom(chdir string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	if chdir != "" {
		cmd.Dir = chdir
	}

	var b bytes.Buffer
	cmd.Stdout = &b
	err := cmd.Run()
	return strings.TrimSpace(b.String()), err
}

func isVersion(s string) bool {
	re := regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	return re.MatchString(s)
}

type Tag struct {
	ShortHash string
	Name      string
}

type GitFile struct {
	Path       string
	XY         string
	Releasable string
}

func (f GitFile) IsClean() bool {
	return f.XY == ""
}

func (f GitFile) IsTracked() bool {
	return f.XY != "??"
}

type Releasable struct {
	Status     string
	Type       string
	Name       string
	Version    string
	CurrentTag string
	Path       string
	releasable string
}

type Releaser struct {
	Root             string
	Prefix           string
	Committed        []string
	Untracked        []string
	TagList          []Tag
	StatusLines      []string
	GitFiles         map[string]GitFile
	AllGoFiles       []string
	RepoName         string
	Ignore           map[rune]bool
	GoModulePrefixes []string
	GoToModule       map[string]string
	ModulePrefixes   []string
}

type GoModule struct {
	PackageName string
	Path        string
}

type NodePackage struct {
	Path string
}

func (r *Releaser) Init() {
	var wg sync.WaitGroup
	var untracked string
	var tagsStr string

	wg.Go(func() {
		out, _ := runGit("remote", "get-url", "origin")
		r.RepoName, _ = strings.CutSuffix(strings.TrimSpace(path.Base(out)), ".git")
	})
	wg.Go(func() {
		out, _ := runGit("rev-parse", "--show-toplevel")
		r.Root = strings.TrimSpace(out)
	})
	wg.Go(func() {
		out, _ := runGit("rev-parse", "--show-prefix")
		r.Prefix = strings.TrimSuffix(strings.TrimSpace(out), "/")
	})
	wg.Go(func() {
		out, _ := runGit("ls-files", "--others", "--exclude-standard")
		untracked = strings.TrimSpace(out)
	})
	wg.Go(func() {
		out, _ := runGit("tag", "--list", "--sort=version:refname", "--format=%(objectname:short=7) %(refname:strip=2)")
		tagsStr = strings.TrimSpace(out)
	})
	wg.Wait()

	if untracked != "" {
		r.Untracked = strings.Split(untracked, "\n")
	}
	if tagsStr != "" {
		for line := range strings.SplitSeq(tagsStr, "\n") {
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				r.TagList = append(r.TagList, Tag{ShortHash: parts[0], Name: parts[1]})
			}
		}
	}
	for i, j := 0, len(r.TagList)-1; i < j; i, j = i+1, j-1 {
		r.TagList[i], r.TagList[j] = r.TagList[j], r.TagList[i]
	}

	statusStr, _ := runGit("status", "--porcelain", ".")
	r.StatusLines = strings.Split(statusStr, "\n")
	lsStr, _ := runGit("ls-files")
	r.Committed = strings.Split(lsStr, "\n")

	r.GitFiles = make(map[string]GitFile)
	for _, line := range r.StatusLines {
		if len(line) < 3 || line[2] != ' ' {
			continue
		}
		xy := line[0:2]
		p := line[3:]
		r.GitFiles[p] = GitFile{Path: p, XY: xy, Releasable: ""}
	}

	goCommStr, _ := runGit("ls-files", "--", "*.go")
	goUntrStr, _ := runGit("ls-files", "--others", "--exclude-standard", "--", "*.go")
	for _, s := range []string{goCommStr, goUntrStr} {
		if s == "" {
			continue
		}
		for f := range strings.SplitSeq(s, "\n") {
			if f != "" {
				r.AllGoFiles = append(r.AllGoFiles, f)
			}
		}
	}

	_ = os.Chdir(r.Root)
}

func (r *Releaser) LatestTag(modPath string) string {
	for _, t := range r.TagList {
		match := false
		if modPath == "" {
			if !strings.Contains(t.Name, "/") && isVersion(t.Name) {
				match = true
			}
		} else if suf, ok := strings.CutPrefix(t.Name, modPath+"/"); ok {
			if isVersion(suf) {
				match = true
			}
		}
		if match {
			return t.Name
		}
	}
	return ""
}

func getDirtyTypes(xy string) []rune {
	types := []rune{}
	if xy == "??" {
		types = append(types, '?')
		return types
	}

	if strings.Contains(xy, "A") {
		types = append(types, 'A')
	}
	if strings.ContainsAny(xy, "M") {
		types = append(types, 'M')
	}
	if strings.ContainsAny(xy, "R") {
		types = append(types, 'R')
	}
	if strings.ContainsAny(xy, "C") {
		types = append(types, 'C')
	}
	if strings.Contains(xy, "D") {
		types = append(types, 'D')
	}
	return types
}

func (r *Releaser) DirtyStates(modPath string) map[rune]bool {
	dr := make(map[rune]bool)
	if modPath != "" {
		pre := modPath + "/"
		for p, gf := range r.GitFiles {
			if p == modPath || strings.HasPrefix(p, pre) {
				for _, t := range getDirtyTypes(gf.XY) {
					dr[t] = true
				}
			}
		}
	} else {
		for p, gf := range r.GitFiles {
			matched := false
			for _, pre := range r.ModulePrefixes {
				if pre != "" && strings.HasPrefix(p, pre) {
					matched = true
					break
				}
			}
			if !matched {
				for _, t := range getDirtyTypes(gf.XY) {
					dr[t] = true
				}
			}
		}
	}
	return dr
}

func getVersionStatus(r *Releaser, modPath, manifestRel string) (ver string, commits int, tagStr, status string) {
	ver = "" // empty for no change
	latest := r.LatestTag(modPath)
	tagStr = "-"
	if latest != "" {
		tagStr = latest
	}
	pArg := "."
	if modPath != "" {
		pArg = "./" + modPath
	}
	var suf string
	if latest != "" {
		suf = latest
		if modPath != "" {
			suf = strings.TrimPrefix(latest, modPath+"/")
		}
		cS, _ := runGit("rev-list", "--count", latest+"..", "--", pArg)
		commits, _ = strconv.Atoi(cS)
		if commits > 0 {
			ver = fmt.Sprintf("%s-%d", suf, commits)
		}
	} else {
		ver = "v0.1.0"
		cS, _ := runGit("rev-list", "--count", "--", pArg)
		commits, _ = strconv.Atoi(cS)
		if commits > 0 {
			ver = fmt.Sprintf("%s-%d", ver, commits)
		}
	}
	dirtyMap := r.DirtyStates(modPath)
	dirtyStr := ""
	for _, c := range []rune{'?', 'A', 'M', 'R', 'C', 'D'} {
		if dirtyMap[c] && !r.Ignore[c] {
			dirtyStr += string(c)
		}
	}
	untrackedMod := false
	if gf, ok := r.GitFiles[manifestRel]; ok && gf.XY == "??" {
		untrackedMod = true
	} else {
		untrackedMod = slices.Contains(r.Untracked, manifestRel)
	}
	status = "" // current, clean
	if untrackedMod {
		status = "-" // untracked
		ver = "-"
		if tagStr == "-" {
			tagStr = ""
		}
	} else if dirtyStr != "" {
		if ver == "" {
			// ver = "v0.0.0"
			ver = suf
		}
		ver += "+dev"
		status = "dirty (" + dirtyStr + ")"
	} else if commits > 0 {
		status = "++"
	}
	return
}

func (r *Releaser) DiscoverGoModules() []GoModule {
	modCh := make(chan GoModule, 10)

	var wg sync.WaitGroup
	var mods []GoModule
	go func() {
		for mod := range modCh {
			mods = append(mods, mod)
		}
	}()
	for _, f := range append(r.Committed, r.Untracked...) {
		if f == "" {
			continue
		}
		if f == "go.mod" || strings.HasSuffix(f, "/go.mod") {
			p := filepath.Dir(f)
			if p == "." {
				p = ""
			}
			mods = append(mods, GoModule{PackageName: "", Path: p})
			// TODO for when we need the real package name
			wg.Go(func() {
				// pkg, _ := RunGoFrom(p, "list", "-f", "{{.Name}}", ".")
				// modCh <- GoModule{PackageName: pkg, Path: p}
			})
		}
	}
	wg.Wait()
	close(modCh)

	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })

	r.GoModulePrefixes = make([]string, 0, len(mods))
	for _, m := range mods {
		pre := m.Path
		if pre != "" {
			pre += "/"
		}
		r.GoModulePrefixes = append(r.GoModulePrefixes, pre)
	}
	sort.Slice(r.GoModulePrefixes, func(i, j int) bool { return len(r.GoModulePrefixes[i]) > len(r.GoModulePrefixes[j]) })

	r.GoToModule = make(map[string]string)
	for _, gf := range r.AllGoFiles {
		dir := filepath.Dir(gf)
		if dir == "." {
			dir = ""
		}
		matchP := ""
		for _, pre := range r.GoModulePrefixes {
			if pre != "" && strings.HasPrefix(dir+"/", pre) || pre == "" {
				matchP = strings.TrimSuffix(pre, "/")
				break
			}
		}
		r.GoToModule[gf] = matchP
	}
	return mods
}

func (r *Releaser) DiscoverNodePackages() []NodePackage {
	seen := make(map[string]bool)
	for _, f := range append(r.Committed, r.Untracked...) {
		if f == "" {
			continue
		}
		if f == "package.json" || strings.HasSuffix(f, "/package.json") {
			p := filepath.Dir(f)
			if p == "." {
				p = ""
			}
			seen[p] = true
		}
	}
	var pkgs []NodePackage
	for p := range seen {
		pkgs = append(pkgs, NodePackage{Path: p})
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Path < pkgs[j].Path })
	return pkgs
}

func (m GoModule) Process(r *Releaser) []Releasable {
	manifestRel := "go.mod"
	if m.Path != "" {
		manifestRel = m.Path + "/go.mod"
	}
	ver, _, tagStr, status := getVersionStatus(r, m.Path, manifestRel)

	name := ""
	goModFile := manifestRel
	if data, err := os.ReadFile(goModFile); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if full, ok := strings.CutPrefix(line, "module "); ok {
				name = filepath.Base(full)
				break
			}
		}
	}
	if name == "" {
		if m.Path == "" {
			name = r.RepoName
		} else {
			name = filepath.Base(m.Path)
		}
	}

	mainDirs := make(map[string]bool)
	for _, gf := range r.AllGoFiles {
		if r.GoToModule[gf] != m.Path {
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
		for line := range strings.SplitSeq(string(data), "\n") {
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

	bins := make(map[string]string)
	for dir := range mainDirs {
		var bname, fullP string
		if dir == "" || dir == "." {
			bname = r.RepoName
			fullP = "."
		} else {
			bname = filepath.Base(dir)
			fullP = dir
		}
		bins[bname] = fullP
	}

	hasRootMain := false
	rootD := m.Path
	if rootD == "" {
		rootD = ""
	}
	for d := range mainDirs {
		if d == rootD {
			hasRootMain = true
			break
		}
	}
	showModRow := !hasRootMain

	rows := []Releasable{}
	if showModRow {
		relname := m.Path
		if relname == "" {
			relname = r.RepoName
		}
		rows = append(rows, Releasable{
			Status:     status,
			Type:       "mod",
			Name:       name,
			Version:    ver,
			CurrentTag: tagStr,
			Path:       "./" + manifestRel,
			releasable: relname,
		})
	}
	if len(bins) > 0 {
		names := make([]string, 0, len(bins))
		for n := range bins {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fullP := bins[n]
			binShow := fullP
			if fullP == "" || fullP == "." {
				binShow = "."
			} else {
				binShow += "/"
			}
			rows = append(rows, Releasable{
				Status:     status,
				Type:       "bin",
				Name:       n,
				Version:    ver,
				CurrentTag: tagStr,
				Path:       "./" + binShow,
				releasable: strings.TrimSuffix(binShow, "/"),
			})
		}
	}
	return rows
}

func (p NodePackage) Process(r *Releaser) []Releasable {
	manifestRel := "package.json"
	if p.Path != "" {
		manifestRel = p.Path + "/package.json"
	}
	ver, _, tagStr, status := getVersionStatus(r, p.Path, manifestRel)

	pkgFile := manifestRel
	name := ""
	bins := make(map[string]string)
	if data, err := os.ReadFile(pkgFile); err == nil {
		var pi struct {
			Name string `json:"name"`
			Bin  any    `json:"bin"`
		}
		if json.Unmarshal(data, &pi) == nil {
			if pi.Name != "" {
				name = pi.Name
				if idx := strings.LastIndex(name, "/"); idx != -1 {
					name = name[idx+1:]
				}
			}
			switch v := pi.Bin.(type) {
			case string:
				if v != "" {
					rel := filepath.Clean(filepath.Join(p.Path, v))
					n := name
					if n == "" {
						n = strings.TrimSuffix(filepath.Base(v), filepath.Ext(v))
					}
					if n == "" || n == "." {
						n = "bin"
					}
					bins[n] = rel
				}
			case map[string]any:
				for k, vv := range v {
					if s, ok := vv.(string); ok && s != "" {
						rel := filepath.Clean(filepath.Join(p.Path, s))
						bins[k] = rel
					}
				}
			}
		}
	}
	if name == "" {
		if p.Path == "" {
			name = r.RepoName
		} else {
			name = filepath.Base(p.Path)
		}
	}

	showModRow := len(bins) == 0
	rows := []Releasable{}
	if showModRow {
		rows = append(rows, Releasable{
			Status:     status,
			Type:       "mod",
			Name:       name,
			Version:    ver,
			CurrentTag: tagStr,
			Path:       "./" + manifestRel,
		})
	}
	if len(bins) > 0 {
		names := make([]string, 0, len(bins))
		for n := range bins {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			rel := bins[n]
			rows = append(rows, Releasable{
				Status:     status,
				Type:       "bin",
				Name:       n,
				Version:    ver,
				CurrentTag: tagStr,
				Path:       "./" + rel,
			})
		}
	}
	return rows
}

type MainConfig struct {
	ignoreDirty string
	useCSV      bool
	csvComma    string
	rows        []Releasable
}

func main() {
	cli := &MainConfig{}

	fs := flag.NewFlagSet("rerelease status", flag.ExitOnError)
	// var verbose = flag.Bool("verbose", false, "")
	fs.StringVar(&cli.ignoreDirty, "ignore-dirty", "", "ignore dirty states [? A M R C D]")
	fs.BoolVar(&cli.useCSV, "csv", false, "output CSV instead of table")
	fs.StringVar(&cli.csvComma, "comma", ",", "CSV field separator")
	_ = fs.Parse(os.Args[1:])

	cli.init()
	cli.status()
}

func (cli *MainConfig) init() {
	r := &Releaser{}
	r.Init()

	r.Ignore = make(map[rune]bool)
	for _, c := range cli.ignoreDirty {
		r.Ignore[c] = true
	}

	goMods := r.DiscoverGoModules()
	nodePkgs := r.DiscoverNodePackages()

	r.ModulePrefixes = make([]string, 0)
	for _, gm := range goMods {
		pre := gm.Path
		if pre != "" {
			pre += "/"
		}
		r.ModulePrefixes = append(r.ModulePrefixes, pre)
	}
	for _, np := range nodePkgs {
		pre := np.Path
		if pre != "" {
			pre += "/"
		}
		r.ModulePrefixes = append(r.ModulePrefixes, pre)
	}
	sort.Slice(r.ModulePrefixes, func(i, j int) bool {
		return len(r.ModulePrefixes[i]) > len(r.ModulePrefixes[j])
	})

	cli.rows = []Releasable{}
	for _, m := range goMods {
		cli.rows = append(cli.rows, m.Process(r)...)
	}
	for _, p := range nodePkgs {
		cli.rows = append(cli.rows, p.Process(r)...)
	}
}
