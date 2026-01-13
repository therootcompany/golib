//
// Written in 2025 by AJ ONeal <aj@therootcompany.com>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.

// Package sql-migrate provides a simple SQL migrator that's easy to roll back or mix and match during development
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMigrationDir = "./sql/migrations/"
	defaultMigrationLog = "./sql/migrations.log"
	defaultCommand      = `psql "$PG_URL" < %s`
)

var (
	nonWordRe      = regexp.MustCompile(`\W+`)
	commandStartRe = regexp.MustCompile(`^#\s*command:\s*`)
	batchStartRe   = regexp.MustCompile(`^#\s*batch:\s*`)
	commentStartRe = regexp.MustCompile(`(^|\s+)#.*`)
)

type State struct {
	Date     time.Time
	Command  string
	Current  int
	Lines    []string
	Migrated []string
	SqlDir   string
	LogFile  string
}

func parseLog(text string, date time.Time) *State {
	state := &State{Date: date, Command: "", Current: 0, Lines: []string{}, Migrated: []string{}}
	text = strings.TrimSpace(text)
	if text == "" {
		state.Command = defaultCommand
		return state
	}
	state.Lines = strings.Split(text, "\n")
	batchCount := 0
	for i := range state.Lines {
		line := strings.TrimSpace(state.Lines[i])
		if commandStartRe.MatchString(line) {
			if state.Command != "" {
				log.Printf("   ignoring duplicate '%s'", line)
			} else {
				state.Command = commandStartRe.ReplaceAllString(line, "")
			}
		}
		if batchStartRe.MatchString(line) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || n <= 0 {
				log.Printf("   invalid '%s'", line)
				n = -1
			}
			batchCount++
			if n > state.Current {
				state.Current = n
			}
			if batchCount > state.Current {
				state.Current = batchCount
			}
		}
		migration := commentStartRe.ReplaceAllString(line, "")
		migration = strings.TrimSpace(migration)
		if migration != "" {
			state.Migrated = append(state.Migrated, migration)
		}
		state.Lines[i] = line
	}
	if state.Command == "" {
		state.Command = defaultCommand
	}
	if !strings.Contains(state.Command, "%s") {
		state.Command += " %s"
	}
	return state
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func create(state *State, desc string) error {
	dateStr := state.Date.Format("2006-01-02")
	entries, err := os.ReadDir(state.SqlDir)
	if err != nil {
		return err
	}

	maxNumber := 0
	datePrefix := dateStr + "-"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, datePrefix) {
			continue
		}
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		if strings.HasSuffix(name, "_"+desc+".up.sql") {
			return fmt.Errorf("migration for %q already exists:\n   %s", desc, state.SqlDir+"/"+name)
		}
		if strings.HasSuffix(name, ".down.sql") {
			continue
		}

		parts := strings.SplitN(name, "-", 4)
		if len(parts) < 4 {
			continue
		}
		numDesc := strings.SplitN(parts[3], "_", 2)
		if len(numDesc) < 2 {
			continue
		}
		num, err := strconv.Atoi(numDesc[0])
		if err != nil {
			continue
		}

		if num > maxNumber {
			maxNumber = num
		}
	}

	number := maxNumber / 1000
	number *= 1000
	number += 1000
	if number > 9000 {
		return fmt.Errorf("it's over 9000! ")
	}

	baseFilename := fmt.Sprintf("%s-%06d_%s", dateStr, number, desc)
	upPath := filepath.Join(state.SqlDir, baseFilename+".up.sql")
	downPath := filepath.Join(state.SqlDir, baseFilename+".down.sql")

	// Use fmt.Appendf to build byte slice, ignoring error as it can't fail with static format
	upContent := fmt.Appendf(nil, "-- %s (up)\n", desc)
	_ = os.WriteFile(upPath, upContent, 0644)
	downContent := fmt.Appendf(nil, "-- %s (down)\n", desc)
	_ = os.WriteFile(downPath, downContent, 0644)

	fmt.Fprintf(os.Stderr, "    created pair %s\n", upPath)
	fmt.Fprintf(os.Stderr, "                 %s\n", downPath)
	return nil
}

func listMigrations(state *State) (ups, downs []string, err error) {
	entries, err := os.ReadDir(state.SqlDir)
	if err != nil {
		return nil, nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			log.Printf("   ignoring '%s'", name)
			continue
		}
		if strings.HasSuffix(name, ".up.sql") {
			base := strings.TrimSuffix(name, ".up.sql")
			ups = append(ups, base)
			companion := filepath.Join(state.SqlDir, base+".down.sql")
			if !fileExists(companion) {
				log.Printf("   missing '%s'", companion)
			}
			continue
		}
		if strings.HasSuffix(name, ".down.sql") {
			base := strings.TrimSuffix(name, ".down.sql")
			downs = append(downs, base)
			companion := filepath.Join(state.SqlDir, base+".up.sql")
			if !fileExists(companion) {
				log.Printf("   missing '%s'", companion)
			}
			continue
		}
		log.Printf("   unknown '%s'", name)
	}
	sort.Strings(ups)
	sort.Strings(downs)
	return ups, downs, nil
}

func up(state *State) error {
	ups, _, err := listMigrations(state)
	if err != nil {
		return err
	}
	var pending []string
	for _, mig := range ups {
		found := slices.Contains(state.Migrated, mig)
		if !found {
			pending = append(pending, mig)
		}
	}
	if len(pending) == 0 {
		log.Println("   already up-to-date")
		return nil
	}
	n := state.Current + 1
	fmt.Printf("echo '# batch: %d' >> %s\n", n, state.LogFile)
	for _, mig := range pending {
		fmt.Println("")
		fmt.Printf("# INSERT INTO \"migrations\" ('%d', '%s')\n", n, mig)
		fmt.Printf("echo '%s' >> %s\n", mig, state.LogFile)
		path := filepath.Join(state.SqlDir, mig+".up.sql")
		if !strings.HasPrefix(path, "/") {
			if !strings.HasPrefix(path, "./") && !strings.HasPrefix(path, "../") {
				path = "./" + path
			}
		}
		cmd := strings.Replace(state.Command, "%s", path, 1)
		fmt.Println(cmd)
	}
	fmt.Println("")
	return nil
}

func down(state *State) error {
	lines := make([]string, len(state.Lines))
	copy(lines, state.Lines)
	lineCount := len(lines)
	slices.Reverse(lines)
	var batchLine string
	var batch []string
	for _, line := range lines {
		lineCount--
		if batchStartRe.MatchString(line) {
			batchLine = line
			break
		}
		mig := commentStartRe.ReplaceAllString(line, "")
		mig = strings.TrimSpace(mig)
		if mig == "" {
			log.Printf("   ignoring '%s'", line)
			continue
		}
		batch = append(batch, mig)
	}
	log.Printf("ROLLBACK %s", batchLine)
	for _, mig := range batch {
		fmt.Println("")
		fmt.Printf("# DELETE FROM \"migrations\" WHERE \"name\" = '%s';\n", mig)
		sqlfile := filepath.Join(state.SqlDir, mig+".down.sql")
		if !fileExists(sqlfile) {
			log.Printf("   missing '%s'", sqlfile)
		}
		cmd := strings.Replace(state.Command, "%s", sqlfile, 1)
		fmt.Println(cmd)
	}
	fmt.Println("")
	fmt.Println("# new file as to not overwrite the file while reading")
	fmt.Printf("head -n '%d' %s > %s.new\n", lineCount, state.LogFile, state.LogFile)
	fmt.Printf("mv %s.new %s\n", state.LogFile, state.LogFile)
	fmt.Println("")
	return nil
}

func status(state *State) error {
	lines := make([]string, len(state.Lines))
	copy(lines, state.Lines)
	hasCommand := commandStartRe.MatchString(lines[0])
	if hasCommand {
		lines = lines[1:]
	}
	slices.Reverse(lines)
	var previous []string
	for _, line := range lines {
		previous = append([]string{line}, previous...)
		if batchStartRe.MatchString(line) {
			break
		}
	}
	fmt.Fprintf(os.Stderr, "sqldir: %s\n", state.SqlDir)
	fmt.Fprintf(os.Stderr, "logfile: %s\n", state.LogFile)
	fmt.Fprintf(os.Stderr, "command: %s\n", state.Command)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Printf("# previous: %d\n", len(previous))
	for _, mig := range previous {
		fmt.Printf("   %s\n", mig)
	}
	if len(previous) == 0 {
		fmt.Println("   # (no previous migrations)")
	}
	fmt.Println("")
	ups, _, err := listMigrations(state)
	if err != nil {
		return err
	}
	var pending []string
	for _, mig := range ups {
		found := slices.Contains(state.Migrated, mig)
		if !found {
			pending = append(pending, mig)
		}
	}
	fmt.Printf("# pending: %d\n", len(pending))
	for _, mig := range pending {
		fmt.Printf("   %s\n", mig)
	}
	if len(pending) == 0 {
		fmt.Println("   # (no pending migrations)")
	}
	return nil
}

const helpText = `
sql-migrate v1.0.2 - a feature-branch-friendly SQL migrator

USAGE
   sql-migrate <command> [-d sqldir] [-f logfile] [args]

EXAMPLE
   sql-migrate init -d ./sql/migrations/ -f ./sql/migrations.log
   sql-migrate create <kebab-case-description>
   sql-migrate status
   sql-migrate up
   sql-migrate down
   sql-migrate list

COMMANDS
   init          - inits sql dir and migration file, adding or updating the
                   default command
   create        - creates a new, canonically-named up/down file pair in the
                   migrations directory
   status        - shows the same output as if processing a forward-migration
                   for the most recent batch
   up            - processes the first 'up' migration file missing from the
                   migration state
   down          - rolls back the latest entry of the latest migration batch
                   (the whole batch if just one)
   list          - lists migrations

OPTIONS
   -d <migrations directory>  default: ./sql/migrations/
   -f <migration state file>  default: ./sql/migrations.log

NOTES
   Migrations files are in the following format:
      <yyyy-mm-dd>-<number>_<name>.<up|down>.sql
      2020-01-01-1000_init.up.sql

   The migration state file contains the client command template (defaults to
      'psql "$PG_URL" < %s'), followed by a list of batches identified by a batch
      number comment and a list of migration file basenames and optional user
      comments, such as:
      # command: psql "$PG_URL" < %s
      # batch: 1
      2020-01-01-1000_init.up.sql # does a lot
      2020-01-01-1100_add-customer-tables.up.sql
      # batch: 2
      # We did id! Finally!
      2020-01-01-2000_add-ALL-THE-TABLES.up.sql

   The 'create' generates an up/down pair of files using the current date and
      the number 1000. If either file exists, the number is incremented by 1000 and
      tried again, up to 9000, or throws the error "it's over 9000!" on failure.
`

func main() {
	if len(os.Args) < 2 {
		//nolint
		fmt.Printf("%s\n", helpText)
		os.Exit(0)
	}

	command := os.Args[1]
	switch command {
	case "help", "--help",
		"version", "--version", "-V":
		fmt.Printf("%s\n", helpText)
		os.Exit(0)
	default:
		// do nothing
	}

	fs := flag.NewFlagSet(command, flag.ExitOnError)
	sqlDir := fs.String("d", defaultMigrationDir, "migrations directory")
	logFile := fs.String("f", defaultMigrationLog, "migration log file")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	date := time.Now()
	var state *State
	var err error

	logText, err := os.ReadFile(*logFile)
	if os.IsNotExist(err) {
		if command != "init" {
			log.Printf("   run 'init' first: missing '%s'", *logFile)
			os.Exit(1)
		}
		text := fmt.Sprintf("# command: %s\n", defaultCommand)
		dir := filepath.Dir(*logFile)
		err = os.MkdirAll(*sqlDir, 0755)
		if err != nil {
			log.Fatal(err)
		}
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile(*logFile, []byte(text), 0644)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("   created '%s'", *logFile)
		logText = []byte{}
	} else if err != nil {
		log.Fatal(err)
	}

	state = parseLog(string(logText), date)
	state.SqlDir = *sqlDir
	state.LogFile = *logFile

	switch command {
	case "init":
		if len(logText) > 0 {
			log.Printf("   found '%s'", *logFile)
		}
	case "create":
		args := fs.Args()
		if len(args) == 0 {
			log.Fatal("create requires a description")
		}
		desc := strings.Join(args, " ")
		desc = nonWordRe.ReplaceAllString(desc, " ")
		desc = strings.TrimSpace(desc)
		desc = nonWordRe.ReplaceAllString(desc, "-")
		desc = strings.ToLower(desc)
		err = create(state, desc)
		if err != nil {
			log.Fatal(err)
		}
	case "status":
		err = status(state)
		if err != nil {
			log.Fatal(err)
		}
	case "list":
		ups, downs, err := listMigrations(state)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Ups:")
		if len(ups) == 0 {
			fmt.Println("   (none)")
		}
		for _, u := range ups {
			fmt.Println(u)
		}
		fmt.Println("Downs:")
		if len(downs) == 0 {
			fmt.Println("   (none)")
		}
		for _, d := range downs {
			fmt.Println(d)
		}
	case "up":
		err = up(state)
		if err != nil {
			log.Fatal(err)
		}
	case "down":
		err = down(state)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Printf("unknown command %s", command)
		fmt.Printf("%s\n", helpText)
		os.Exit(1)
	}
}
