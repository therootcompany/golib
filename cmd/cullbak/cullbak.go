// Authored in 2024 by AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	dailyDir  = "."
	weeklyDir = "weekly"
	trashDir  = "trash"
)

var (
	dailyExpire  time.Duration
	exts         []string
	visitedWeeks = make(map[string]struct{})
)

func main() {
	var path string
	var extsFlag string
	var dryRun bool
	var keepDaily int

	flag.StringVar(&extsFlag, "exts", "", "comma-separated list of file extensions")
	flag.IntVar(&keepDaily, "keep-daily", 5*7, "how many daily backups to retain")
	flag.BoolVar(&dryRun, "dry-run", false, "print files that would be moved or deleted")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("USAGE")
		fmt.Println("    go run cullbak.go --exts 'tar.xz,tar.zst' /mnt/backups/project-x/")
		os.Exit(1)
	}
	path = flag.Arg(0)

	dailyExpire = time.Duration(keepDaily) * 24 * time.Hour

	for ext := range strings.SplitSeq(extsFlag, ",") {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		exts = append(exts, ext)
	}
	if len(exts) == 0 {
		fmt.Fprintln(os.Stderr, "no valid extensions provided")
		os.Exit(1)
	}

	// Get the current date
	currentDay := time.Now()
	fmt.Println("Culling archive files of these types:", strings.Join(exts, ","))

	// Process daily backups
	err := processDailyBackups(path, currentDay, dryRun)
	if err != nil {
		fmt.Printf("Error processing %q: %v\n", path, err)
	}
}

func processDailyBackups(
	path string, currentDay time.Time, dryRun bool,
) error {
	//bakfiles := []os.DirEntry{}
	bakfiles := []os.FileInfo{}
	dailyPath := filepath.Join(path, dailyDir)

	{
		allFiles, err := os.ReadDir(dailyPath)
		if err != nil {
			return err
		}

		for _, file := range allFiles {
			if file.IsDir() {
				fmt.Printf("[skip] directory %q\n", file.Name())
				continue
			}

			hasExt := false
			for _, ext := range exts {
				if strings.HasSuffix(file.Name(), ext) {
					hasExt = true
					break
				}
			}
			if !hasExt {
				fmt.Printf("[skip] non-archive file %q\n", file.Name())
				continue
			}

			fileInfo, err := file.Info()
			if err != nil {
				return err
			}
			bakfiles = append(bakfiles, fileInfo)
		}
	}

	// oldest to youngest (asc)
	sort.Slice(bakfiles, func(i, j int) bool {
		fileI := bakfiles[i]
		fileJ := bakfiles[j]

		return fileI.ModTime().Before(fileJ.ModTime())
	})

	for _, fileInfo := range bakfiles {
		modifiedTime := fileInfo.ModTime()
		age := currentDay.Sub(modifiedTime)
		if dailyExpire < 24*time.Hour {
			panic("'keep-daily' must be at least 1 day")
		}
		tooFreshToCull := age < dailyExpire
		if tooFreshToCull {
			fmt.Printf("[skip] files from this and after are fresh: %q (%s)\n", fileInfo.Name(), formatDuration(age))
			break
		}

		year, week := modifiedTime.ISOWeek()
		yearWeek := fmt.Sprintf("%d-w%02d", year, week)
		weeklyPath := filepath.Join(path, weeklyDir, yearWeek)

		// If the dir exists, skip (we already have that backup)
		if _, ok := visitedWeeks[weeklyPath]; !ok {
			if _, err := os.Stat(weeklyPath); os.IsNotExist(err) {
				src := filepath.Join(dailyPath, fileInfo.Name())
				dst := filepath.Join(weeklyPath, fileInfo.Name())

				if dryRun {
					fmt.Printf("mv %q %q\n", src, dst)
					visitedWeeks[weeklyPath] = struct{}{}
					continue
				}

				if err := os.MkdirAll(weeklyPath, os.ModePerm); err != nil {
					return err
				}
				err := os.Rename(src, dst)
				if err != nil {
					fmt.Printf("couldn't move %s to %s:\n    %v\n", src, dst, err)
					// remove the dir so that it doesn't count as existing
					_ = os.Remove(weeklyPath)
					return err
				}
				fmt.Println("[move] created weekly backup", src, weeklyPath)
				continue
			}
		}

		{
			trashPath := filepath.Join(path, trashDir)
			src := filepath.Join(dailyPath, fileInfo.Name())
			dst := filepath.Join(trashPath, fileInfo.Name())

			if dryRun {
				fmt.Printf("rm %s\n", src)
				continue
			}

			if err := os.MkdirAll(trashPath, os.ModePerm); err != nil {
				return err
			}

			fmt.Printf("[cull] delete %s\n", src)
			if err := os.Rename(src, dst); err != nil {
				fmt.Printf("couldn't move %s to %s:\n    %v\n", src, dst, err)
				return err
			}
			if err := os.Remove(dst); err != nil {
				fmt.Printf("couldn't delete %s: %v\n", dst, err)
			}
		}
	}

	return nil
}

func formatDuration(d time.Duration) string {
	days := int64(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int64(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int64(d / time.Minute)
	d -= time.Duration(minutes) * time.Minute
	seconds := d.Seconds()

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 || hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}

	if hours < 1 {
		parts = append(parts, fmt.Sprintf("%.3fs", seconds))
	} else {
		parts = append(parts, fmt.Sprintf("%ds", int64(seconds)))
	}

	return strings.Join(parts, " ")
}

// func firstDayOfWeek90DaysAgo(currentDay time.Time) time.Time {
// 	// Calculate 90 days ago
// 	daysAgo := currentDay.AddDate(0, 0, -90)

// 	// Calculate the first day (Sunday) of the week 90 days ago
// 	daysAgoWeekday := daysAgo.Weekday()
// 	daysToFirstDayOfWeek := int(time.Sunday - daysAgoWeekday)
// 	firstDayOfWeek := daysAgo.AddDate(0, 0, daysToFirstDayOfWeek)

// 	return firstDayOfWeek
// }
