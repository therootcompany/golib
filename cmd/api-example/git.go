package main

import (
	"os/exec"
	"strings"
	"time"
)

func maybeGetVersion() string {
	// Try git describe for tag + commits since tag
	args := []string{"describe", "--tags", "--abbrev=7", "--dirty=+local", "--always"}
	if out, err := exec.Command("git", args...).Output(); err == nil {
		return strings.TrimSpace(strings.TrimPrefix(string(out), "v"))
	}

	return "0.0.0-dev"
}

func maybeGetCommit() string {
	// Try git rev-parse for short commit hash
	if out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output(); err == nil {
		if out, err := exec.Command("git", "status", "--porcelain").Output(); err == nil && len(out) == 0 {
			return strings.TrimSpace(string(out))
		}
		return strings.TrimSpace(string(out)) + "+dev"
	}
	return "0000000"
}

func maybeGetDate() string {
	// Get timestamp of most recent commit, if clean
	if out, err := exec.Command("git", "status", "--porcelain").Output(); err == nil && len(out) == 0 {
		if out, err := exec.Command("git", "log", "-1", "--format=%ci").Output(); err == nil {
			if t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(string(out))); err == nil {
				return t.Format(time.RFC3339)
			}
		}
	}

	// Return current day with 0s for hour, minute, second
	return time.Now().UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
}
