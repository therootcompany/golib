package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

func maybeGetUptime() (time.Time, error) {
	out, err := exec.Command("uptime").Output()
	if err != nil {
		return time.Now(), fmt.Errorf("uptime command failed: %s\n%w", out, err)
	}
	// Parse uptime output (e.g., "up 1 day,  2:34" or "up 2:34")
	re := regexp.MustCompile(`up\s+(?:(\d+)\s+days?,?\s+)?(?:(\d+):)?(\d+)`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) < 2 {
		return time.Now(), fmt.Errorf("invalid uptime format")
	}

	var seconds int64
	if days, err := strconv.Atoi(matches[1]); err == nil && matches[1] != "" {
		seconds += int64(days) * 24 * 3600
	}
	if hours, err := strconv.Atoi(matches[2]); err == nil && matches[2] != "" {
		seconds += int64(hours) * 3600
	}
	if minutes, err := strconv.Atoi(matches[3]); err == nil {
		seconds += int64(minutes) * 60
	}

	duration := time.Duration(seconds) * time.Second
	return time.Now().Add(-duration), nil
}
