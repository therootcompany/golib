package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/therootcompany/golib/time/calendar"
)

// ---------- 1. Data structures for a row ----------
type Rule struct {
	Event     string
	Nth       int          // 0 = fixed day of month, -1 = last, … (same semantics as GetNthWeekday)
	Weekday   time.Weekday // ignored when Nth == 0
	FixedDay  int          // used only when Nth == 0 (e.g. “15” for the 15th)
	TimeOfDay string       // HH:MM in the event’s local zone (e.g. "19:00")
	Location  *time.Location
	// Reminders are ignored for now – you can add them later.
}

// ---------- 2. CSV → []Rule ----------
func LoadRules(rd *csv.Reader) ([]Rule, error) {
	// first line is the header
	if _, err := rd.Read(); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	var rules []Rule
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read row: %w", err)
		}
		if len(rec) < 6 {
			continue // malformed – skip
		}
		rule, err := parseRule(rec)
		if err != nil {
			// keep going but report the problem
			fmt.Printf("WARN: skip row %q: %v\n", rec, err)
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseRule(rec []string) (Rule, error) {
	event := rec[0]
	nthStr := rec[1]
	dayStr := rec[2]
	dateStr := rec[3]
	timeStr := rec[4]
	tz := rec[5]

	var r Rule
	r.Event = strings.TrimSpace(event)

	// ----- Nth -----
	nthStr = strings.TrimSpace(nthStr)
	if nthStr == "" {
		r.Nth = 0 // fixed day
	} else {
		// allow “-1” for “last”
		n, err := strconv.Atoi(nthStr)
		if err != nil {
			return r, fmt.Errorf("invalid Nth %q", nthStr)
		}
		r.Nth = n
	}
	if r.Nth > 5 || r.Nth < -5 {
		return r, fmt.Errorf("'Nth' value must be between -5 and 5, not %q", nthStr)
	}

	// ----- Weekday -----
	dayStr = strings.TrimSpace(dayStr)
	if dayStr != "" && r.Nth != 0 {
		wd, ok := parseWeekday(dayStr)
		if !ok {
			return r, fmt.Errorf("unknown weekday %q", dayStr)
		}
		r.Weekday = wd
	}

	// ----- Fixed day (only when Nth == 0) -----
	if r.Nth == 0 {
		dateStr := strings.TrimSpace(dateStr)
		if dateStr == "" {
			return r, fmt.Errorf("missing fixed day for event %s", r.Event)
		}
		d, err := strconv.Atoi(dateStr)
		if err != nil || d == 0 || d < -31 || d > 31 {
			return r, fmt.Errorf("invalid fixed day %q", dateStr)
		}
		r.FixedDay = d
	}

	// ----- Time -----
	r.TimeOfDay = strings.TrimSpace(timeStr)
	if r.TimeOfDay == "" {
		r.TimeOfDay = "00:00"
	}
	if _, err := time.Parse("15:04", r.TimeOfDay); err != nil {
		return r, fmt.Errorf("bad time %q", r.TimeOfDay)
	}

	// ----- Location (Address column is ignored for now) -----
	// We default to America/Denver – change if you have a column with TZ name.
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return r, err
	}
	r.Location = loc

	return r, nil
}

func parseWeekday(s string) (time.Weekday, bool) {
	m := map[string]time.Weekday{
		"SUN": time.Sunday, "MON": time.Monday, "TUE": time.Tuesday,
		"WED": time.Wednesday, "THU": time.Thursday,
		"FRI": time.Friday, "SAT": time.Saturday,
	}
	wd, ok := m[strings.ToUpper(s[:3])]
	return wd, ok
}

// ---------- 3. Next occurrence ----------
func (r Rule) NextAfter(after time.Time, cal calendar.MultiYearCalendar) (time.Time, error) {
	candidate, ok := r.Next(after)
	if !ok {
		return time.Time{}, fmt.Errorf("no occurrence for rule")
	}

	// Convert to the rule’s local zone and attach the time-of-day.
	candidate = time.Date(candidate.Year(), candidate.Month(), candidate.Day(),
		0, 0, 0, 0, r.Location)

	hour, min, err := parseHourMin(r.TimeOfDay)
	if err != nil {
		return time.Time{}, err
	}
	candidate = time.Date(candidate.Year(), candidate.Month(), candidate.Day(),
		hour, min, 0, 0, r.Location)

	if candidate.After(after) {
		return candidate, nil
	}

	return time.Time{}, fmt.Errorf("no occurrence found for %s after %s", r.Event, after)
}

// Next returns the *date* (midnight UTC) for the rule in the given year/month.
// It respects the same semantics as GetNthWeekday.
func (r Rule) Next(start time.Time) (time.Time, bool) {
	if r.Nth != 0 {
		// Floating weekday rule
		startYear := start.Year()
		endYear := startYear + 5 // up through leap year
		startMonth := start.Month()
		for year := startYear; year <= endYear; year++ {
			for month := startMonth; month <= 12; month++ {
				t, ok := calendar.GetNthWeekday(year, month, r.Weekday, r.Nth)
				if ok {
					if t.After(start) {
						return t, ok
					}
				}
			}
			startMonth = 1
		}
		return time.Time{}, false
	}

	// Fixed day of month
	if r.FixedDay < -31 || r.FixedDay > 31 {
		return time.Time{}, false
	}

	// time.Date will clamp invalid days (e.g. 31st of February → March 3rd)
	// – we simply reject months that cannot contain the day.
	// the 0th day of the next month is the last day of the previous month
	lastDay := time.Date(start.Year(), start.Month()+1, 0, 0, 0, 0, 0, r.Location).Day()
	if r.FixedDay > lastDay {
		return time.Time{}, false
	}

	fixedDay := r.FixedDay
	if r.FixedDay < 0 {
		// -1 is last, -2 is second to last... -31 is first for a month with 31 days
		// 1+ 31 -1 = 31
		// 1+ 31 -31 = 1
		fixedDay = 1 + lastDay + r.FixedDay
		if fixedDay < 1 {
			return time.Time{}, false
		}
	}

	// fmt.Fprintf(os.Stderr, "DEBUG event %s: %d-%d-%d\n", r.Event, start.Year(), start.Month(), fixedDay)
	var t time.Time
	startYear := start.Year()
	endYear := startYear + 5 // up through leap year
	startMonth := start.Month()
	for year := startYear; year <= endYear; year++ {
		for month := startMonth; month <= 12; month++ {
			t = time.Date(year, month, fixedDay, 0, 0, 0, 0, r.Location)
			// fmt.Fprintf(os.Stderr, "DEBUG candidate event time %s\n", t.Format(time.RFC3339))
			if t.After(start) {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func parseHourMin(s string) (hour, min int, err error) {
	_, err = fmt.Sscanf(s, "%d:%d", &hour, &min)
	return
}

type Event struct {
	Rule Rule
	Time time.Time
}

// ---------- 4. Example usage ----------
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: go run ./cmd/calendar/ ./path/to/events.csv\n")
		os.Exit(1)
	}

	csvpath := os.Args[1]
	f, err := os.Open(csvpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	csvr := csv.NewReader(f)
	defer func() {
		_ = f.Close()
	}()
	rules, err := LoadRules(csvr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cal := calendar.NewMultiYearCalendar(2025, 2026, calendar.FixedHolidays, calendar.FloatingHolidays)
	now := time.Now()

	var events []Event
	for _, r := range rules {
		t, err := r.NextAfter(now, cal)
		if err != nil {
			fmt.Printf("%s: %v\n", r.Event, err)
			continue
		}
		events = append(events, Event{r, t})
	}
	slices.SortFunc(events, func(a, b Event) int {
		if a.Time.Before(b.Time) {
			return -1
		}
		if a.Time.After(b.Time) {
			return 1
		}
		if a.Rule.Event > b.Rule.Event {
			return 1
		} else if a.Rule.Event < b.Rule.Event {
			return -1
		}
		return 0
	})

	for _, ev := range events {
		fmt.Printf("%s → %s\n", ev.Time.Format(time.RFC3339), ev.Rule.Event)
	}
}
