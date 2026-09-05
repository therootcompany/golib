package calendar

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

type testCase struct {
	inputDate string
	inputTZ   string
	expected  string
}

func TestNthWeekday(t *testing.T) {
	tests := []testCase{
		{"2025-10-31T00:00:00Z", "UTC", "2025-10-31 (Fri) is the 5th Friday of the month"},
		{"2025-11-01T00:00:00Z", "UTC", "2025-11-01 (Sat) is the 1st Saturday of the month"},
		{"2025-11-02T00:00:00Z", "UTC", "2025-11-02 (Sun) is the 1st Sunday of the month"},
		{"2025-11-06T00:00:00Z", "UTC", "2025-11-06 (Thu) is the 1st Thursday of the month"},
		{"2025-11-07T00:00:00Z", "UTC", "2025-11-07 (Fri) is the 1st Friday of the month"},
		{"2025-11-08T00:00:00Z", "UTC", "2025-11-08 (Sat) is the 2nd Saturday of the month"},
		{"2025-10-31T00:00:00Z", "America/Denver", "2025-10-31 (Fri) is the 5th Friday of the month"},
		{"2025-11-01T00:00:00Z", "America/Denver", "2025-11-01 (Sat) is the 1st Saturday of the month"},
		{"2025-11-02T00:00:00Z", "America/Denver", "2025-11-02 (Sun) is the 1st Sunday of the month"},
		{"2025-11-06T00:00:00Z", "America/Denver", "2025-11-06 (Thu) is the 1st Thursday of the month"},
		{"2025-11-07T00:00:00Z", "America/Denver", "2025-11-07 (Fri) is the 1st Friday of the month"},
		{"2025-11-08T00:00:00Z", "America/Denver", "2025-11-08 (Sat) is the 2nd Saturday of the month"},
		{"2025-11-15T00:00:00Z", "UTC", "2025-11-15 (Sat) is the 3rd Saturday of the month"},
		{"2025-11-30T00:00:00Z", "UTC", "2025-11-30 (Sun) is the 5th Sunday of the month"},
		{"2025-02-28T00:00:00Z", "UTC", "2025-02-28 (Fri) is the 4th Friday of the month"},
		{"2024-02-29T00:00:00Z", "UTC", "2024-02-29 (Thu) is the 5th Thursday of the month"},
	}

	for _, tc := range tests {
		t.Run(tc.inputDate+"_"+tc.inputTZ, func(t *testing.T) {
			loc, _ := time.LoadLocation(tc.inputTZ)
			date, _ := time.ParseInLocation(time.RFC3339, tc.inputDate, loc)

			nth := NthWeekday(date)
			got := fmt.Sprintf("%s is the %d%s %s of the month",
				date.Format("2006-01-02 (Mon)"),
				nth,
				GetSuffixEnglish(nth),
				date.Weekday())

			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

type nthWeekdayTest struct {
	year     int
	month    time.Month
	weekday  time.Weekday
	n        int
	wantDate string
	wantOK   bool
}

func TestGetNthWeekday(t *testing.T) {
	tests := []nthWeekdayTest{
		{2025, time.November, time.Saturday, 1, "2025-11-01", true},
		{2025, time.November, time.Saturday, 2, "2025-11-08", true},
		{2025, time.November, time.Saturday, 3, "2025-11-15", true},
		{2025, time.November, time.Saturday, 4, "2025-11-22", true},
		{2025, time.November, time.Saturday, 5, "2025-11-29", true},
		{2025, time.November, time.Saturday, 6, "", false},
		{2025, time.November, time.Saturday, 0, "", false},
		{2025, time.November, time.Saturday, -1, "2025-11-29", true},
		{2025, time.November, time.Saturday, -2, "2025-11-22", true},
		{2025, time.November, time.Saturday, -3, "2025-11-15", true},
		{2025, time.November, time.Saturday, -4, "2025-11-08", true},
		{2025, time.November, time.Saturday, -5, "2025-11-01", true},
		{2025, time.November, time.Saturday, -6, "", false},

		{2025, time.November, time.Sunday, 1, "2025-11-02", true},
		{2025, time.November, time.Friday, 1, "2025-11-07", true},
		{2025, time.November, time.Friday, 5, "", false}, // only 4 Fridays

		{2024, time.February, time.Monday, 5, "", false}, // Feb 2024 has only 4 Mondays
		{2024, time.February, time.Thursday, 4, "2024-02-22", true},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%d-%02d-%s-%d", tt.year, tt.month, tt.weekday, tt.n)
		t.Run(name, func(t *testing.T) {
			got, ok := GetNthWeekday(tt.year, tt.month, tt.weekday, tt.n)
			if ok != tt.wantOK {
				t.Fatalf("ok mismatch: want %v, got %v", tt.wantOK, ok)
			}
			if !ok {
				return
			}
			if got.Format("2006-01-02") != tt.wantDate {
				t.Errorf("date = %s, want %s", got.Format("2006-01-02"), tt.wantDate)
			}
			if got.Weekday() != tt.weekday {
				t.Errorf("weekday = %s, want %s", got.Weekday(), tt.weekday)
			}
		})
	}
}

type businessDaysBeforeTest struct {
	start string
	n     int
	want  string
}

func TestGetBankDaysBefore(t *testing.T) {
	tests := []businessDaysBeforeTest{
		{"2025-11-10T12:00:01Z", 1, "2025-11-07T12:00:01Z"}, // Mon → Fri
		{"2025-11-10T12:00:02Z", 2, "2025-11-06T12:00:02Z"}, // Mon → Thu
		{"2025-11-08T12:00:03Z", 1, "2025-11-06T12:00:03Z"}, // Sat (non-biz) → count 2 → Thu
		{"2025-11-11T12:00:04Z", 1, "2025-11-10T12:00:04Z"}, // Wed → Tue
		{"2025-11-27T12:00:04Z", 1, "2025-11-25T12:00:04Z"}, // Thu (holiday) → count 2 → Tue
		{"2025-12-26T12:00:05Z", 1, "2025-12-23T12:00:05Z"}, // Fri → Tue (skip Xmas, Xmas Eve)
		{"2025-12-31T12:00:06Z", 1, "2025-12-29T12:00:06Z"}, // NYE (non-biz) → count 2 → Tue
	}
	cal := NewMultiYearCalendar(2025, 2025, FixedHolidays, FloatingHolidays)

	for _, tt := range tests {
		t.Run(tt.start+"_"+strconv.Itoa(tt.n), func(t *testing.T) {
			start, _ := time.Parse(time.RFC3339, tt.start)
			got := cal.GetNthBankDayBefore(start, tt.n)
			want, _ := time.Parse(time.RFC3339, tt.want)
			if !got.Equal(want) {
				t.Errorf("For %d days before %s got %s, want %s", tt.n, tt.start, got.Format(time.RFC3339), want.Format(time.RFC3339))
			}
		})
	}
}
