package calendar

import (
	"time"
)

func GetSuffixEnglish(n int) string {
	if n%100 >= 11 && n%100 <= 13 {
		return "th"
	}
	switch n % 10 {
	case 1:
		return "st"
	case 2:
		return "nd"
	case 3:
		return "rd"
	default:
		return "th"
	}
}

// Returns which nth weekday of the month the target date is (e.g. 2nd Tuesday)
func NthWeekday(t time.Time) int {
	_, _, date := t.Date()
	nth := date / 7
	nthMod := date % 7
	if nthMod != 0 {
		nth += 1
	}

	return nth
}

func NthWeekdayFromEnd(t time.Time) int {
	_, _, day := t.Date()
	lastDay := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, t.Location()).Day()
	return (lastDay-day)/7 + 1
}

// GetNthWeekday can find the 1st, 2nd, 3rd, 4th (and sometimes 5th) Monday, etc of the given month
func GetNthWeekday(year int, month time.Month, weekday time.Weekday, n int) (time.Time, bool) {
	var mOffset time.Month
	nOffset := 1
	if n < 0 {
		mOffset = 1
		nOffset = 0
	}

	// First day of month
	first := time.Date(year, mOffset+month, 1, 0, 0, 0, 0, time.UTC)
	wd := first.Weekday()

	// Days to first target weekday
	daysToAdd := int(weekday - wd)
	if daysToAdd < 0 {
		daysToAdd += 7
	}

	// First occurrence
	firstOcc := first.AddDate(0, 0, daysToAdd)

	// nth occurrence
	target := firstOcc.AddDate(0, 0, (n-nOffset)*7)

	// Check if still in same month
	if target.Month() != month {
		return time.Time{}, false
	}

	return target, true
}

type Year = int

type YearlyDate struct {
	Month time.Month
	Day   int
}

type YearlyCalendar map[YearlyDate]struct{}

type MultiYearCalendar map[Year]YearlyCalendar

func NewMultiYearCalendar(startYear, endYear int, fixed []FixedDate, floating []FloatingDate) MultiYearCalendar {
	var mcal = make(MultiYearCalendar)
	for year := startYear; year <= endYear; year++ {
		mcal[year] = make(YearlyCalendar)
		for _, fixedDate := range fixed {
			date := YearlyDate{fixedDate.Month, fixedDate.Day}
			mcal[year][date] = struct{}{}
		}
		for _, floatingDate := range floating {
			date := floatingDate.ToDate(year)
			mcal[year][date] = struct{}{}
		}
	}
	return mcal
}

type FixedDate struct {
	Month time.Month
	Day   int
	Name  string
}

type FloatingDate struct {
	Nth     int
	Weekday time.Weekday
	Month   time.Month
	Name    string
}

func (d FloatingDate) ToDate(year int) YearlyDate {
	t, _ := GetNthWeekday(year, d.Month, d.Weekday, d.Nth)
	_, month, day := t.Date()
	return YearlyDate{month, day}
}

// Reserved. DO NOT USE. For the time being, Easter, Moon cycles, moveable feasts and such must be entered manually
type LunisolarHoliday struct{}

func (h MultiYearCalendar) IsBusinessDay(t time.Time) bool {
	if wd := t.Weekday(); wd == time.Saturday || wd == time.Sunday {
		return false
	}
	_, ok := h[t.Year()][YearlyDate{t.Month(), t.Day()}]
	return !ok
}

// GetBankDaysBefore calculates business days is useful for calculating transactions that must occur such
// that they will complete by the target date. For example, if you want money to be in
// your account by the 15th each month, and the transfer takes 3 business days, and this
// month's 15th is a Monday that happens to be a holiday, this would return the previous
// Tuesday.
func (h MultiYearCalendar) GetNthBankDayBefore(t time.Time, n int) time.Time {
	if !h.IsBusinessDay(t) {
		n++
	}
	for n > 0 {
		t = t.AddDate(0, 0, -1)
		if h.IsBusinessDay(t) {
			n--
		}
	}
	return t
}
