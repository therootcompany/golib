package calendar

import (
	"time"
)

// FixedHolidays contains US Federal holidays should include both fixed date and pre-calculated holidays.
// For example: Lunar Holidays, such as Easter, should be included manually here,
// as it is no simple feat to calculate them - they are not accurate to the day
// unless using sophisticated algorithms tracking gravitational pull of the Sun,
// Earth, Moon, and planets, etc - really.
// See https://en.wikipedia.org/wiki/Public_holidays_in_the_United_States#Federal_holidays
// See also https://calendarholidays.net/2025-citibank-holidays/
var FixedHolidays = []FixedDate{
	{time.January, 1, "New Year's Day"},
	{time.June, 19, "Juneteenth"},
	{time.July, 4, "Independence Day"},
	{time.October, 11, "Veterans Day"},
	{time.December, 24, "Christmas Eve"}, // non-Federal, but observed by some banks
	{time.December, 25, "Christmas"},
	{time.December, 31, "New Year's Eve"}, // non-Federal, but observed by some banks
}

// FloatingHolidays are based on 1st, 2nd, 3rd, 4th, or last of a given weekday.
// See https://en.wikipedia.org/wiki/Public_holidays_in_the_United_States#Federal_holidays
// See also https://calendarholidays.net/2025-citibank-holidays/
var FloatingHolidays = []FloatingDate{
	{3, time.Monday, time.January, "Martin Luther King Day"},
	{3, time.Monday, time.February, "Presidents Day"},
	{-1, time.Monday, time.May, "Memorial Day"},
	{1, time.Monday, time.September, "Labor Day"},
	{2, time.Monday, time.October, "Columbus Day"},
	{4, time.Thursday, time.November, "Thanksgiving Day"},
	{4, time.Friday, time.November, "Black Friday"}, // non-Federal, but some banks close early
}
