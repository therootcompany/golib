package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/therootcompany/golib/time/calendar"
)

func main() {
	t := time.Now()
	dateStr := t.Format(time.RFC3339)
	tz, _ := t.Local().Zone() // ignore offset for now
	flag.StringVar(&tz, "timezone", tz, "timezone (e.g. America/Denver)")
	flag.StringVar(&dateStr, "datetime", dateStr, "date (RFC3339, use 'Z' for timezone)")
	flag.Parse()

	var err error
	t, err = time.Parse(time.RFC3339, dateStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid date: %v\n", err)
		os.Exit(1)
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid tz: %v\n", err)
		os.Exit(1)
	}
	t = t.In(loc)

	nth := calendar.NthWeekday(t)
	fmt.Printf("%s is the %d%s %s of the month\n",
		t.Format("2006-01-02 (Mon)"),
		nth,
		calendar.GetSuffixEnglish(nth),
		t.Weekday(),
	)
}
