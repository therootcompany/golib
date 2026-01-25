package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/therootcompany/golib/net/smsgw"
	"github.com/therootcompany/golib/net/smsgw/androidsmsgateway"
	"github.com/therootcompany/golib/net/smsgw/smscsv"
)

type MainConfig struct {
	csvPath     string
	dryRun      bool
	printCurl   bool
	shuffle     bool
	startClock  string
	startTime   time.Time
	runTime     time.Time
	endClock    string
	endTime     time.Time
	maxDuration time.Duration
	duration    time.Duration
	minDelay    time.Duration
	maxDelay    time.Duration
	delay       time.Duration
	verbose     bool
	confirmed   bool
}

const (
	textReset  = "\033[0m"
	textBold   = "\033[1m"
	fgYellow   = "\033[33m"
	fgBlue     = "\033[34m"
	fgGreen    = "\033[32m"
	fgRed      = "\033[31m"
	textErr    = textBold + fgRed
	textWarn   = textBold + fgYellow
	textInfo   = fgYellow
	textTmpl   = fgGreen
	textPrompt = fgBlue
)

func main() {
	var err error
	cfg := MainConfig{
		maxDelay: 2 * time.Minute,
	}

	_ = godotenv.Load("./.env")

	// note: we could also use twilio, or whatever
	var sender smsgw.Gateway = androidsmsgateway.New(
		os.Getenv("SMSGW_BASEURL"),
		os.Getenv("SMSGW_USERNAME"),
		os.Getenv("SMSGW_PASSWORD"),
	)

	// TODO add days of week
	// TODO add start time zone and end time zone for whole country (e.g. 9am ET to 8pm PT)
	now := time.Now()
	zoneName, offset := now.Zone()

	flag.BoolVar(&cfg.confirmed, "y", false, "Confirm without prompting")
	flag.BoolVar(&cfg.verbose, "verbose", false, "Show parse warnings and other debug info")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "Skip sending messages and sleeping, runs without confirmation")
	flag.BoolVar(&cfg.printCurl, "print-curl", false, "Show full curl commands instead of messages")
	flag.StringVar(&cfg.csvPath, "csv", "./messages.csv", "Path to file with newline-delimited phone numbers")
	flag.BoolVar(&cfg.shuffle, "shuffle", false, "Randomize the list")
	flag.StringVar(&cfg.startClock, "start-time", "10am", "don't send messages before this time (e.g. 10:00, 10am, 00:00)")
	flag.StringVar(&cfg.endClock, "end-time", "8:30pm", "don't send messages after this time (e.g. 4pm, 23:59)")
	flag.DurationVar(&cfg.maxDuration, "max-duration", 0, "don't send messages for more than this long (e.g. 10m, 2h30m, 6h)")
	flag.DurationVar(&cfg.minDelay, "min-delay", 0, "don't send messages closer together on average than this (e.g. 10s, 2m) (Default: 20s)")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "Info: Time zone: %s, Offset: %.2fh\n", zoneName, float64(offset)/3600)
	// os.Exit(1)

	// now, startTime, and endTime checks
	{
		cfg.startTime, err = parseClock(cfg.startClock, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%sError%s: could not use --start-time %q: %v\n", textErr, textReset, cfg.startClock, err)
			os.Exit(1)
		}
		cfg.endTime, err = parseClock(cfg.endClock, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%sError%s: could not use --end-time %q: %v\n", textErr, textReset, cfg.endClock, err)
			os.Exit(1)
		}
		if cfg.startTime.After(cfg.endTime) || cfg.startTime.Equal(cfg.endTime) {
			fmt.Fprintf(os.Stderr,
				"\n%sError%s: no time between --start-time %q and --end-time %q\n", textErr, textReset, cfg.startTime, cfg.endTime)
			os.Exit(1)
		}
	}

	if cfg.minDelay == 0 {
		cfg.minDelay = 20 * time.Second
	}
	if cfg.maxDelay < cfg.minDelay {
		cfg.maxDelay = cfg.minDelay
	}

	fmt.Fprintf(os.Stderr, "Info: opening, reading, and parsing %q\n", cfg.csvPath)
	file, err := os.Open(cfg.csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%sError%s: %v\n", textErr, textReset, err)
		os.Exit(1)
	}
	defer func() {
		_ = file.Close()
	}()
	csvr := csv.NewReader(file)
	csvr.FieldsPerRecord = -1

	messages, warns, err := smscsv.ReadOrIgnoreAll(csvr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%sError%s: %v\n", textErr, textReset, err)
		os.Exit(1)
	}
	if len(warns) > 0 {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "%sWarning%s: skipped %d rows with missing or invalid data\n", textWarn, textReset, len(warns))
		if !cfg.verbose {
			fmt.Fprintf(os.Stderr, "         (pass --verbose for more detail)\n")
		}
		if cfg.verbose {
			for _, warn := range warns {
				fmt.Fprintf(os.Stderr, "   Skip: %s\n", warn.Message)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}
	fmt.Fprintf(os.Stderr, "Info: list of %d messages\n", len(messages))

	if now.After(cfg.endTime) || now.Equal(cfg.endTime) {
		fmt.Fprintf(os.Stderr, "%sWarning%s: Too late now. %sWaiting until tomorrow%s:\n", textWarn, textReset, textWarn, textReset)

		cfg.startTime = safeSetTomorrow(cfg.startTime)
		cfg.endTime = safeSetTomorrow(cfg.endTime)

		// check for issues caused by daylight savings
		if cfg.startTime.After(cfg.endTime) || cfg.startTime.Equal(cfg.endTime) {
			fmt.Fprintf(os.Stderr,
				"\n%sError%s: no time between --start-time %q and --end-time %q\n",
				textErr, textReset,
				cfg.startTime, cfg.endTime,
			)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "         %s\n\n", cfg.startTime)
	}
	if now.Before(cfg.startTime) {
		fmt.Fprintf(os.Stderr, "\n%sWarning%s: It's too early now. %sWaiting until %s.%s\n\n", textWarn, textReset, textWarn, cfg.startTime.Format("3:04pm"), textReset)
	}

	cfg.runTime = now
	if cfg.startTime.After(now) {
		cfg.runTime = cfg.startTime
	}

	// duration
	{
		cfg.duration = cfg.endTime.Sub(cfg.runTime)
		if cfg.maxDuration != 0 {
			if cfg.maxDuration < cfg.duration {
				cfg.duration = cfg.maxDuration
			}
		}
		var startAgo = now.Sub(cfg.startTime)
		if startAgo >= 0 {
			fmt.Fprintf(os.Stderr, "Info: start after %s         (%s ago)\n", cfg.startTime.Format("3:04pm"), startAgo.Round(time.Second))
		} else {
			startAgo *= -1
			fmt.Fprintf(os.Stderr, "Info: start after %s         (%s from now)\n", cfg.startTime.Format("3:04pm"), startAgo.Round(time.Second))
		}
		fmt.Fprintf(os.Stderr, "Info: end around %s          (%s from now)\n", cfg.endTime.Format("3:04pm"), cfg.duration.Round(time.Second))
	}

	// delay
	{
		n := len(messages)
		// add a small buffer so we complete in the time, even with randomness
		n += 2
		cfg.delay = cfg.duration / time.Duration(n)
		if cfg.delay < cfg.minDelay {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "%sWarning%s: cannot send all %d messages in %s (would require 1 message every %s)\n", textWarn, textReset, len(messages), cfg.duration.Round(time.Second), cfg.delay.Round(time.Millisecond))
			fmt.Fprintf(os.Stderr, "         (we'll just %ssend what we can%s for now, 1 every %s)\n", textWarn, textReset, cfg.minDelay)
			fmt.Fprintf(os.Stderr, "\n")
			cfg.delay = cfg.minDelay
		}
		if cfg.delay > cfg.maxDelay {
			cfg.delay = cfg.maxDelay
		}

		// add a small buffer to allow for a final message, with randomness
		cfg.duration = cfg.duration + cfg.delay + cfg.delay
	}

	r := rand.New(rand.NewSource(37))
	if cfg.shuffle {
		r.Shuffle(len(messages), func(i, j int) {
			messages[i], messages[j] = messages[j], messages[i]
		})
	}

	quarterDelay := cfg.delay / 4
	baseDelay := quarterDelay * 3
	jitter := int64(quarterDelay * 2)
	fmt.Fprintf(os.Stderr,
		"Info: delay %s between messages  (%s + %s jitter)\n",
		cfg.delay.Round(time.Second), baseDelay.Round(time.Millisecond), time.Duration(jitter).Round(time.Millisecond),
	)

	if len(messages) == 0 {
		fmt.Fprintf(os.Stderr, "\n%sError%s: no messages to send\n", textErr, textReset)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Info: This is what a %ssample message%s from list look like:\n", textInfo, textReset)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "      To: %s (%s)\n", messages[0].Number, messages[0].Name)
	fmt.Fprintf(os.Stderr, "      %s%s%s\n", textTmpl, messages[0].Template, textReset)
	fmt.Fprintf(os.Stderr, "      %s%s%s\n", textInfo, messages[0].Text, textReset)
	fmt.Fprintf(os.Stderr, "\n")

	if !cfg.confirmed && !cfg.dryRun {
		if !confirmContinue() {
			fmt.Fprintf(os.Stderr, "%scanceled%s\n", textErr, textReset)
			os.Exit(1)
			return
		}
	}

	// if there was a delay
	diff := cfg.startTime.Sub(now)
	if diff > 0 {
		fmt.Fprintf(os.Stderr, "\n%sWarning%s: It's too early now. %sWaiting until %s.%s\n", textWarn, textReset, textWarn, cfg.startTime.Format("3:04pm"), textReset)
		time.Sleep(diff)
		fmt.Fprintf(os.Stderr, "\n")
	}

	deadline := now.Add(cfg.duration)
	for i, message := range messages {
		now := time.Now()
		if now.After(deadline) {
			cur := i + 1
			last := len(messages)
			left := last - cur
			if left > 0 {
				fmt.Fprintf(os.Stderr, "\n%sError%s: Oh, look at the time. Ending now. (%d messages remaining)\n", textErr, textReset, left)
				os.Exit(1)
				return
			}
		}

		var delay time.Duration
		{
			ns := int64(baseDelay) + rand.Int63n(jitter)
			delay = time.Duration(ns)
		}

		if i > 0 {
			if cfg.dryRun || cfg.printCurl {
				fmt.Printf("sleep %s\n\n", delay.Round(time.Millisecond))
			} else {
				time.Sleep(delay)
			}
		}

		fmt.Fprintf(os.Stderr, "# Send to %s (%s) %s-%s\n", message.Number[:2], message.Number[2:5], message.Number[5:8], message.Number[8:])
		if cfg.printCurl {
			curl := sender.CurlString(message.Number, message.Text)
			fmt.Println(curl)
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", message.Text)
		}
		if cfg.dryRun {
			continue
		}

		if err := sender.Send(message.Number, message.Text); err != nil {
			fmt.Fprintf(os.Stderr, "%sError%s: %v\n", textErr, textReset, err)
			continue
		}
	}

	fmt.Fprintf(os.Stderr, "\nInfo: finished at %s\n", time.Now())
}

func confirmContinue() bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf(textPrompt + "Continue? [y/N] " + textReset)
		input, err := reader.ReadString('\n')
		if err != nil {
			return false // EOF or error → treat as no
		}

		input = strings.TrimSpace(strings.ToLower(input))

		switch input {
		case "y", "yes":
			return true
		case "", "n", "no":
			return false
		default:
			fmt.Fprintf(os.Stderr, "%sError%s: please answer y or n", textErr, textReset)
			// loop again
		}
	}
}

// set by day rather than time to account for daylight savings
func safeSetTomorrow(ref time.Time) time.Time {
	return time.Date(ref.Year(), ref.Month(), 1+ref.Day(), ref.Hour(), ref.Minute(), 0, 0, ref.Location())
}

// parseClock parses "10am", "10:00", "22:30", etc. into today's date + that time
func parseClock(s string, ref time.Time) (t time.Time, err error) {
	// "10:05 AM" => "10:05am"
	// "10 AM" => "10am"
	// "23:05" => "23:05"
	// "00" => "00"
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")

	var hour, min int
	var ampm string

	// "10:05am" => "10:05"
	// "10am" => "10"
	// "23:05" => "23:05"
	// "00" => "00"
	if strings.HasSuffix(s, "am") {
		ampm = "am"
		s = strings.TrimSuffix(s, "am")
	} else if strings.HasSuffix(s, "pm") {
		ampm = "pm"
		s = strings.TrimSuffix(s, "pm")
	}

	// "10:05" => {hour: 10, minute: 5}
	// "10" => {hour: 10, minute: 0}
	// "00" => {hour: 0, minute: 0}
	// "23:05" => "23:05"
	// "00" => "00"
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 2:
		minStr := parts[1]
		minStr = strings.TrimLeft(minStr, "0")
		if len(minStr) > 0 {
			min, err = strconv.Atoi(minStr)
			if err != nil {
				return t, smsgw.ErrInvalidClockFormat
			}
		}
		fallthrough
	case 1:
		hourStr := parts[0]
		hourStr = strings.TrimLeft(hourStr, "0")
		if len(hourStr) > 0 {
			hour, err = strconv.Atoi(hourStr)
			if err != nil {
				return t, smsgw.ErrInvalidClockFormat
			}
		}
	default:
		return t, smsgw.ErrInvalidClockFormat
	}

	if hour < 0 || hour > 23 || min < 0 || min > 59 {
		return t, smsgw.ErrInvalidClockTime
	}

	switch ampm {
	case "pm":
		if hour < 12 {
			hour += 12
		}
	case "am":
		if hour == 12 {
			hour = 0
		}
	case "":
		// no change
	default:
		panic(fmt.Errorf("impossible condition: ampm set to %q", ampm))
	}

	t = time.Date(ref.Year(), ref.Month(), ref.Day(), hour, min, 0, 0, ref.Location())
	return t, nil
}
