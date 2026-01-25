package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"maps"
	"math/rand"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type SMSSender interface {
	CurlString(to, text string) string
	Send(to, text string) error
}

type SMSMessage struct {
	Name     string
	Number   string
	Template string
	Vars     map[string]string
	Text     string
}

type TextMessage struct {
	Text string `json:"text"`
}

type Payload struct {
	TextMessage  TextMessage `json:"textMessage"`
	PhoneNumbers []string    `json:"phoneNumbers"`
	Priority     int         `json:"priority,omitempty"`
}

var ErrInvalidClockFormat = fmt.Errorf("invalid clock time, ex: '06:00 PM', '6pm', or '18:00' (space and case insensitive)")
var ErrInvalidClockTime = fmt.Errorf("invalid hour or minute, for example '27:63 p' would not be valid")
var ErrPhoneEmpty = fmt.Errorf("no phone number")
var ErrPhoneInvalid11 = fmt.Errorf("invalid 11-digit number (does not start with 1)")
var ErrPhoneInvalid12 = fmt.Errorf("invalid 12-digit number (does not start with +1)")
var ErrPhoneInvalidLength = fmt.Errorf("invalid number length (should be 10 digits or 12 with +1 prefix)")

type MainConfig struct {
	csvPath     string
	dryRun      bool
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
	fgRed      = "\033[31m"
	textErr    = textBold + fgRed
	textWarn   = textBold + fgYellow
	textPrompt = fgBlue
)

func main() {
	var err error
	cfg := MainConfig{
		maxDelay: 2 * time.Minute,
	}

	_ = godotenv.Load("./.env")

	// note: we could also use twilio, or whatever
	var sender SMSSender = &SMSGatewayForAndroid{
		baseURL:  os.Getenv("SMSGW_BASEURL"),
		username: os.Getenv("SMSGW_USERNAME"),
		password: os.Getenv("SMSGW_PASSWORD"),
	}

	// TODO add days of week
	// TODO add start time zone and end time zone for whole country (e.g. 9am ET to 8pm PT)
	now := time.Now()
	zoneName, offset := now.Zone()

	flag.BoolVar(&cfg.confirmed, "y", false, "Confirm without prompting")
	flag.BoolVar(&cfg.verbose, "verbose", false, "Show parse warnings and other debug info")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "Print curl commands instead of sending messages")
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
			fmt.Fprintf(os.Stderr, "%sError%s: could not use --start-time %q: %v\n", textErr, textReset, cfg.startClock, err)
			os.Exit(1)
		}
		cfg.endTime, err = parseClock(cfg.endClock, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError%s: could not use --end-time %q: %v\n", textErr, textReset, cfg.endClock, err)
			os.Exit(1)
		}
		if cfg.startTime.After(cfg.endTime) || cfg.startTime.Equal(cfg.endTime) {
			fmt.Fprintf(os.Stderr,
				"%sError%s: no time between --start-time %q and --end-time %q\n", textErr, textReset, cfg.startTime, cfg.endTime)
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
		fmt.Fprintf(os.Stderr, "%sError%s: %v\n", textErr, textReset, err)
		os.Exit(1)
	}
	defer func() {
		_ = file.Close()
	}()
	csvr := csv.NewReader(file)
	csvr.FieldsPerRecord = -1

	messages, warns, err := cfg.LaxParseCSV(csvr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if len(warns) > 0 {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "%sWarning%s: skipped %d rows with too few fields, invalid numbers, bad templates, etc\n", textWarn, textReset, len(warns))
		if !cfg.verbose {
			fmt.Fprintf(os.Stderr, "         (pass --verbose to show warnings)\n")
		}
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "\n")
			for _, warn := range warns {
				fmt.Fprintf(os.Stderr, "Skip: %s\n", warn.Message)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")
	}
	fmt.Fprintf(os.Stderr, "Info: messages to send: %d\n", len(messages))

	if now.After(cfg.endTime) || now.Equal(cfg.endTime) {
		fmt.Fprintf(os.Stderr, "%sWarning%s: Too late now. %sWaiting until tomorrow%s:\n", textWarn, textReset, textWarn, textReset)

		cfg.startTime = safeSetTomorrow(cfg.startTime)
		cfg.endTime = safeSetTomorrow(cfg.endTime)

		// check for issues caused by daylight savings
		if cfg.startTime.After(cfg.endTime) || cfg.startTime.Equal(cfg.endTime) {
			fmt.Fprintf(os.Stderr,
				"%sError%s: no time between --start-time %q and --end-time %q\n",
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
			fmt.Fprintf(os.Stderr, "Info: start time was %s (%s ago)\n", cfg.startTime.Format("3:04pm"), startAgo.Round(time.Second))
		} else {
			startAgo *= -1
			fmt.Fprintf(os.Stderr, "Info: start time is %s (%s from now)\n", cfg.startTime.Format("3:04pm"), startAgo.Round(time.Second))
		}
		fmt.Fprintf(os.Stderr, "Info: end time is %s (%s from now)\n", cfg.endTime.Format("3:04pm"), cfg.duration.Round(time.Second))
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

	fmt.Fprintf(os.Stderr, "Info: average delay between messages: %s\n", cfg.delay.Round(time.Second))
	quarterDelay := cfg.delay / 4
	baseDelay := quarterDelay * 3
	jitter := int64(quarterDelay * 2)
	fmt.Fprintf(os.Stderr,
		"      (%s minimum + %s jitter)\n",
		baseDelay.Round(time.Millisecond), time.Duration(jitter).Round(time.Millisecond),
	)

	if len(messages) == 0 {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "%sError%s: no messages to send\n", textErr, textReset)
		os.Exit(1)
	}

	if !cfg.confirmed && !cfg.dryRun {
		fmt.Fprintf(os.Stderr, "\n")
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
				fmt.Fprintf(os.Stderr, "%sError%s: Oh, look at the time. Ending now. (%d messages remaining)\n", textErr, textReset, left)
				os.Exit(1)
				return
			}
		}

		var delay time.Duration
		{
			ns := int64(baseDelay) + rand.Int63n(jitter)
			delay = time.Duration(ns)
		}

		if cfg.dryRun {
			fmt.Printf("sleep %s\n\n", delay)
		} else if i > 0 {
			time.Sleep(delay)
		}

		fmt.Fprintf(os.Stderr, "# Send to %s (%s) %s-%s\n", message.Number[:2], message.Number[2:5], message.Number[5:8], message.Number[8:])
		if cfg.dryRun {
			fmt.Println(message.Text)
			// curl := sender.CurlString(message.Number, message.Text)
			// fmt.Println(curl)
			continue
		}

		if err := sender.Send(message.Number, message.Text); err != nil {
			fmt.Fprintf(os.Stderr, "%sError%s: %v\n", textErr, textReset, err)
			continue
		}
	}

	fmt.Fprintf(os.Stderr, "finished at %s", time.Now())
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

// we're not just skipping symbols,
// we're also eliminating non-printing characters copied from HTML and such
func cleanPhoneNumber(raw string) string {
	var cleaned strings.Builder
	for i, char := range raw {
		if (i == 0 && char == '+') || (char >= '0' && char <= '9') {
			cleaned.WriteRune(char)
		}
	}
	return cleaned.String()
}

func (cfg *MainConfig) validateAndFormatNumber(number string) (string, error) {
	switch len(number) {
	case 0:
		return "", ErrPhoneEmpty
	case 10:
		return "+1" + number, nil
	case 11:
		if strings.HasPrefix(number, "1") {
			return "+" + number, nil
		}
		return "", fmt.Errorf("%w: %s", ErrPhoneInvalid11, number)
	case 12:
		if strings.HasPrefix(number, "+1") {
			return number, nil
		}
		return "", fmt.Errorf("%w: %s", ErrPhoneInvalid12, number)
	default:
		return "", fmt.Errorf("%w: %s", ErrPhoneInvalidLength, number)
	}
}

func GetFieldIndex(header []string, name string) int {
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i
		}
	}
	return -1
}

type CSVWarn struct {
	Index   int
	Code    string
	Message string
	Record  []string
}

var reUnmatchedVars = regexp.MustCompile(`\{[^}]+\}`)

func (cfg *MainConfig) LaxParseCSV(csvr *csv.Reader) (messages []SMSMessage, warns []CSVWarn, err error) {
	header, err := csvr.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("header could not be parsed: %w", err)
	}

	FIELD_NAME := GetFieldIndex(header, "Name")
	FIELD_PHONE := GetFieldIndex(header, "Phone")
	FIELD_MESSAGE := GetFieldIndex(header, "Message")
	if FIELD_NAME == -1 || FIELD_PHONE == -1 || FIELD_MESSAGE == -1 {
		return nil, nil, fmt.Errorf("header is missing one or more of 'Preferred', 'Phone', and/or 'Message'")
	}
	FIELD_MIN := 1 + slices.Max([]int{FIELD_NAME, FIELD_PHONE, FIELD_MESSAGE})

	rowIndex := 1 // 1-index, start at header
	for {
		rowIndex++
		rec, err := csvr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse row %d (and all following rows): %w", rowIndex, err)
		}

		if len(rec) < FIELD_MIN {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "TooFewFields",
				Message: fmt.Sprintf("ignoring row %d: too few fields (want %d, have %d)", rowIndex, FIELD_MIN, len(rec)),
				Record:  rec,
			})
			continue
		}

		vars := make(map[string]string)
		n := min(len(header), len(rec))
		for i := range n {
			switch i {
			case FIELD_NAME, FIELD_PHONE, FIELD_MESSAGE:
				continue
			default:
				key := header[i]
				val := rec[i]
				vars[key] = val
			}
		}

		message := SMSMessage{
			Name:     strings.TrimSpace(rec[FIELD_NAME]),
			Number:   strings.TrimSpace(rec[FIELD_PHONE]),
			Template: strings.TrimSpace(rec[FIELD_MESSAGE]),
			Vars:     vars,
			Text:     strings.TrimSpace(rec[FIELD_MESSAGE]),
		}

		keyIter := maps.Keys(message.Vars)
		keys := slices.Sorted(keyIter)
		for _, key := range keys {
			val := message.Vars[key]
			message.Text = replaceVar(message.Text, key, val)
		}

		if reUnmatchedVars.MatchString(message.Text) {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "UnmatchedVars",
				Message: fmt.Sprintf("ignoring row %d: leftover template variables (e.g. {VarName})", rowIndex),
				Record:  rec,
			})
			continue
		}

		message.Number = cleanPhoneNumber(message.Number)
		message.Number, err = cfg.validateAndFormatNumber(message.Number)
		if err != nil {
			warns = append(warns, CSVWarn{
				Index:   rowIndex,
				Code:    "PhoneInvalid",
				Message: fmt.Sprintf("ignoring row %d (%s): %s", rowIndex, message.Name, err.Error()),
				Record:  rec,
			})
			continue
		}

		messages = append(messages, message)
	}

	return messages, warns, nil
}

func replaceVar(text, key, val string) string {
	if val != "" {
		// No special treatment:
		// "Hey {+Name}," => "Hey Doe,"
		// "Bob,{Name}" => "Bob,Doe"
		// "{Name-},Joe" => "Doe,Joe"
		// "Hi {-Name-}, Joe" => "Hi Doe, Joe"
		var reHasVar = regexp.MustCompile(fmt.Sprintf(`\{\+?%s-?\}`, regexp.QuoteMeta(key)))
		return reHasVar.ReplaceAllString(text, val)
	}

	var metaKey = regexp.QuoteMeta(key)

	// "Hey {+Name}," => "Hey ,"
	var reEatNone = regexp.MustCompile(fmt.Sprintf(`\{\+%s\}`, metaKey))
	text = reEatNone.ReplaceAllString(text, val)

	// "Bob,{Name};" => "Bob;"
	var reEatOneLeft = regexp.MustCompile(fmt.Sprintf(`.?\{%s\}`, metaKey))
	text = reEatOneLeft.ReplaceAllString(text, val)

	// ",{Name-};Joe" => ",Joe"
	var reEatOneRight = regexp.MustCompile(fmt.Sprintf(`\{%s-\}.?`, metaKey))
	text = reEatOneRight.ReplaceAllString(text, val)

	// "Hi {-Name-}, Joe" => "Hi Joe"
	var reEatOneBoth = regexp.MustCompile(fmt.Sprintf(`.?\{-%s-\}.?`, metaKey))
	text = reEatOneBoth.ReplaceAllString(text, val)

	return text
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
				return t, ErrInvalidClockFormat
			}
		}
		fallthrough
	case 1:
		hourStr := parts[0]
		hourStr = strings.TrimLeft(hourStr, "0")
		if len(hourStr) > 0 {
			hour, err = strconv.Atoi(hourStr)
			if err != nil {
				return t, ErrInvalidClockFormat
			}
		}
	default:
		return t, ErrInvalidClockFormat
	}

	if hour < 0 || hour > 23 || min < 0 || min > 59 {
		return t, ErrInvalidClockTime
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
