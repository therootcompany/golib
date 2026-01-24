package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type SMSSender struct {
	baseURL  string
	user     string
	password string
}

type SMSMessage struct {
	FirstName       string
	PhoneNumber     string
	MessageTemplate string
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

type MainConfig struct {
	csvPath     string
	dryRun      bool
	shuffle     bool
	startClock  string
	startTime   time.Time
	endClock    string
	endTime     time.Time
	maxDuration time.Duration
	duration    time.Duration
	minDelay    time.Duration
	maxDelay    time.Duration
	delay       time.Duration
	verbose     bool
}

func main() {
	var err error
	cfg := MainConfig{
		maxDelay: 2 * time.Minute,
	}

	_ = godotenv.Load("./.env")
	sender := &SMSSender{
		baseURL:  os.Getenv("SMSGW_BASEURL"),
		user:     os.Getenv("SMSGW_USER"),
		password: os.Getenv("SMSGW_PASSWORD"),
	}

	// TODO add days of week
	// TODO add start time zone and end time zone for whole country (e.g. 9am ET to 8pm PT)
	now := time.Now()
	zoneName, offset := now.Zone()

	flag.BoolVar(&cfg.dryRun, "dry-run", false, "Print curl commands instead of sending messages")
	flag.StringVar(&cfg.csvPath, "csv", "./messages.csv", "Path to file with newline-delimited phone numbers")
	flag.BoolVar(&cfg.shuffle, "shuffle", false, "Randomize the list")
	flag.StringVar(&cfg.startClock, "start-time", "10am", "don't send messages before this time (e.g. 10:00, 10am, 00:00)")
	flag.StringVar(&cfg.endClock, "end-time", "8:30pm", "don't send messages after this time (e.g. 4pm, 23:59)")
	flag.DurationVar(&cfg.maxDuration, "max-duration", 0, "don't send messages for more than this long (e.g. 10m, 2h30m, 6h)")
	flag.DurationVar(&cfg.minDelay, "min-delay", 0, "don't send messages closer together on average than this (e.g. 10s, 2m) (Default: 20s)")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "Current time zone: %s, Offset: %.2fh\n", zoneName, float64(offset)/3600)
	// os.Exit(1)

	// now, startTime, and endTime checks
	{
		cfg.startTime, err = parseClock(cfg.startClock, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not use --start-time %q: %v\n", cfg.startClock, err)
			os.Exit(1)
		}
		cfg.endTime, err = parseClock(cfg.endClock, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: could not use --end-time %q: %v\n", cfg.endClock, err)
			os.Exit(1)
		}
		if cfg.startTime.After(cfg.endTime) || cfg.startTime.Equal(cfg.endTime) {
			fmt.Fprintf(os.Stderr,
				"Error: no time between --start-time %q and --end-time %q\n",
				cfg.startTime, cfg.endTime,
			)
			os.Exit(1)
		}
	}

	if cfg.minDelay == 0 {
		cfg.minDelay = 20 * time.Second
	}
	if cfg.maxDelay < cfg.minDelay {
		cfg.maxDelay = cfg.minDelay
	}

	file, err := os.Open(cfg.csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %q could not be read\n", cfg.csvPath)
		os.Exit(1)
	}
	defer func() {
		_ = file.Close()
	}()
	csvr := csv.NewReader(file)
	csvr.FieldsPerRecord = -1
	messages, err := cfg.LaxParseCSV(csvr, cfg.csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "\nInfo: parsed %q\n\n", cfg.csvPath)

	if now.After(cfg.endTime) || now.Equal(cfg.endTime) {
		fmt.Fprintf(os.Stderr, "Too late now. Waiting until tomorrow:\n")

		cfg.startTime = safeSetTomorrow(cfg.startTime)
		cfg.endTime = safeSetTomorrow(cfg.endTime)

		// check for issues caused by daylight savings
		if cfg.startTime.After(cfg.endTime) || cfg.startTime.Equal(cfg.endTime) {
			fmt.Fprintf(os.Stderr,
				"Error: no time between --start-time %q and --end-time %q\n",
				cfg.startTime, cfg.endTime,
			)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "\t%s\n", cfg.startTime)
	} else {
		cfg.startTime = now
	}

	{
		// duration, delay
		cfg.duration = cfg.endTime.Sub(cfg.startTime)
		if cfg.maxDuration != 0 {
			if cfg.maxDuration < cfg.duration {
				cfg.duration = cfg.maxDuration
			}
		}
		n := len(messages)
		// add a small buffer so we complete in the time, even with randomness
		n += 2
		cfg.delay = cfg.duration / time.Duration(n)
		if cfg.delay < cfg.minDelay {
			fmt.Fprintf(os.Stderr, "Warn: cannot send all %d messages in %s (would require 1 message every %s)\n", len(messages), cfg.duration, cfg.delay)
			fmt.Fprintf(os.Stderr, "      (we'll just send what we can for now, 1 every %s)\n", cfg.minDelay)
			cfg.delay = cfg.minDelay
		}
		if cfg.delay > cfg.maxDelay {
			cfg.delay = cfg.maxDelay
		}
		// add a small buffer to allow for a final message, with randomness
		cfg.duration = cfg.duration + cfg.delay + cfg.delay
		fmt.Fprintf(os.Stderr, "Info: sending for the next %s\n", cfg.duration.Round(time.Second))
	}

	// if there was a delay
	diff := cfg.startTime.Sub(now)
	time.Sleep(diff)

	r := rand.New(rand.NewSource(37))
	if cfg.shuffle {
		r.Shuffle(len(messages), func(i, j int) {
			messages[i], messages[j] = messages[j], messages[i]
		})
	}

	fmt.Fprintf(os.Stderr,
		"Info: sending %d messages, roughly 1 every %s\n",
		len(messages), cfg.delay.Round(time.Second),
	)
	quarterDelay := cfg.delay / 4
	baseDelay := quarterDelay * 3
	jitter := int64(quarterDelay * 2)
	fmt.Fprintf(os.Stderr,
		"      (%s + %s jitter)\n",
		baseDelay.Round(time.Millisecond), time.Duration(jitter).Round(time.Millisecond),
	)

	deadline := now.Add(cfg.duration)
	if cfg.dryRun {
		os.Exit(0)
	}
	for i, message := range messages {
		now := time.Now()
		if now.After(deadline) {
			cur := i + 1
			last := len(messages)
			left := last - cur
			if left > 0 {
				fmt.Printf("Oh, look at the time. Ending now. (%d messages remaining)\n", left)
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

		fmt.Fprintf(os.Stderr, "# Send to %s (%s) %s-%s\n", message.PhoneNumber[:2], message.PhoneNumber[2:5], message.PhoneNumber[5:8], message.PhoneNumber[8:])
		text := strings.ReplaceAll(message.MessageTemplate, "{First}", message.FirstName)
		if cfg.dryRun {
			sender.printDryRun(message.PhoneNumber, text)
			continue
		}
		sender.sendMessage(message.PhoneNumber, text)
	}
}

// set by day rather than time to account for daylight savings
func safeSetTomorrow(ref time.Time) time.Time {
	return time.Date(ref.Year(), ref.Month(), 1+ref.Day(), ref.Hour(), ref.Minute(), 0, 0, ref.Location())
}

func cleanPhoneNumber(raw string) string {
	var cleaned strings.Builder
	for i, char := range raw {
		if (i == 0 && char == '+') || (char >= '0' && char <= '9') {
			cleaned.WriteRune(char)
		}
	}
	return cleaned.String()
}

func (cfg *MainConfig) validateAndFormatNumber(number string) string {
	switch len(number) {
	case 10:
		return "+1" + number
	case 11:
		if strings.HasPrefix(number, "1") {
			return "+" + number
		}
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Warn: invalid 11-digit number '%s'\n", number)
		}
		return ""
	case 12:
		if strings.HasPrefix(number, "+1") {
			return number
		}
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Warn: invalid 12-digit number '%s' does not start with +1\n", number)
		}
		return ""
	default:
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Warn: invalid number length for '%s'\n", number)
		}
		return ""
	}
}

func (s *SMSSender) printDryRun(number, message string) {
	url := s.baseURL + "/messages"
	payload := Payload{
		TextMessage:  TextMessage{Text: message},
		PhoneNumbers: []string{number},
		Priority:     65,
	}
	body := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)

	escapedBody := strings.ReplaceAll(body.String(), "'", "'\\''")

	fmt.Printf("curl --fail-with-body --user '%s:%s' -X POST '%s' \\\n", s.user, s.password, url)
	fmt.Printf("   -H 'Content-Type: application/json' \\\n")
	fmt.Printf("   --data-binary '%s'\n", escapedBody)
}

func (s *SMSSender) sendMessage(number, message string) {
	number = cleanPhoneNumber(number)
	if len(number) == 0 {
		panic(fmt.Errorf("non-sanitized number '%s'", number))
	}

	url := s.baseURL + "/messages"
	payload := Payload{
		TextMessage:  TextMessage{Text: message},
		PhoneNumbers: []string{number},
		Priority:     65,
	}

	body := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)

	req, _ := http.NewRequest("POST", url, body)
	req.SetBasicAuth(s.user, s.password)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("error: failed to send message to '%s': %v\n", number, err)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("error: failed to send message to '%s': %d %s\n", number, resp.StatusCode, string(body))
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

func (cfg *MainConfig) LaxParseCSV(csvr *csv.Reader, csvFile string) ([]SMSMessage, error) {
	header, err := csvr.Read()
	if err != nil {
		return nil, fmt.Errorf("error: %q header could not be parsed: %w", csvFile, err)
	}

	FIELD_NICK := GetFieldIndex(header, "Preferred")
	FIELD_PHONE := GetFieldIndex(header, "Phone")
	FIELD_MESSAGE := GetFieldIndex(header, "Message")
	if FIELD_NICK == -1 || FIELD_PHONE == -1 || FIELD_MESSAGE == -1 {
		return nil, fmt.Errorf("error: %q is missing one or more of 'Preferred', 'Phone', and/or 'Message'", csvFile)
	}
	FIELD_MIN := 1 + slices.Max([]int{FIELD_NICK, FIELD_PHONE, FIELD_MESSAGE})

	var messages []SMSMessage
	rowIndex := 1 // 1-index, start at header
	for {
		rowIndex++
		rec, err := csvr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error parsing %q row %d: %w", csvFile, rowIndex, err)
		}

		if len(rec) < FIELD_MIN {
			if cfg.verbose {
				fmt.Fprintf(os.Stderr, "Warn: skipping row %d (too few fields): %s\n", rowIndex, strings.Join(rec, ","))
			}
			continue
		}

		message := SMSMessage{
			FirstName:       strings.TrimSpace(rec[FIELD_NICK]),
			PhoneNumber:     strings.TrimSpace(rec[FIELD_PHONE]),
			MessageTemplate: strings.TrimSpace(rec[FIELD_MESSAGE]),
		}

		message.PhoneNumber = cleanPhoneNumber(message.PhoneNumber)
		message.PhoneNumber = cfg.validateAndFormatNumber(message.PhoneNumber)
		if message.PhoneNumber == "" {
			if cfg.verbose {
				fmt.Fprintf(os.Stderr, "Warn: skipping row %d (no phone number): %s\n", rowIndex, strings.Join(rec, ","))
			}
			continue
		}

		messages = append(messages, message)
	}

	return messages, nil
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
