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

func main() {
	_ = godotenv.Load("./.env")
	sender := &SMSSender{
		baseURL:  os.Getenv("SMSGW_BASEURL"),
		user:     os.Getenv("SMSGW_USER"),
		password: os.Getenv("SMSGW_PASSWORD"),
	}

	dryRun := flag.Bool("dry-run", false, "Print curl commands instead of sending messages")
	csvFile := flag.String("csv", "./messages.csv", "Path to file with newline-delimited phone numbers")
	flag.Parse()

	file, err := os.Open(*csvFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %q could not be read\n", *csvFile)
		os.Exit(1)
	}
	defer func() {
		_ = file.Close()
	}()

	csvr := csv.NewReader(file)
	csvr.FieldsPerRecord = -1

	messages, err := LaxParseCSV(csvr, csvFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	r := rand.New(rand.NewSource(37))
	r.Shuffle(len(messages), func(i, j int) {
		messages[i], messages[j] = messages[j], messages[i]
	})

	for _, message := range messages {
		delay := 60 + rand.Float64()*90

		fmt.Fprintf(os.Stderr, "# Send to %s (%s) %s-%s\n", message.PhoneNumber[:2], message.PhoneNumber[2:5], message.PhoneNumber[5:8], message.PhoneNumber[8:])
		text := strings.ReplaceAll(message.MessageTemplate, "{First}", message.FirstName)
		if *dryRun {
			sender.printDryRun(message.PhoneNumber, text)
			fmt.Printf("sleep %.3f\n\n", delay)
		} else {
			sender.sendMessage(message.PhoneNumber, text)
			fmt.Printf("sleep %.3f\n\n", delay)
			time.Sleep(time.Duration(delay * float64(time.Second)))
		}
	}
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

func validateAndFormatNumber(number string) string {
	switch len(number) {
	case 10:
		return "+1" + number
	case 11:
		if strings.HasPrefix(number, "1") {
			return "+" + number
		}
		fmt.Printf("warning: invalid 11-digit number '%s'\n", number)
		return ""
	case 12:
		if strings.HasPrefix(number, "+1") {
			return number
		}
		fmt.Printf("warning: invalid 12-digit number '%s' does not start with +1\n", number)
		return ""
	default:
		fmt.Printf("warning: invalid number length for '%s'\n", number)
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

func LaxParseCSV(csvr *csv.Reader, csvFile *string) ([]SMSMessage, error) {
	header, err := csvr.Read()
	if err != nil {
		return nil, fmt.Errorf("error: %q header could not be parsed: %w", *csvFile, err)
	}

	FIELD_NICK := GetFieldIndex(header, "Preferred")
	FIELD_PHONE := GetFieldIndex(header, "Phone")
	FIELD_MESSAGE := GetFieldIndex(header, "Message")
	if FIELD_NICK == -1 || FIELD_PHONE == -1 || FIELD_MESSAGE == -1 {
		return nil, fmt.Errorf("error: %q is missing one or more of 'Preferred', 'Phone', and/or 'Message'", *csvFile)
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
			return nil, fmt.Errorf("error parsing %q row %d: %w", *csvFile, rowIndex, err)
		}

		if len(rec) < FIELD_MIN {
			fmt.Printf("skipping row %d (too few fields): %s\n", rowIndex, strings.Join(rec, ","))
			continue
		}

		message := SMSMessage{
			FirstName:       strings.TrimSpace(rec[FIELD_NICK]),
			PhoneNumber:     strings.TrimSpace(rec[FIELD_PHONE]),
			MessageTemplate: strings.TrimSpace(rec[FIELD_MESSAGE]),
		}

		message.PhoneNumber = cleanPhoneNumber(message.PhoneNumber)
		message.PhoneNumber = validateAndFormatNumber(message.PhoneNumber)
		if message.PhoneNumber == "" {
			fmt.Printf("skipping row %d (no phone number): %s\n", rowIndex, strings.Join(rec, ","))
			continue
		}

		messages = append(messages, message)
	}

	return messages, nil
}
