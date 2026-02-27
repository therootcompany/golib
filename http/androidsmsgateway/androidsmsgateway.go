package androidsmsgateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type AndroidSMSGateway struct {
	baseURL  string
	username string
	password string
}

func New(baseURL, username, password string) *AndroidSMSGateway {
	return &AndroidSMSGateway{
		baseURL:  baseURL,
		username: username,
		password: password,
	}
}

type MessagePayload struct {
	TextMessage struct {
		Text string `json:"text"`
	} `json:"textMessage"`
	PhoneNumbers []string `json:"phoneNumbers"`
	Priority     int      `json:"priority,omitempty"`
}

func (s *AndroidSMSGateway) CurlString(number, message string) string {
	url := s.baseURL + "/messages"
	payload := MessagePayload{
		TextMessage: struct {
			Text string `json:"text"`
		}{
			Text: message,
		},
		PhoneNumbers: []string{number},
		Priority:     65,
	}
	body := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)

	escapedBody := strings.ReplaceAll(body.String(), "'", "'\\''")

	return fmt.Sprintf("curl --fail-with-body --user '%s:%s' -X POST '%s' \\\n", s.username, s.password, url) +
		"   -H 'Content-Type: application/json' \\\n" +
		"   --data-binary '" + escapedBody + "'"
}

func (s *AndroidSMSGateway) Send(number, message string) error {
	number = cleanPhoneNumber(number)
	if len(number) == 0 {
		panic(fmt.Errorf("non-sanitized number '%s'", number))
	}

	url := s.baseURL + "/messages"
	payload := MessagePayload{
		TextMessage: struct {
			Text string `json:"text"`
		}{
			Text: message,
		},
		PhoneNumbers: []string{number},
		Priority:     65,
	}

	body := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(payload)

	req, _ := http.NewRequest("POST", url, body)
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request to send message to '%s' failed: %v", number, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed sending message to '%s': %d %s",
			number, resp.StatusCode, string(body),
		)
	}

	return nil
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
