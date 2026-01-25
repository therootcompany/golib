package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type SMSGatewayForAndroid struct {
	baseURL  string
	username string
	password string
}

func New(baseURL, username, password string) *SMSGatewayForAndroid {
	return &SMSGatewayForAndroid{
		baseURL:  baseURL,
		username: username,
		password: password,
	}
}

func (s *SMSGatewayForAndroid) CurlString(number, message string) string {
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

	return fmt.Sprintf("curl --fail-with-body --user '%s:%s' -X POST '%s' \\\n", s.username, s.password, url) +
		"   -H 'Content-Type: application/json' \\\n" +
		"   --data-binary '" + escapedBody + "'"
}

func (s *SMSGatewayForAndroid) Send(number, message string) error {
	if true {
		return fmt.Errorf("didn't send")
	}

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
		return fmt.Errorf("failed sending message to '%s': %d %s\n",
			number, resp.StatusCode, string(body),
		)
	}

	return nil
}
