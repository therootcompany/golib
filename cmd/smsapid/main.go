package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/simonfrey/jsonl"
	"github.com/therootcompany/golib/colorjson"
	"github.com/therootcompany/golib/http/androidsmsgateway"
)

var jsonf = colorjson.NewFormatter()

var webhookEvents []androidsmsgateway.WebhookEvent
var webhookWriter jsonl.Writer
var webhookMux = sync.Mutex{}

func main() {
	jsonf.Indent = 3

	// TODO manual override via flags
	// color.NoColor = false

	filePath := "./messages.jsonl"
	{
		file, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("failed to open file '%s': %v", filePath, err)
		}
		defer func() { _ = file.Close() }()

		// buf := bufio.NewReader(file)
		buf := file
		webhookEvents, err = readWebhooks(buf)
		if err != nil {
			log.Fatalf("failed to read jsonl file '%s': %v", filePath, err)
		}
	}
	{
		file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Errorf("failed to open file: %v", err))
		}
		defer func() { _ = file.Close() }()

		webhookWriter = jsonl.NewWriter(file)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/webhooks", handlerWebhooks)
	mux.Handle("GET /", LogRequest(http.HandlerFunc(HandleOK)))
	mux.Handle("POST /", LogRequest(http.HandlerFunc(handler)))
	mux.Handle("PATCH /", LogRequest(http.HandlerFunc(HandleOK)))
	mux.Handle("PUT /", LogRequest(http.HandlerFunc(HandleOK)))
	mux.Handle("DELETE /", LogRequest(http.HandlerFunc(HandleOK)))

	addr := "localhost:8088"
	fmt.Printf("Listening on %s...\n\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func HandleOK(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type ctxKey struct{}

var CtxKeyBody = ctxKey{}

func LogRequest(next http.Handler) http.Handler {
	return LogHeaders(LogBody(next))
}

func LogHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log method, path, and query
		var query string
		if len(r.URL.RawQuery) > 0 {
			query = "?" + r.URL.RawQuery
		}
		log.Printf("%s %s%s", r.Method, r.URL.Path, query)

		// Find max header name length for alignment
		maxLen := len("HOST")
		for name := range r.Header {
			if len(name) > maxLen {
				maxLen = len(name)
			}
		}
		maxLen += 1

		fmt.Printf("   %-"+fmt.Sprintf("%d", maxLen+1)+"s %s\n", "HOST", r.Host)
		for name, values := range r.Header {
			for _, value := range values {
				fmt.Printf("   %-"+fmt.Sprintf("%d", maxLen+1)+"s %s\n", name+":", value)
			}
		}
		fmt.Fprintf(os.Stderr, "\n")

		next.ServeHTTP(w, r)
	})
}

func LogBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		switch strings.ToUpper(r.Method) {
		case "HEAD", "GET", "DELETE", "OPTIONS":
			if len(body) > 0 {
				fmt.Fprintf(os.Stderr, "Unexpected body:\n%q\n", string(body))
			}
		case "POST", "PATCH", "PUT":
			// known
		default:
			fmt.Fprintf(os.Stderr, "Unexpected method %s\n", r.Method)
		}
		defer fmt.Println()

		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read body:\n%q\n", string(body))
			return
		}

		// Parse and pretty-print JSON, or raw body
		textBytes := body
		var text string
		var data any
		if err := json.Unmarshal(body, &data); err == nil {
			textBytes, _ = jsonf.Marshal(data)
		}
		text = string(textBytes)
		text = prefixLines(text, "   ")
		text = strings.TrimSpace(text)
		fmt.Printf("   %s\n", text)

		ctx := context.WithValue(r.Context(), CtxKeyBody, body)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func handlerWebhooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	next := r.URL.Query().Get("next")
	previous := r.URL.Query().Get("previous")
	limitStr := r.URL.Query().Get("limit")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 1000
	}

	var startIdx, endIdx int
	if next != "" {
		for i, event := range webhookEvents {
			switch e := event.(type) {
			case *androidsmsgateway.WebhookSent:
				if e.ID == next {
					startIdx = i + 1
					break
				}
			case *androidsmsgateway.WebhookDelivered:
				if e.ID == next {
					startIdx = i + 1
					break
				}
			case *androidsmsgateway.WebhookReceived:
				if e.ID == next {
					startIdx = i + 1
					break
				}
			}
		}
	} else if previous != "" {
		for i, event := range webhookEvents {
			switch e := event.(type) {
			case *androidsmsgateway.WebhookSent:
				if e.ID == previous && i >= limit {
					startIdx = i - limit
					break
				}
			case *androidsmsgateway.WebhookDelivered:
				if e.ID == previous && i >= limit {
					startIdx = i - limit
					break
				}
			case *androidsmsgateway.WebhookReceived:
				if e.ID == previous && i >= limit {
					startIdx = i - limit
					break
				}
			}
		}
	} else {
		if len(webhookEvents) > limit {
			startIdx = len(webhookEvents) - limit
		} else {
			startIdx = 0
		}
	}

	endIdx = min(startIdx+limit, len(webhookEvents))

	if _, err := w.Write([]byte("[")); err != nil {
		http.Error(w, `{"error":"failed to write response"}`, http.StatusInternalServerError)
		return
	}
	for i, event := range webhookEvents[startIdx:endIdx] {
		if i > 0 {
			if _, err := w.Write([]byte(",")); err != nil {
				http.Error(w, `{"error":"failed to write response"}`, http.StatusInternalServerError)
				return
			}
		}
		if err := enc.Encode(event); err != nil {
			http.Error(w, `{"error":"failed to encode webhook"}`, http.StatusInternalServerError)
			return
		}
	}
	if _, err := w.Write([]byte("]")); err != nil {
		http.Error(w, `{"error":"failed to write response"}`, http.StatusInternalServerError)
		return
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	// this will return OK unless a retry is needed (e.g. internal error)

	body, ok := r.Context().Value(CtxKeyBody).([]byte)
	if !ok {
		return
	}

	var webhook androidsmsgateway.Webhook
	if err := json.Unmarshal(body, &webhook); err != nil {
		http.Error(w, `{"error":"failed to parse webhook"}`, http.StatusOK)
		return
	}
	ts, _ := strconv.Atoi(r.Header.Get("X-Timestamp"))
	webhook.XTimestamp = int64(ts)
	webhook.XSignature = r.Header.Get("X-Signature")

	h, err := androidsmsgateway.Decode(&webhook)
	if err != nil {
		http.Error(w, `{"error":"failed to parse webhook as a specific event"}`, http.StatusOK)
		return
	}

	switch h.GetEvent() {
	case "mms:received", "sms:received", "sms:data-received", "sms:sent", "sms:delivered", "sms:failed":
		webhookMux.Lock()
		defer webhookMux.Unlock()
		if err := webhookWriter.Write(h); err != nil {
			http.Error(w, `{"error":"failed to save webhook"}`, http.StatusOK)
			return
		}
		webhookEvents = append(webhookEvents, h)
	case "system:ping":
		// nothing to do yet
	default:
		http.Error(w, `{"error":"unknown webhook event"}`, http.StatusOK)
		return
	}

	_, _ = w.Write([]byte(`{"message": "ok"}`))
}

func prefixLines(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func readWebhooks(f io.Reader) ([]androidsmsgateway.WebhookEvent, error) {
	var webhooks []androidsmsgateway.WebhookEvent
	r := jsonl.NewReader(f)
	err := r.ReadLines(func(line []byte) error {
		if len(line) == 0 {
			return nil
		}

		var webhook androidsmsgateway.Webhook
		if err := json.Unmarshal(line, &webhook); err != nil {
			return fmt.Errorf("could not unmarshal into Webhook: %w", err)
		}

		switch webhook.Event {
		case "sms:sent":
			var sent androidsmsgateway.WebhookSent
			if err := json.Unmarshal(line, &sent); err != nil {
				return fmt.Errorf("could not unmarshal into WebhookSent: %w", err)
			}
			webhooks = append(webhooks, &sent)
		case "sms:delivered":
			var delivered androidsmsgateway.WebhookDelivered
			if err := json.Unmarshal(line, &delivered); err != nil {
				return fmt.Errorf("could not unmarshal into WebhookDelivered: %w", err)
			}
			webhooks = append(webhooks, &delivered)
		case "sms:received":
			var received androidsmsgateway.WebhookReceived
			if err := json.Unmarshal(line, &received); err != nil {
				return fmt.Errorf("could not unmarshal into WebhookReceived: %w", err)
			}
			webhooks = append(webhooks, &received)
		default:
			return fmt.Errorf("unknown event type: %s", webhook.Event)
		}
		return nil
	})

	if err != nil {
		return webhooks, fmt.Errorf("failed to read JSONL lines: %w", err)
	}
	return webhooks, nil
}
