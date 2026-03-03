package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/therootcompany/golib/auth"
	"github.com/therootcompany/golib/auth/csvauth"
	"github.com/therootcompany/golib/colorjson"
	"github.com/therootcompany/golib/http/androidsmsgateway"
	"github.com/therootcompany/golib/http/middleware/v2"

	chiware "github.com/go-chi/chi/v5/middleware"
	"github.com/jszwec/csvutil"
	"github.com/simonfrey/jsonl"
)

const (
	name         = "smsapid"
	desc         = "for self-hosting android-sms-gateway"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)"
	licenseType  = "MPL-2.0"
)

// replaced by goreleaser / ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "%s\n", desc)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

var (
	ErrNoAuth = errors.New("request missing the required form of authorization")
)

var (
	jsonf = colorjson.NewFormatter()

	// webhookMux protects webhookWriter, pingWriter, webhookEvents, and pingEvents.
	webhookMux    = sync.Mutex{}
	webhookEvents []androidsmsgateway.WebhookEvent
	webhookWriter jsonl.Writer
	pingEvents    []*androidsmsgateway.WebhookPing
	pingWriter    jsonl.Writer

	smsgwSigningKey string
	smsRequestAuth  *auth.BasicRequestAuthenticator
	// TODO
	// smsgwUsername   string
	// smsgwPassword   string
)

type MainConfig struct {
	Bind                       string
	Port                       int
	credsPath                  string
	credsComma                 rune
	credsCommaString           string
	AES128KeyPath              string
	ShowVersion                bool
	BasicRealm                 string
	AuthorizationHeaderSchemes []string
	TokenHeaderNames           []string
	QueryParamNames            []string
	tokenSchemeList            string
	tokenHeaderList            string
	tokenParamList             string
	// TODO
	// SMSGatewayURL              string
}

func (c *MainConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Bind, c.Port)
}

func main() {
	cli := MainConfig{
		Bind:                       "0.0.0.0",
		Port:                       8080,
		credsPath:                  "./credentials.tsv",
		AES128KeyPath:              filepath.Join("~", ".config", "csvauth", "aes-128.key"),
		credsComma:                 '\t',
		tokenSchemeList:            "",
		tokenHeaderList:            "",
		tokenParamList:             "",
		BasicRealm:                 "Basic",
		AuthorizationHeaderSchemes: nil, // []string{"Bearer", "Token"}
		TokenHeaderNames:           nil, // []string{"X-API-Key", "X-Auth-Token", "X-Access-Token"},
		QueryParamNames:            nil, // []string{"access_token", "token"},
	}

	// Override defaults from env
	if v := os.Getenv("SMSAPID_PORT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cli.Port); err != nil {
			fmt.Fprintf(os.Stderr, "invalid SMSAPID_PORT value: %s\n", v)
			os.Exit(1)
		}
	}
	if v := os.Getenv("SMSAPID_ADDRESS"); v != "" {
		cli.Bind = v
	}
	if v := os.Getenv("SMSAPID_CREDENTIALS_FILE"); v != "" {
		cli.credsPath = v
	}

	// Flags
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.BoolVar(&cli.ShowVersion, "version", false, "show version and exit")
	fs.IntVar(&cli.Port, "port", cli.Port, "port to listen on")
	fs.StringVar(&cli.Bind, "address", cli.Bind, "address to bind to (e.g. 127.0.0.1)")
	fs.StringVar(&cli.AES128KeyPath, "creds-key-file", cli.AES128KeyPath, "path to credentials TSV/CSV file")
	fs.StringVar(&cli.credsPath, "creds-file", cli.credsPath, "path to credentials TSV/CSV file")
	fs.StringVar(&cli.credsCommaString, "creds-comma", "\\t", "single-character CSV separator for credentials file (literal characters and escapes accepted)")
	fs.StringVar(&cli.tokenSchemeList, "token-schemes", "Bearer,Token", "checks for header 'Authorization: <Scheme> <token>'")
	fs.StringVar(&cli.tokenHeaderList, "token-headers", "X-API-Key,X-Auth-Token,X-Access-Token", "checks for header '<API-Key-Header>: <token>'")
	fs.StringVar(&cli.tokenParamList, "token-params", "access_token,token", "checks for query param '?<param>=<token>'")
	// TODO
	// fs.StringVar(&cli.SMSGatewayURL, "sms-gateway-url", "", "URL of the phone running android-sms-gateway")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE\n  %s [flags]\n\n", name)
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nENVIRONMENT\n")
		fmt.Fprintf(os.Stderr, "  SMSAPID_PORT              port to listen on\n")
		fmt.Fprintf(os.Stderr, "  SMSAPID_ADDRESS           bind address\n")
		fmt.Fprintf(os.Stderr, "  SMSAPID_CREDENTIALS_FILE  path to tokens file\n")
		fmt.Fprintf(os.Stderr, "  SMS_GATEWAY_USERNAME      android-sms-gateway basic auth username\n")
		fmt.Fprintf(os.Stderr, "  SMS_GATEWAY_PASSWORD      android-sms-gateway basic auth password\n")
		fmt.Fprintf(os.Stderr, "  SMS_GATEWAY_SIGNING_KEY   android-sms-gateway signing key for webhooks\n")
	}

	// Special handling for version/help
	if len(os.Args) > 1 {
		arg := os.Args[1]
		switch arg {
		case "-V", "version", "-version", "--version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			_, _ = fmt.Fprintln(os.Stdout, "")
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}
	printVersion(os.Stderr)
	fmt.Fprintln(os.Stderr, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			fs.Usage()
			os.Exit(0)
		}
		log.Fatalf("flag parse error: %v", err)
	}

	{
		homedir, err := os.UserHomeDir()
		if err == nil {
			var found bool
			if cli.AES128KeyPath, found = strings.CutPrefix(cli.AES128KeyPath, "~"); found {
				cli.AES128KeyPath = homedir + cli.AES128KeyPath
			}
		}
	}

	cli.AuthorizationHeaderSchemes = ArgFields(cli.tokenSchemeList, ",", []string{"none"})
	cli.TokenHeaderNames = ArgFields(cli.tokenHeaderList, ",", []string{"none"})
	cli.QueryParamNames = ArgFields(cli.tokenParamList, ",", []string{"none"})

	// Load credentials for /api/smsgw routes.
	var smsAuth *csvauth.Auth
	credPath := "./credentials.tsv"
	if v := os.Getenv("SMSAPID_CREDENTIALS_FILE"); v != "" {
		credPath = v
	}
	f, err := os.Open(credPath)
	if err != nil {
		log.Fatalf("failed to load credentials from %q: %v", credPath, err)
	}
	defer func() { _ = f.Close() }()

	aesKey, err := getAESKey("CSVAUTH_AES_128_KEY", cli.AES128KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	smsAuth = csvauth.New(aesKey)
	if err := smsAuth.LoadCSV(f, cli.credsComma); err != nil {
		log.Fatalf("failed to load credentials from %q: %v\n", credPath, err)
	}
	smsRequestAuth = auth.NewBasicRequestAuthenticator(smsAuth)

	// Load optional webhook signing key.
	smsgwSigningKey = os.Getenv("SMS_GATEWAY_SIGNING_KEY")
	// TODO
	// smsgwUsername = os.Getenv("SMS_GATEWAY_USERNAME")
	// smsgwPassword = os.Getenv("SMS_GATEWAY_PASSWORD")

	// credentials file delimiter
	cli.credsComma, err = DecodeDelimiter(cli.credsCommaString)
	if err != nil {
		log.Fatalf("comma parse error: %v", err)
	}

	cli.run()
}

func (cli *MainConfig) run() {
	jsonf.Indent = 3

	messagesPath := "./messages.jsonl"
	{
		file, err := os.OpenFile(messagesPath, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("failed to open file '%s': %v", messagesPath, err)
		}
		defer func() { _ = file.Close() }()

		webhookEvents, err = readWebhooks(file)
		if err != nil {
			log.Fatalf("failed to read jsonl file '%s': %v", messagesPath, err)
		}
	}
	{
		file, err := os.OpenFile(messagesPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Errorf("failed to open file: %v", err))
		}
		defer func() { _ = file.Close() }()

		webhookWriter = jsonl.NewWriter(file)
	}

	pingsPath := "./pings.jsonl"
	{
		file, err := os.OpenFile(pingsPath, os.O_RDONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("failed to open file '%s': %v", pingsPath, err)
		}
		defer func() { _ = file.Close() }()

		pingEvents, err = readPings(file)
		if err != nil {
			log.Fatalf("failed to read jsonl file '%s': %v", pingsPath, err)
		}
	}
	{
		file, err := os.OpenFile(pingsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(fmt.Errorf("failed to open file: %v", err))
		}
		defer func() { _ = file.Close() }()

		pingWriter = jsonl.NewWriter(file)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/webhooks", handlerWebhooks)
	mux.Handle("POST /", LogRequest(http.HandlerFunc(handler)))

	// Protected routes under /api/smsgw, each guarded by its specific sms:* permission.
	smsgw := middleware.WithMux(mux, LogRequest)
	smsgw.With(requireSMSPermission("sms:received")).HandleFunc("GET /api/smsgw/received.csv", handlerReceived)
	smsgw.With(requireSMSPermission("sms:received")).HandleFunc("GET /api/smsgw/received.json", handlerReceived)
	smsgw.With(requireSMSPermission("sms:sent")).HandleFunc("GET /api/smsgw/sent.csv", handlerSent)
	smsgw.With(requireSMSPermission("sms:sent")).HandleFunc("GET /api/smsgw/sent.json", handlerSent)
	smsgw.With(requireSMSPermission("sms:ping")).HandleFunc("GET /api/smsgw/ping.csv", handlerPing)
	smsgw.With(requireSMSPermission("sms:ping")).HandleFunc("GET /api/smsgw/ping.json", handlerPing)

	addr := cli.Addr()
	fmt.Printf("Listening on %s...\n\n", addr)
	log.Fatal(http.ListenAndServe(addr, chiware.Logger(chiware.Compress(5)(mux))))
}

// hasSMSPermission reports whether perms includes the wildcard "sms:*" or the specific permission.
func hasSMSPermission(perms []string, permission string) bool {
	for _, p := range perms {
		if p == "sms:*" || p == permission {
			return true
		}
	}
	return false
}

// requireSMSPermission returns a middleware that authenticates the request and enforces
// that the credential holds "sms:*" or the given specific permission.
func requireSMSPermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cred, err := smsRequestAuth.Authenticate(r)
			if err != nil || !hasSMSPermission(cred.Permissions(), permission) {
				w.Header().Set("WWW-Authenticate", smsRequestAuth.BasicRealm)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})

	}
}

// getAESKey reads an AES-128 key (32 hex chars) from an environment variable.
func getAESKey(envname, filename string) ([]byte, error) {
	envKey := os.Getenv(envname)
	if envKey != "" {
		key, err := hex.DecodeString(strings.TrimSpace(envKey))
		if err != nil || len(key) != 16 {
			return nil, fmt.Errorf("invalid %s: must be 32-char hex string", envname)
		}
		fmt.Fprintf(os.Stderr, "Found AES Key in %s\n", envname)
		return key, nil
	}

	if _, err := os.Stat(filename); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", filename, err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("invalid key in %s: must be 32-char hex string", filename)
	}
	// relpath := strings.Replace(filename, homedir, "~", 1)
	fmt.Fprintf(os.Stderr, "Found AES Key at %s\n", filename)
	return key, nil
}

// parseSinceLimit extracts the "since" (ISO datetime) and "limit" query parameters.
func parseSinceLimit(r *http.Request) (time.Time, int) {
	var since time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		for _, format := range []string{time.RFC3339, "2006-01-02T15:04:05-0700", "2006-01-02"} {
			if t, err := time.Parse(format, s); err == nil {
				since = t
				break
			}
		}
	}

	limit := 10_000
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(strings.ReplaceAll(l, "_", "")); err == nil && n > 0 {
			limit = n
		}
	}

	return since, limit
}

func handlerReceived(w http.ResponseWriter, r *http.Request) {
	since, limit := parseSinceLimit(r)

	webhookMux.Lock()
	rows := make([]*androidsmsgateway.WebhookReceived, 0, min(len(webhookEvents), limit))
	for _, event := range webhookEvents {
		recv, ok := event.(*androidsmsgateway.WebhookReceived)
		if !ok {
			continue
		}
		if !since.IsZero() && !recv.Payload.ReceivedAt.After(since) {
			continue
		}
		rows = append(rows, recv)
		if len(rows) >= limit {
			break
		}
	}
	webhookMux.Unlock()

	serveCSVOrJSON(w, r, rows)
}

func handlerSent(w http.ResponseWriter, r *http.Request) {
	since, limit := parseSinceLimit(r)

	webhookMux.Lock()
	rows := make([]*androidsmsgateway.WebhookSent, 0, min(len(webhookEvents), limit))
	for _, event := range webhookEvents {
		sent, ok := event.(*androidsmsgateway.WebhookSent)
		if !ok {
			continue
		}
		if !since.IsZero() && !sent.Payload.SentAt.After(since) {
			continue
		}
		rows = append(rows, sent)
		if len(rows) >= limit {
			break
		}
	}
	webhookMux.Unlock()

	serveCSVOrJSON(w, r, rows)
}

func handlerPing(w http.ResponseWriter, r *http.Request) {
	since, limit := parseSinceLimit(r)

	webhookMux.Lock()
	rows := make([]*androidsmsgateway.WebhookPing, 0, min(len(pingEvents), limit))
	for _, ping := range pingEvents {
		pingedAt := ping.PingedAt
		if pingedAt.IsZero() {
			pingedAt = time.UnixMilli(ping.XTimestamp).UTC()
		}
		if !since.IsZero() && !pingedAt.After(since) {
			continue
		}
		rows = append(rows, ping)
		if len(rows) >= limit {
			break
		}
	}
	webhookMux.Unlock()

	serveCSVOrJSON(w, r, rows)
}

// serveCSVOrJSON writes v as CSV when the request path ends with ".csv", otherwise as JSON.
func serveCSVOrJSON[T any](w http.ResponseWriter, r *http.Request, v []T) {
	if strings.HasSuffix(r.URL.Path, ".csv") {
		b, err := csvutil.Marshal(v)
		if err != nil {
			http.Error(w, `{"error":"failed to encode CSV"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
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

	if smsgwSigningKey != "" {
		if !androidsmsgateway.VerifySignature(smsgwSigningKey, string(body), r.Header.Get("X-Timestamp"), webhook.XSignature) {
			http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
			return
		}
	}

	h, err := androidsmsgateway.Decode(&webhook)
	if err != nil {
		http.Error(w, `{"error":"failed to parse webhook as a specific event"}`, http.StatusOK)
		return
	}

	switch h.GetEvent() {
	case "system:ping":
		ping := h.(*androidsmsgateway.WebhookPing)
		ping.PingedAt = time.UnixMilli(webhook.XTimestamp).UTC()
		webhookMux.Lock()
		defer webhookMux.Unlock()
		if err := pingWriter.Write(ping); err != nil {
			http.Error(w, `{"error":"failed to save ping"}`, http.StatusOK)
			return
		}
		pingEvents = append(pingEvents, ping)
	case "mms:received", "sms:received", "sms:data-received", "sms:sent", "sms:delivered", "sms:failed":
		webhookMux.Lock()
		defer webhookMux.Unlock()
		if err := webhookWriter.Write(h); err != nil {
			http.Error(w, `{"error":"failed to save webhook"}`, http.StatusOK)
			return
		}
		webhookEvents = append(webhookEvents, h)
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

func readPings(f io.Reader) ([]*androidsmsgateway.WebhookPing, error) {
	var pings []*androidsmsgateway.WebhookPing
	r := jsonl.NewReader(f)
	err := r.ReadLines(func(line []byte) error {
		if len(line) == 0 {
			return nil
		}
		var ping androidsmsgateway.WebhookPing
		if err := json.Unmarshal(line, &ping); err != nil {
			return fmt.Errorf("could not unmarshal into WebhookPing: %w", err)
		}
		pings = append(pings, &ping)
		return nil
	})

	if err != nil {
		return pings, fmt.Errorf("failed to read JSONL lines: %w", err)
	}
	return pings, nil
}
