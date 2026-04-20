package formmailer

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
	"golang.org/x/time/rate"

	"github.com/phuslu/iploc"
)

const (
	maxFormSize      = 10 * 1024 // 10KB total form limit
	maxMessageLength = 4000
	maxCompanyLength = 200
	maxNameLength    = 100
	maxEmailLength   = 254
	maxPhoneLength   = 20

	requestsPerMinute = 5
	burstSize         = 3
)

var ErrInvalidEmail = fmt.Errorf("email address doesn't look like an email address")
var ErrInvalidMX = fmt.Errorf("email address isn't deliverable")
var ErrInvalidPhone = fmt.Errorf("phone number is not properly formatted")
var ErrContentTooLong = fmt.Errorf("one or more of the field values was too long")
var ErrInvalidNewlines = fmt.Errorf("invalid use of newlines or returns")

var (
	phoneRe = regexp.MustCompile(`^[0-9+\-\(\) ]{7,20}$`)

	// Global per-IP limiter map
	limiterMu sync.Mutex
	limiters  = make(map[string]*rate.Limiter)
)

type FormMailer struct {
	showVersion  bool
	listenAddr   string
	smtpHost     string
	smtpFrom     string
	smtpToList   string
	smtpUser     string
	smtpPass     string
	smtpSubject  string
	successFile  string
	errorFile    string
	responseType string
	Blacklist    *ipcohort.Cohort
}

func Init() {
	gitURL := "git@github.com:bitwire-it/ipblocklist.git"
	blacklistPath := "/home/app/srv/ipblocklist/inbound.txt"

	cfg := &FormMailer{
		listenAddr:   "localhost:3081",
		smtpHost:     os.Getenv("SMTP_HOST"),
		smtpFrom:     os.Getenv("SMTP_FROM"),
		smtpToList:   os.Getenv("SMTP_TO"),
		smtpUser:     os.Getenv("SMTP_USER"),
		smtpPass:     "",
		smtpSubject:  "Website contact request from {.Email}",
		successFile:  "success-file.html",
		errorFile:    "error-file.html",
		responseType: "text/plain",
		Blacklist:    nil,
	}

	if cfg.smtpHost == "" || cfg.smtpFrom == "" || cfg.smtpToList == "" {
		return fmt.Errorf("missing required SMTP settings")
	}

	if _, err := os.ReadFile(cfg.successFile); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: couldn't read success response file %q: %v\n\n", cfg.successFile, err)
		os.Exit(1)
	}
	if _, err := os.ReadFile(cfg.errorFile); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: couldn't read error response file %q: %v\n\n", cfg.errorFile, err)
		os.Exit(1)
	}

	if cfg.smtpUser == "" {
		cfg.smtpUser = cfg.smtpFrom
	}
	if cfg.smtpFrom == "" {
		cfg.smtpFrom = cfg.smtpUser
	}

	if pass, hasPass := os.LookupEnv("SMTP_PASS"); !hasPass {
		fmt.Fprintf(os.Stderr, "SMTP_PASS not set → ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		fmt.Fprintln(os.Stderr)
		cfg.smtpPass = strings.TrimSpace(string(pwBytes))
	} else {
		cfg.smtpPass = pass
	}

	if strings.HasSuffix(strings.ToLower(cfg.successFile), ".html") {
		cfg.responseType = "text/html"
	} else if strings.HasSuffix(strings.ToLower(cfg.successFile), ".json") {
		cfg.responseType = "application/json"
	}

	cfg.Blacklist = NewBlacklist(gitURL, blacklistPath)
	fmt.Fprintf(os.Stderr, "Syncing git repo ...\n")
	skipGCOnce := true
	if n, err := cfg.Blacklist.Init(skipGCOnce); err != nil {
		fmt.Fprintf(os.Stderr, "error: ip cohort: %v\n", err)
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "ip cohort: loaded %d blacklist entries\n", n)
	}
	go func() {
		cfg.Blacklist.Run(context.TODO())
	}()

	http.HandleFunc("POST /contact", cfg.submitHandler)
	http.HandleFunc("POST /contact/", cfg.submitHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "form2email server running. POST form data to /contact")
	})

	fmt.Printf("form2email listening on http://%s\n", cfg.listenAddr)
	fmt.Printf("Forwarding submissions from %s → %s via %s\n", cfg.smtpFrom, cfg.smtpToList, cfg.smtpHost)
	fmt.Printf("Rate limit: ~%d req/min per IP (burst %d)\n", requestsPerMinute, burstSize)
	fmt.Println("CTRL+C to stop")

	log.Fatal(http.ListenAndServe(cfg.listenAddr, nil))
}

func (cfg *FormMailer) submitHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", cfg.responseType)

	// Parse form early (needed for rate limit decision, but still protected by size limit)
	err := r.ParseMultipartForm(maxFormSize)
	if err != nil {
		http.Error(w, "Form too large or invalid", http.StatusBadRequest)
		log.Printf("ParseMultipartForm error: %v", err)
		return
	}

	// Rate limit FIRST (cheap check)
	ipStr := getClientIP(r)
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		b := cfg.getErrorBody(fmt.Errorf("malformed proxy headers"))
		_, _ = w.Write(b)
		return
	}

	if cfg.Blacklist.Contains(ipStr) {
		w.WriteHeader(http.StatusBadRequest)
		b := cfg.getErrorBotty(fmt.Errorf("bots are not allowed to submit contact requests"))
		_, _ = w.Write(b)
		return
	}

	switch iploc.IPCountry(ip) {
	case "", "US", "CA", "MX", "CR", "VI":
		// North America, or unknown
	default:
		w.WriteHeader(http.StatusBadRequest)
		b := cfg.getErrorBody(fmt.Errorf("it appears that you are contacting us from outside of the United States, please email us directly for international inquiries"))
		_, _ = w.Write(b)
		return
	}

	if !validateRateLimit(ipStr) {
		http.Error(w, "Rate limit exceeded (try again later)", http.StatusTooManyRequests)
		return
	}

	stuff := make(map[string]string)
	// Extract & trim fields
	email := strings.ToLower(strings.TrimSpace(r.FormValue("input_3")))
	stuff["name"] = strings.TrimSpace(r.FormValue("input_1"))
	stuff["phone"] = strings.TrimSpace(r.FormValue("input_4"))
	stuff["company"] = strings.TrimSpace(r.FormValue("input_5"))
	stuff["message"] = strings.TrimSpace(r.FormValue("input_7"))

	// Validation chain
	if err := validateLengths(stuff["name"], email, stuff["phone"], stuff["company"], stuff["message"]); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		b := cfg.getErrorBody(err)
		_, _ = w.Write(b)
		return
	}

	if err := validatePhone(stuff["phone"]); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		b := cfg.getErrorBody(err)
		_, _ = w.Write(b)
		return
	}

	if err := validateNoHeaderInjection(stuff["name"], email, stuff["company"]); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		b := cfg.getErrorBody(err)
		_, _ = w.Write(b)
		return
	}

	if err := validateEmailAndMX(email); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		b := cfg.getErrorBody(err)
		_, _ = w.Write(b)
		return
	}

	// Log submission
	n := min(len(stuff["message"]), 100)
	log.Printf("Submission from %s | Name=%q Email=%q Phone=%q Company=%q Message=%q",
		ipStr, stuff["name"], email, stuff["phone"], stuff["company"], stuff["message"][:n]+"...")

	// TODO blacklist

	if strings.HasSuffix(email, ".ru") {
		b, _ := os.ReadFile(cfg.successFile)
		_, _ = w.Write(b)
		return
	}

	// Build email
	body := fmt.Sprintf(
		"New contact form submission:\n\n"+
			"Name:    %s\n"+
			"Email:   %s\n"+
			"Phone:   %s\n"+
			"Company: %s\n"+
			"Message:\n%s\n",
		stuff["name"], email, stuff["phone"], stuff["company"], stuff["message"],
	)

	msg := fmt.Appendf(nil,
		"To: %s\r\n"+
			"From: %s\r\n"+
			"Reply-To: %s\r\n"+
			"Subject: %s\r\n"+
			"\r\n"+
			"%s\r\n",
		cfg.smtpToList, cfg.smtpFrom, email, strings.ReplaceAll(cfg.smtpSubject, "{.Email}", email), body,
	)

	hostname := strings.Split(cfg.smtpHost, ":")[0]
	auth := smtp.PlainAuth("", cfg.smtpUser, cfg.smtpPass, hostname)

	smtpTo := strings.Split(cfg.smtpToList, ",")
	err = smtp.SendMail(cfg.smtpHost, auth, cfg.smtpFrom, smtpTo, msg)
	if err != nil {
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		log.Printf("SMTP error: %v", err)
		return
	}

	b, _ := os.ReadFile(cfg.successFile)
	_, _ = w.Write(b)
}

func (cfg *FormMailer) getErrorBody(err error) []byte {
	b, _ := os.ReadFile(cfg.errorFile)
	b = bytes.ReplaceAll(b, []byte("{.Error}"), []byte(err.Error()))
	b = bytes.ReplaceAll(b, []byte("{.SupportEmail}"), []byte(cfg.smtpFrom))
	return b
}

func (cfg *FormMailer) getErrorBotty(err error) []byte {
	b, _ := os.ReadFile(cfg.errorFile)
	b = bytes.ReplaceAll(b, []byte("{.Error}"), []byte(err.Error()))
	b = bytes.ReplaceAll(b, []byte("{.SupportEmail}"), []byte("[REDACTED]"))
	return b
}

// ────────────────────────────────────────────────────────────────────────────────
// Validation functions
// ────────────────────────────────────────────────────────────────────────────────

func validateRateLimit(ipStr string) bool {
	limiterMu.Lock()
	lim, ok := limiters[ipStr]
	if !ok {
		lim = rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerMinute)), burstSize)
		limiters[ipStr] = lim
	}
	limiterMu.Unlock()

	if !lim.Allow() {
		log.Printf("Rate limited IP: %s", ipStr)
		return false
	}
	return true
}

func validateLengths(name, email, phone, company, message string) error {
	if len(name) > maxNameLength ||
		len(email) > maxEmailLength ||
		len(phone) > maxPhoneLength ||
		len(company) > maxCompanyLength ||
		len(message) > maxMessageLength {
		return ErrContentTooLong
	}

	return nil
}

func validateEmailAndMX(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ErrInvalidEmail
	}
	domain := parts[1]

	_, err = net.LookupMX(domain)
	if err != nil {
		return ErrInvalidMX
	}

	return nil
}

func validatePhone(phone string) error {
	if phone == "" {
		return nil
	}
	if !phoneRe.MatchString(phone) {
		return ErrInvalidPhone
	}

	return nil
}

func validateNoHeaderInjection(name, email, company string) error {
	combined := name + email + company
	if strings.ContainsAny(combined, "\r\n") {
		return ErrInvalidNewlines
	}

	return nil
}

// getClientIP prefers X-Forwarded-For (first value) over RemoteAddr
func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first (original client) IP in case of multiple proxies
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			fmt.Println("Remote IP XFF:", xff)
			return strings.TrimSpace(parts[0])
		}
	}
	// Fallback to RemoteAddr (strip port)
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > -1 {
		ip = ip[:idx]
		fmt.Println("Remote IP:", ip)
	}
	return ip
}
