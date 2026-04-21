// Package formmailer provides an HTTP handler that validates, rate-limits,
// and emails contact form submissions.
//
// Typical setup:
//
//	// Blacklist can be any snapshot source — e.g. *dataset.View[ipcohort.Cohort]
//	// satisfies CohortSource directly via its Value() method.
//	blacklist := dataset.Add(set, func() (*ipcohort.Cohort, error) { ... })
//
//	fm := &formmailer.FormMailer{
//	    SMTPHost:    "smtp.example.com:587",
//	    SMTPFrom:    "noreply@example.com",
//	    SMTPTo:      []string{"contact@example.com"},
//	    SMTPUser:    "noreply@example.com",
//	    SMTPPass:    os.Getenv("SMTP_PASS"),
//	    Subject:     "Contact from {.Email}",
//	    SuccessBody: successHTML,
//	    ErrorBody:   errorHTML,
//	    Blacklist:   blacklist,
//	    AllowedCountries: []string{"US", "CA", "MX"},
//	}
//	http.Handle("POST /contact", fm)
package formmailer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/phuslu/iploc"
	"golang.org/x/time/rate"

	"github.com/therootcompany/golib/net/ipcohort"
)

const (
	maxFormSize      = 10 * 1024
	maxMessageLength = 4000
	maxCompanyLength = 200
	maxNameLength    = 100
	maxEmailLength   = 254
	maxPhoneLength   = 20

	defaultRPM         = 5
	defaultBurst       = 3
	defaultSMTPTimeout = 15 * time.Second
	defaultMXTimeout   = 3 * time.Second

	limiterTTL        = 10 * time.Minute
	limiterSweepEvery = 1024 // sweep once every N handler invocations
)

var (
	ErrInvalidEmail    = errors.New("email address doesn't look like an email address")
	ErrInvalidMX       = errors.New("email address isn't deliverable")
	ErrInvalidPhone    = errors.New("phone number is not properly formatted")
	ErrContentTooLong  = errors.New("one or more field values was too long")
	ErrInvalidNewlines = errors.New("invalid use of newlines or carriage returns")

	phoneRe = regexp.MustCompile(`^[0-9+\-\(\) ]{7,20}$`)
)

// CohortSource returns the current cohort snapshot, or nil if not yet loaded.
// *dataset.View[ipcohort.Cohort] satisfies this interface directly.
type CohortSource interface {
	Value() *ipcohort.Cohort
}

// FormFields maps logical field names to the HTML form field names.
// Zero values use GravityForms-compatible defaults (input_1, input_3, etc.).
type FormFields struct {
	Name    string // default "input_1"
	Email   string // default "input_3"
	Phone   string // default "input_4"
	Company string // default "input_5"
	Message string // default "input_7"
}

func (f FormFields) get(r *http.Request, field, def string) string {
	key := field
	if key == "" {
		key = def
	}
	return strings.TrimSpace(r.FormValue(key))
}

// FormMailer is an http.Handler that validates and emails contact form submissions.
type FormMailer struct {
	// SMTP
	SMTPHost string
	SMTPFrom string
	SMTPTo   []string
	SMTPUser string
	SMTPPass string
	Subject  string // may contain {.Email}

	// SMTPTimeout bounds the entire connect+auth+send cycle. Zero uses 15s.
	SMTPTimeout time.Duration
	// MXTimeout bounds the per-submission MX lookup. Zero uses 3s.
	MXTimeout time.Duration

	// SuccessBody and ErrorBody are the response bodies sent to the client.
	// ErrorBody may contain {.Error} and {.SupportEmail} placeholders.
	// Load from files before use: fm.SuccessBody, _ = os.ReadFile("success.html")
	SuccessBody []byte
	ErrorBody   []byte
	ContentType string // inferred from SuccessBody if empty

	// Blacklist — if set, matching IPs are rejected before any other processing.
	// *dataset.View[ipcohort.Cohort] satisfies this interface.
	Blacklist CohortSource

	// AllowedCountries — if non-nil, only requests from listed ISO codes are
	// accepted. Unknown country ("") is always allowed.
	// Example: []string{"US", "CA", "MX"}
	AllowedCountries []string

	// Fields maps logical names to HTML form field names.
	Fields FormFields

	// RPM and Burst control per-IP rate limiting. Zero uses defaults (5/3).
	RPM   int
	Burst int

	once     sync.Once
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	reqCount uint64
}

type limiterEntry struct {
	lim      *rate.Limiter
	lastUsed time.Time
}

func (fm *FormMailer) init() {
	fm.limiters = make(map[string]*limiterEntry)
}

func (fm *FormMailer) contentType() string {
	if fm.ContentType != "" {
		return fm.ContentType
	}
	// Infer from SuccessBody sniff or leave as plain text.
	if bytes.Contains(fm.SuccessBody[:min(512, len(fm.SuccessBody))], []byte("<html")) {
		return "text/html; charset=utf-8"
	}
	if bytes.HasPrefix(bytes.TrimSpace(fm.SuccessBody), []byte("{")) {
		return "application/json"
	}
	return "text/plain; charset=utf-8"
}

func (fm *FormMailer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fm.once.Do(fm.init)

	if err := r.ParseMultipartForm(maxFormSize); err != nil {
		http.Error(w, "form too large or invalid", http.StatusBadRequest)
		return
	}

	ipStr := clientIP(r)
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		fm.writeError(w, fmt.Errorf("malformed client IP"), true)
		return
	}

	// Blocklist check — fail before any other processing.
	if fm.Blacklist != nil {
		if c := fm.Blacklist.Value(); c != nil && c.ContainsAddr(ip) {
			fm.writeError(w, fmt.Errorf("automated requests are not accepted"), false)
			return
		}
	}

	// Geo check.
	if fm.AllowedCountries != nil {
		country := string(iploc.IPCountry(ip))
		if country != "" && !slices.Contains(fm.AllowedCountries, country) {
			fm.writeError(w, fmt.Errorf("submissions from your region are not accepted; please email us directly"), true)
			return
		}
	}

	// Rate limit.
	if !fm.allow(ipStr) {
		http.Error(w, "rate limit exceeded — please try again later", http.StatusTooManyRequests)
		return
	}

	name := fm.Fields.get(r, fm.Fields.Name, "input_1")
	email := strings.ToLower(fm.Fields.get(r, fm.Fields.Email, "input_3"))
	phone := fm.Fields.get(r, fm.Fields.Phone, "input_4")
	company := fm.Fields.get(r, fm.Fields.Company, "input_5")
	message := fm.Fields.get(r, fm.Fields.Message, "input_7")

	if err := validateLengths(name, email, phone, company, message); err != nil {
		fm.writeError(w, err, true)
		return
	}
	if err := validateNoHeaderInjection(name, email, company); err != nil {
		fm.writeError(w, err, true)
		return
	}
	if err := validatePhone(phone); err != nil {
		fm.writeError(w, err, true)
		return
	}
	if err := fm.validateEmailAndMX(r.Context(), email); err != nil {
		fm.writeError(w, err, true)
		return
	}

	n := min(len(message), 100)
	log.Printf("contact form: ip=%s name=%q email=%q phone=%q company=%q message=%q",
		ipStr, name, email, phone, company, message[:n])

	subject := strings.ReplaceAll(fm.Subject, "{.Email}", email)
	body := fmt.Sprintf(
		"New contact form submission:\n\nName:    %s\nEmail:   %s\nPhone:   %s\nCompany: %s\nMessage:\n%s\n",
		name, email, phone, company, message,
	)
	msg := fmt.Appendf(nil,
		"To: %s\r\nFrom: %s\r\nReply-To: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		strings.Join(fm.SMTPTo, ", "), fm.SMTPFrom, email, subject, body,
	)

	if err := fm.sendMail(r.Context(), msg); err != nil {
		log.Printf("contact form: smtp error: %v", err)
		http.Error(w, "failed to send — please try again later", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", fm.contentType())
	_, _ = w.Write(fm.SuccessBody)
}

// sendMail dials SMTPHost with a bounded timeout and writes the message.
// Uses smtp.NewClient directly so the dial respects ctx; stdlib smtp.SendMail
// has no context plumbing.
func (fm *FormMailer) sendMail(ctx context.Context, msg []byte) error {
	timeout := fm.SMTPTimeout
	if timeout == 0 {
		timeout = defaultSMTPTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", fm.SMTPHost)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	hostname, _, err := net.SplitHostPort(fm.SMTPHost)
	if err != nil {
		hostname = fm.SMTPHost
	}
	c, err := smtp.NewClient(conn, hostname)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(nil); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if fm.SMTPUser != "" {
		auth := smtp.PlainAuth("", fm.SMTPUser, fm.SMTPPass, hostname)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(fm.SMTPFrom); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, to := range fm.SMTPTo {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("rcpt to %s: %w", to, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return c.Quit()
}

func (fm *FormMailer) writeError(w http.ResponseWriter, err error, showSupport bool) {
	w.Header().Set("Content-Type", fm.contentType())
	w.WriteHeader(http.StatusBadRequest)
	support := fm.SMTPFrom
	if !showSupport {
		support = ""
	}
	b := bytes.ReplaceAll(fm.ErrorBody, []byte("{.Error}"), []byte(err.Error()))
	b = bytes.ReplaceAll(b, []byte("{.SupportEmail}"), []byte(support))
	_, _ = w.Write(b)
}

func (fm *FormMailer) allow(ipStr string) bool {
	rpm := fm.RPM
	if rpm == 0 {
		rpm = defaultRPM
	}
	burst := fm.Burst
	if burst == 0 {
		burst = defaultBurst
	}

	now := time.Now()
	fm.mu.Lock()
	e, ok := fm.limiters[ipStr]
	if !ok {
		e = &limiterEntry{
			lim: rate.NewLimiter(rate.Every(time.Minute/time.Duration(rpm)), burst),
		}
		fm.limiters[ipStr] = e
	}
	e.lastUsed = now
	fm.reqCount++
	if fm.reqCount%limiterSweepEvery == 0 {
		for k, v := range fm.limiters {
			if now.Sub(v.lastUsed) > limiterTTL {
				delete(fm.limiters, k)
			}
		}
	}
	lim := e.lim
	fm.mu.Unlock()

	if !lim.Allow() {
		log.Printf("contact form: rate limited ip=%s", ipStr)
		return false
	}
	return true
}

func validateLengths(name, email, phone, company, message string) error {
	if len(name) > maxNameLength || len(email) > maxEmailLength ||
		len(phone) > maxPhoneLength || len(company) > maxCompanyLength ||
		len(message) > maxMessageLength {
		return ErrContentTooLong
	}
	return nil
}

func (fm *FormMailer) validateEmailAndMX(ctx context.Context, email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return ErrInvalidEmail
	}
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return ErrInvalidEmail
	}
	timeout := fm.MXTimeout
	if timeout == 0 {
		timeout = defaultMXTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := net.DefaultResolver.LookupMX(lookupCtx, domain); err != nil {
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

func validateNoHeaderInjection(fields ...string) error {
	for _, f := range fields {
		if strings.ContainsAny(f, "\r\n") {
			return ErrInvalidNewlines
		}
	}
	return nil
}

// clientIP returns the originating IP, preferring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
