// Package formmailer provides an HTTP handler that validates, rate-limits,
// and emails contact form submissions.
//
// Fields are declared as an ordered slice; each Field names the HTML input,
// the label for the email body, and the validation Kind. Exactly one Kind
// must be KindEmail — its value is used for Reply-To, Subject substitution,
// and the MX check.
//
// Typical setup:
//
//	blacklist := dataset.Add(set, func() (*ipcohort.Cohort, error) { ... })
//
//	fm := &formmailer.FormMailer{
//	    SMTPHost: "smtp.example.com:587",
//	    SMTPFrom: "noreply@example.com",
//	    SMTPTo:   []string{"contact@example.com"},
//	    SMTPUser: "noreply@example.com",
//	    SMTPPass: os.Getenv("SMTP_PASS"),
//	    Subject:  "Contact from {.Email}",
//	    Fields: []formmailer.Field{
//	        {Label: "Name",    FormName: "input_1", Kind: formmailer.KindText},
//	        {Label: "Email",   FormName: "input_3", Kind: formmailer.KindEmail},
//	        {Label: "Phone",   FormName: "input_4", Kind: formmailer.KindPhone},
//	        {Label: "Company", FormName: "input_5", Kind: formmailer.KindText},
//	        {Label: "Budget",  FormName: "input_8", Kind: formmailer.KindText},
//	        {Label: "Message", FormName: "input_7", Kind: formmailer.KindMessage},
//	    },
//	    SuccessBody: successHTML,
//	    ErrorBody:   errorHTML,
//	    Blacklist:   blacklist,
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
	"github.com/therootcompany/golib/sync/dataset"
)

const (
	maxFormSize = 10 * 1024

	// Default per-Kind length caps; override with Field.MaxLen.
	maxEmailLength   = 254
	maxPhoneLength   = 20
	maxTextLength    = 200
	maxMessageLength = 4000

	defaultRPM         = 5
	defaultBurst       = 3
	defaultSMTPTimeout = 5 * time.Second
	defaultMXTimeout   = 2 * time.Second

	limiterTTL        = 10 * time.Minute
	limiterSweepEvery = 1024 // sweep once every N handler invocations
)

var (
	ErrInvalidEmail    = errors.New("email address doesn't look like an email address")
	ErrInvalidMX       = errors.New("email address isn't deliverable")
	ErrInvalidPhone    = errors.New("phone number is not properly formatted")
	ErrContentTooLong  = errors.New("one or more field values was too long")
	ErrInvalidNewlines = errors.New("invalid use of newlines or carriage returns")
	ErrMissingRequired = errors.New("required field was empty")
	ErrNoEmailField    = errors.New("FormMailer.Fields must contain exactly one KindEmail field")

	phoneRe = regexp.MustCompile(`^[0-9+\-\(\) ]{7,20}$`)
)

// FieldKind picks validation rules and default length cap for a Field.
type FieldKind int

const (
	KindText    FieldKind = iota // default; length-capped text
	KindEmail                    // RFC 5321 parse + MX lookup
	KindPhone                    // phoneRe match
	KindMessage                  // long free text (body of the submission)
)

// Field declares one form input. Order is preserved in the email body.
type Field struct {
	Label    string    // shown in email body, e.g. "Name"
	FormName string    // HTML form field name, e.g. "input_1"
	Kind     FieldKind // validation rules + default MaxLen
	MaxLen   int       // 0 = default for Kind
	Required bool      // if true, empty value is rejected
}

func (f Field) maxLen() int {
	if f.MaxLen > 0 {
		return f.MaxLen
	}
	switch f.Kind {
	case KindEmail:
		return maxEmailLength
	case KindPhone:
		return maxPhoneLength
	case KindMessage:
		return maxMessageLength
	default:
		return maxTextLength
	}
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

	// SMTPTimeout bounds the entire connect+auth+send cycle. Zero uses 5s.
	SMTPTimeout time.Duration
	// MXTimeout bounds the per-submission MX lookup. Zero uses 2s.
	MXTimeout time.Duration

	// SuccessBody and ErrorBody are the response bodies sent to the client.
	// ErrorBody may contain {.Error} and {.SupportEmail} placeholders.
	SuccessBody []byte
	ErrorBody   []byte
	ContentType string // inferred from SuccessBody if empty

	// Blacklist — if set, matching IPs are rejected before any other processing.
	Blacklist *dataset.View[ipcohort.Cohort]

	// AllowedCountries — if non-nil, only requests from listed ISO codes are
	// accepted. Unknown country ("") is always allowed.
	AllowedCountries []string

	// Fields declares the form inputs in display order. Exactly one entry
	// must have Kind == KindEmail.
	Fields []Field

	// RPM and Burst control per-IP rate limiting. Zero uses defaults (5/3).
	RPM   int
	Burst int

	once     sync.Once
	initErr  error
	emailIdx int // index into Fields of the KindEmail entry
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
	fm.emailIdx = -1
	for i, f := range fm.Fields {
		if f.Kind == KindEmail {
			if fm.emailIdx >= 0 {
				fm.initErr = ErrNoEmailField
				return
			}
			fm.emailIdx = i
		}
	}
	if fm.emailIdx < 0 {
		fm.initErr = ErrNoEmailField
	}
}

func (fm *FormMailer) contentType() string {
	if fm.ContentType != "" {
		return fm.ContentType
	}
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
	if fm.initErr != nil {
		log.Printf("contact form: misconfigured: %v", fm.initErr)
		http.Error(w, "contact form misconfigured", http.StatusInternalServerError)
		return
	}

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

	if fm.Blacklist != nil {
		if c := fm.Blacklist.Value(); c != nil && c.ContainsAddr(ip) {
			fm.writeError(w, fmt.Errorf("automated requests are not accepted"), false)
			return
		}
	}

	if fm.AllowedCountries != nil {
		country := string(iploc.IPCountry(ip))
		if country != "" && !slices.Contains(fm.AllowedCountries, country) {
			fm.writeError(w, fmt.Errorf("submissions from your region are not accepted; please email us directly"), true)
			return
		}
	}

	if !fm.allow(ipStr) {
		http.Error(w, "rate limit exceeded — please try again later", http.StatusTooManyRequests)
		return
	}

	values := make([]string, len(fm.Fields))
	for i, f := range fm.Fields {
		v := strings.TrimSpace(r.FormValue(f.FormName))
		if f.Kind == KindEmail {
			v = strings.ToLower(v)
		}
		values[i] = v
	}

	for i, f := range fm.Fields {
		v := values[i]
		if f.Required && v == "" {
			fm.writeError(w, fmt.Errorf("%w: %s", ErrMissingRequired, f.Label), true)
			return
		}
		if len(v) > f.maxLen() {
			fm.writeError(w, ErrContentTooLong, true)
			return
		}
		// Header-injection check: all fields except free-form message bodies.
		if f.Kind != KindMessage && strings.ContainsAny(v, "\r\n") {
			fm.writeError(w, ErrInvalidNewlines, true)
			return
		}
		switch f.Kind {
		case KindPhone:
			if err := validatePhone(v); err != nil {
				fm.writeError(w, err, true)
				return
			}
		case KindEmail:
			if err := fm.validateEmailAndMX(r.Context(), v); err != nil {
				fm.writeError(w, err, true)
				return
			}
		}
	}

	email := values[fm.emailIdx]

	var logBuf strings.Builder
	fmt.Fprintf(&logBuf, "contact form: ip=%s", ipStr)
	for i, f := range fm.Fields {
		v := values[i]
		if len(v) > 100 {
			v = v[:100]
		}
		fmt.Fprintf(&logBuf, " %s=%q", f.Label, v)
	}
	log.Print(logBuf.String())

	subject := strings.ReplaceAll(fm.Subject, "{.Email}", email)
	var body strings.Builder
	body.WriteString("New contact form submission:\n\n")
	for i, f := range fm.Fields {
		if f.Kind == KindMessage {
			fmt.Fprintf(&body, "%s:\n%s\n", f.Label, values[i])
			continue
		}
		fmt.Fprintf(&body, "%s: %s\n", f.Label, values[i])
	}
	msg := fmt.Appendf(nil,
		"To: %s\r\nFrom: %s\r\nReply-To: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		strings.Join(fm.SMTPTo, ", "), fm.SMTPFrom, email, subject, body.String(),
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

func (fm *FormMailer) validateEmailAndMX(ctx context.Context, email string) error {
	if email == "" {
		return ErrInvalidEmail
	}
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
