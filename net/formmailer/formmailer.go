// Package formmailer provides an HTTP handler that validates, rate-limits,
// and emails contact form submissions.
//
// Fields are declared as an ordered slice; each Field names the HTML input,
// the label for the email body, and the validation Kind. Exactly one Kind
// must be KindEmail — its value is used for Reply-To, Subject substitution,
// and the MX check.
//
// Typical self-contained setup (Run):
//
//	fm := &formmailer.FormMailer{
//	    ListenAddr:    ":3081",
//	    SMTPHost:      "smtp.example.com:587",
//	    SMTPFrom:      "noreply@example.com",
//	    SMTPTo:        []string{"contact@example.com"},
//	    SMTPUser:      "noreply@example.com",
//	    SMTPPass:      os.Getenv("SMTP_PASS"),
//	    Subject:       "Contact from {.Email}",
//	    BlocklistRepo: "https://github.com/bitwire-it/ipblocklist.git",
//	    CacheDir:      "", // defaults to ~/.cache
//	    SuccessBody:   successHTML,
//	    ErrorBody:     errorHTML,
//	    Fields: []formmailer.Field{
//	        {Label: "Name",    FormName: "input_1", Kind: formmailer.KindText},
//	        {Label: "Email",   FormName: "input_3", Kind: formmailer.KindEmail},
//	        {Label: "Phone",   FormName: "input_4", Kind: formmailer.KindPhone},
//	        {Label: "Company", FormName: "input_5", Kind: formmailer.KindText},
//	        {Label: "Budget",  FormName: "input_8", Kind: formmailer.KindText},
//	        {Label: "Message", FormName: "input_7", Kind: formmailer.KindMessage},
//	    },
//	    AllowedCountries: []string{"US", "CA"},
//	}
//	if err := fm.Run(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// Programmatic setup (composable):
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
//	    },
//	    SuccessBody: successHTML,
//	    ErrorBody:   errorHTML,
//	}
//	http.Handle("POST /contact", fm)
package formmailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
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
	defaultRefresh     = 47 * time.Minute
	defaultGCInterval  = 24 // gc every N fetches (~daily at 47min cadence)

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

// FormMailer is an http.Handler that validates and emails contact form
// submissions. It can be used as a composable handler (ServeHTTP) or as a
// self-contained server (Run).
//
// When used with Run, FormMailer sets up its own blocklist and GeoIP data
// sources using gitshallow, ipcohort, and local geoip archives. When used as a handler, callers pass in
// pre-built *dataset.View values via the Blacklist and Geo fields.
type FormMailer struct {
	// ListenAddr is the address to listen on when using Run. Zero uses ":3081".
	ListenAddr string

	// SMTP
	SMTPHost string
	SMTPFrom string
	SMTPTo   []string
	SMTPUser string
	SMTPPass string
	Subject  string // may contain {.Email}
	// LocalName is the hostname the client announces in EHLO. Zero uses
	// os.Hostname(). Matters for relay (port 25) where receivers may reject
	// EHLO names that don't reverse-resolve; on submission (587) it's
	// informational. NEVER the peer's name — that's TLS SNI / auth binding.
	LocalName string
	// TLSConfig overrides the StartTLS tls.Config. Zero uses
	// &tls.Config{ServerName: <host from SMTPHost>}. Set to supply a custom
	// root CA bundle, to disable verification (in tests), or to pin a cert.
	TLSConfig *tls.Config

	// SMTPTimeout bounds the entire connect+auth+send cycle. Zero uses 5s.
	SMTPTimeout time.Duration
	// MXTimeout bounds the per-submission MX lookup. Zero uses 2s.
	MXTimeout time.Duration

	// SuccessBody and ErrorBody are called per request and return the response
	// body sent to the client. Callers typically build them as closures that
	// re-read an HTML file each invocation (hot-reload) with a baked-in fallback
	// to a copy read at startup. ErrorBody output may contain {.Error} and
	// {.SupportEmail} placeholders.
	SuccessBody func() []byte
	ErrorBody   func() []byte
	ContentType string // inferred from a probe of SuccessBody() if empty

	// HiddenSupportValue replaces {.SupportEmail} in ErrorBody output when the
	// request should not learn the operator's real address — i.e. bot and
	// blacklist rejections. Legitimate validation errors see the real support
	// email. Zero value "" strips the placeholder entirely.
	HiddenSupportValue string

	// TrustedProxies — list of CIDRs whose X-Forwarded-For header we honor.
	// Empty means never trust XFF (use r.RemoteAddr as-is). Without this,
	// any client could forge their IP to bypass rate limiting, blacklist,
	// and country gating.
	TrustedProxies []netip.Prefix

	// Fields declares the form inputs in display order. Exactly one entry
	// must have Kind == KindEmail.
	Fields []Field

	// RPM and Burst control per-IP rate limiting. Zero uses defaults (5/3).
	RPM   int
	Burst int

	// --- Blocklist configuration (used by Run) ---

	// BlocklistRepo is the git URL of the blocklist repo (e.g. bitwire-it).
	// Zero means no blocklist check.
	BlocklistRepo string
	// BlocklistPaths are the paths within the repo to load as the inbound
	// cohort (e.g. "tables/inbound/single_ips.txt", "tables/inbound/networks.txt").
	// Zero defaults to the two standard bitwire-it paths.
	BlocklistPaths []string
	// CacheDir is the parent directory for cached data. Zero defaults to
	// ~/.cache.
	CacheDir string
	// RefreshInterval controls how often blocklists and GeoIP are reloaded.
	// Zero uses 47 minutes.
	RefreshInterval time.Duration
	// GCInterval controls explicit GC after blocklist fetches. 0 defaults
	// to 24 (once daily at 47min cadence). -1 disables explicit GC.
	GCInterval int

	// --- GeoIP configuration (used by Run) ---

	// GeoIPDir is the directory holding the GeoLite2 tarballs. An external
	// geoip-update command owns downloads. Zero uses ~/.cache/maxmind.
	// Ignored when using programmatic setup.
	GeoIPDir string
	// AllowedCountries — if non-nil, only requests from listed ISO codes are
	// accepted. Unknown country ("") is always allowed. Requires GeoIP to be
	// loaded.
	AllowedCountries []string

	// --- Programmatic setup (alternative to Run) ---

	// Blacklist — if set, matching IPs are rejected before any other
	// processing. Ignored when using Run (which builds its own).
	Blacklist *dataset.View[ipcohort.Cohort]
	// Geo — required when AllowedCountries is set and using programmatic
	// setup. Provides the GeoLite2 City/ASN databases used for country
	// lookup. Ignored when using Run (which builds its own).
	Geo *dataset.View[geoip.Databases]

	// --- Internal state ---

	once     sync.Once
	initErr  error
	emailIdx int // index into Fields of the KindEmail entry
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	reqCount uint64

	// Run-only state
	blocklistSet   *dataset.Set
	geoSet         *dataset.Set
	blocklistView  *dataset.View[ipcohort.Cohort]
	geoView        *dataset.View[geoip.Databases]
	server         *http.Server
	serverErr      chan error
	ctx            context.Context
	cancel         context.CancelFunc
	blocklistReady chan struct{} // closed when blocklist is first loaded
	geoReady       chan struct{} // closed when geoip is first loaded
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

func (fm *FormMailer) successBody() []byte {
	if fm.SuccessBody == nil {
		return nil
	}
	return fm.SuccessBody()
}

func (fm *FormMailer) errorBody() []byte {
	if fm.ErrorBody == nil {
		return nil
	}
	return fm.ErrorBody()
}

func (fm *FormMailer) contentType() string {
	if fm.ContentType != "" {
		return fm.ContentType
	}
	probe := fm.successBody()
	if bytes.Contains(probe[:min(512, len(probe))], []byte("<html")) {
		return "text/html; charset=utf-8"
	}
	if bytes.HasPrefix(bytes.TrimSpace(probe), []byte("{")) {
		return "application/json"
	}
	return "text/plain; charset=utf-8"
}

// Run starts the formmailer server with its own blocklist and GeoIP data
// sources. It blocks until ctx is done or a fatal error occurs.
//
// Data sources:
//   - Blocklist: gitshallow clones the configured repo, ipcohort loads the
//     inbound cohort files, dataset manages hot-swap.
//   - GeoIP: an external geoip-update job owns downloads; formmailer polls
//     local City + ASN tarballs and geoip.Open extracts them in memory.
//
// Background refreshes run at RefreshInterval (default 47min). The server
// starts serving immediately; /healthz returns 503 until both blocklist and
// GeoIP are loaded (when configured).
//
// To shut down, cancel ctx or send SIGINT/SIGTERM — Run waits up to 10s for
// in-flight requests to drain.
func (fm *FormMailer) Run(ctx context.Context) error {
	// Set defaults.
	if fm.ListenAddr == "" {
		fm.ListenAddr = ":3081"
	}
	if fm.RefreshInterval == 0 {
		fm.RefreshInterval = defaultRefresh
	}
	if fm.GCInterval == 0 {
		fm.GCInterval = defaultGCInterval
	}
	if len(fm.BlocklistPaths) == 0 {
		fm.BlocklistPaths = []string{
			"tables/inbound/single_ips.txt",
			"tables/inbound/networks.txt",
		}
	}

	// Home directory for defaults.
	home, _ := os.UserHomeDir()
	if fm.CacheDir == "" && home != "" {
		fm.CacheDir = filepath.Join(home, ".cache")
	}

	// Git repo for blocklist.
	var repo *gitshallow.Repo
	if fm.BlocklistRepo != "" {
		repo = gitshallow.New(fm.BlocklistRepo,
			filepath.Join(fm.CacheDir, "bitwire-it"), 1, "")
		repo.MaxAge = fm.RefreshInterval
		repo.GCInterval = fm.GCInterval
	}

	// Blocklist dataset.
	var blocklistSet *dataset.Set
	var blocklistView *dataset.View[ipcohort.Cohort]
	if repo != nil {
		blocklistSet = dataset.NewSet(repo)
		blocklistView = dataset.AddInitial(blocklistSet, &ipcohort.Cohort{},
			func(ctx context.Context) (*ipcohort.Cohort, error) {
				paths := make([]string, len(fm.BlocklistPaths))
				for i, p := range fm.BlocklistPaths {
					paths[i] = repo.FilePath(p)
				}
				return ipcohort.LoadFiles(paths...)
			})
	}

	// GeoIP archives are downloaded by the external geoip-update command.
	// Formmailer only polls and reloads the local tarballs.
	geoDir := filepath.Join(fm.CacheDir, "maxmind")
	if fm.GeoIPDir != "" {
		geoDir = fm.GeoIPDir
	}

	dirPopulated := func(dir string) bool {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		return len(entries) > 0
	}

	var geoSet *dataset.Set
	var geoView *dataset.View[geoip.Databases]
	geoMode := "disabled"
	if dirPopulated(geoDir) {
		geoMode = "poll"
		cityPath := filepath.Join(geoDir, geoip.TarGzName(geoip.CityEdition))
		asnPath := filepath.Join(geoDir, geoip.TarGzName(geoip.ASNEdition))
		geoSet = dataset.NewSet(dataset.PollFiles(cityPath, asnPath))
		geoView = dataset.Add(geoSet, func(ctx context.Context) (*geoip.Databases, error) {
			return geoip.Open(geoDir)
		})
	}

	// Keep the views used by ServeHTTP in sync with the views owned by Run.
	// The local variables above are also passed to healthz, but ServeHTTP uses
	// these fields to select the Run-managed datasets.
	fm.blocklistSet = blocklistSet
	fm.blocklistView = blocklistView
	fm.geoSet = geoSet
	fm.geoView = geoView

	// Signal channels for readiness.
	fm.blocklistReady = make(chan struct{})
	fm.geoReady = make(chan struct{})

	// Context for background goroutines.
	fm.ctx, fm.cancel = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)

	// Initial load.
	if blocklistSet != nil {
		fmt.Fprint(os.Stderr, "Syncing blocklist ... ")
		t := time.Now()
		if err := blocklistSet.Load(fm.ctx); err != nil {
			fmt.Fprintln(os.Stderr)
			log.Printf("blocklist: %v", err)
		} else {
			sz := 0
			if v := blocklistView.Value(); v != nil {
				sz = v.Size()
			}
			fmt.Fprintf(os.Stderr, "%s (entries=%d)\n",
				time.Since(t).Round(time.Millisecond), sz)
			close(fm.blocklistReady)
		}
	}

	if geoSet != nil {
		fmt.Fprint(os.Stderr, "Loading geoip ... ")
		t := time.Now()
		if err := geoSet.Load(fm.ctx); err != nil {
			fmt.Fprintln(os.Stderr)
			log.Printf("geoip: %v", err)
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", time.Since(t).Round(time.Millisecond))
			close(fm.geoReady)
		}
	}

	// Background refreshes.
	if blocklistSet != nil {
		go blocklistSet.Tick(fm.ctx, fm.RefreshInterval, func(err error) {
			log.Printf("blocklist refresh: %v", err)
		})
	}
	if geoSet != nil {
		go geoSet.Tick(fm.ctx, fm.RefreshInterval, func(err error) {
			log.Printf("geoip refresh: %v", err)
		})
	}

	// Build the handler.
	mux := http.NewServeMux()

	// Form handler.
	emailFormName := ""
	for _, f := range fm.Fields {
		if f.Kind == KindEmail {
			emailFormName = f.FormName
			break
		}
	}
	contact := fm.handler(emailFormName)
	mux.Handle("POST /contact", contact)
	mux.Handle("POST /contact/", contact)

	// Healthz endpoint.
	mux.HandleFunc("GET /healthz", fm.healthz(blocklistView, geoView))

	// Root.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "formmailer server running. POST form data to /contact")
	})

	// Server.
	fm.server = &http.Server{
		Addr:    fm.ListenAddr,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return fm.ctx
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}

	fmt.Printf("formmailer listening on http://%s\n", fm.ListenAddr)
	fmt.Printf("Forwarding submissions from %s → %s via %s\n",
		fm.SMTPFrom, strings.Join(fm.SMTPTo, ","), fm.SMTPHost)
	fmt.Printf("Rate limit: ~%d req/min per IP (burst %d)\n",
		maxRate(fm.RPM), maxBurst(fm.Burst))
	if fm.BlocklistRepo != "" {
		fmt.Println("Blocklist: enabled")
	}
	if geoSet != nil && geoMode == "poll" {
		fmt.Printf("GeoIP: poll mode (dir=%s)\n", geoDir)
	}
	if len(fm.AllowedCountries) > 0 {
		fmt.Printf("Country gate: %s\n", strings.Join(fm.AllowedCountries, ", "))
	}
	fmt.Println("CTRL+C to stop")

	// Start server.
	fm.serverErr = make(chan error, 1)
	go func() {
		if err := fm.server.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			fm.serverErr <- err
		}
		close(fm.serverErr)
	}()

	// Wait for shutdown or error.
	select {
	case <-fm.ctx.Done():
		log.Printf("shutdown: %v", fm.ctx.Err())
	case err := <-fm.serverErr:
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}

	// Graceful shutdown.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := fm.server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}

	// Close datasets.
	if blocklistSet != nil {
		_ = blocklistSet.Close()
	}
	if geoSet != nil {
		_ = geoSet.Close()
	}
	return nil
}

// handler returns the form submission handler, optionally wrapping it with
// the .ru silent-drop trap (legacy spam-trap behavior).
func (fm *FormMailer) handler(emailFormName string) http.Handler {
	h := http.Handler(fm)
	if emailFormName != "" {
		h = silentDropRU(h, emailFormName, fm.successBody, fm.contentType())
	}
	return h
}

// healthz returns a handler that reports dataset load status.
func (fm *FormMailer) healthz(
	blocklist *dataset.View[ipcohort.Cohort],
	geo *dataset.View[geoip.Databases],
) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		type dsStatus struct {
			Loaded   bool      `json:"loaded"`
			Size     int       `json:"size,omitzero"`
			LoadedAt time.Time `json:"loaded_at,omitzero"`
		}
		cohortStatus := func(v *dataset.View[ipcohort.Cohort]) dsStatus {
			s := dsStatus{LoadedAt: v.LoadedAt()}
			if cur := v.Value(); cur != nil {
				s.Loaded, s.Size = true, cur.Size()
			}
			return s
		}

		status := make(map[string]dsStatus)
		if blocklist != nil {
			status["blocklist"] = cohortStatus(blocklist)
		}
		if geo != nil {
			s := dsStatus{LoadedAt: geo.LoadedAt()}
			if v := geo.Value(); v != nil {
				s.Loaded = true
			}
			status["geoip"] = s
		}

		ready := true
		if blocklist != nil && !status["blocklist"].Loaded {
			ready = false
		}
		if geo != nil && !status["geoip"].Loaded {
			ready = false
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ready":     ready,
			"databases": status,
		})
	}
}

// ServeHTTP implements http.Handler. It validates, rate-limits, and emails
// contact form submissions. When using Run, the handler is wired internally;
// when used programmatically, callers wire it into their own mux.
func (fm *FormMailer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fm.once.Do(fm.init)
	if fm.initErr != nil {
		log.Printf("contact form: misconfigured: %v", fm.initErr)
		http.Error(w, "contact form misconfigured", http.StatusInternalServerError)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFormSize)
	if err := r.ParseMultipartForm(maxFormSize); err != nil {
		http.Error(w, "form too large or invalid", http.StatusBadRequest)
		return
	}

	ipStr := fm.clientIP(r)
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		fm.writeError(w, fmt.Errorf("malformed client IP"), true)
		return
	}

	// Use Run-provided views or programmatic views.
	var blacklist *dataset.View[ipcohort.Cohort]
	var geo *dataset.View[geoip.Databases]
	if fm.BlocklistRepo != "" {
		blacklist = fm.blocklistView
	} else {
		blacklist = fm.Blacklist
	}
	if fm.BlocklistRepo != "" || fm.geoView != nil {
		geo = fm.geoView
	} else {
		geo = fm.Geo
	}

	if blacklist != nil {
		if c := blacklist.Value(); c != nil && c.ContainsAddr(ip) {
			fm.writeError(w, fmt.Errorf("automated requests are not accepted"), false)
			return
		}
	}

	if fm.AllowedCountries != nil && geo != nil {
		if v := geo.Value(); v != nil {
			country := v.Lookup(ipStr).CountryISO
			if country != "" && !slices.Contains(fm.AllowedCountries, country) {
				fm.writeError(w,
					fmt.Errorf("submissions from your region are not accepted; please email us directly"), true)
				return
			}
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
	log.Printf("contact form: sent ip=%s from=%q to=%s", ipStr, email, strings.Join(fm.SMTPTo, ","))

	w.Header().Set("Content-Type", fm.contentType())
	_, _ = w.Write(fm.successBody())
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
	// NewClient sets the peer name used for AUTH binding and TLS SNI — that
	// must be the SMTP server's hostname. Hello() overrides the *client*
	// identity announced in EHLO; stdlib conflates these into one API but
	// they're semantically distinct.
	c, err := smtp.NewClient(conn, hostname)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer func() { _ = c.Close() }()
	localName := fm.LocalName
	if localName == "" {
		if h, err := os.Hostname(); err == nil {
			localName = h
		} else {
			localName = "localhost"
		}
	}
	if err := c.Hello(localName); err != nil {
		return fmt.Errorf("ehlo: %w", err)
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := fm.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{ServerName: hostname}
		}
		if err := c.StartTLS(tlsCfg); err != nil {
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
		support = fm.HiddenSupportValue
	}
	b := bytes.ReplaceAll(fm.errorBody(), []byte("{.Error}"), []byte(err.Error()))
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

// clientIP returns the originating IP. If the immediate peer (r.RemoteAddr)
// is inside TrustedProxies, the left-most X-Forwarded-For entry is used
// instead. Without TrustedProxies, XFF is ignored — otherwise any client
// could forge their address to bypass rate limits and geo gating.
func (fm *FormMailer) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	peer, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	for _, cidr := range fm.TrustedProxies {
		if cidr.Contains(peer) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				first, _, _ := strings.Cut(xff, ",")
				return strings.TrimSpace(first)
			}
			break
		}
	}
	return remote
}

// silentDropRU returns a handler that silently returns the success body for
// submissions whose email (emailFormName form input) ends with ".ru" —
// legacy spam-trap behavior from the original form2mail. All other
// submissions fall through to h.
func silentDropRU(h http.Handler, emailFormName string, successBody func() []byte, contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ParseMultipartForm is safe to call twice; formmailer will see the
		// already-parsed form. Use a bounded reader to match formmailer's cap.
		r.Body = http.MaxBytesReader(w, r.Body, 10*1024)
		if err := r.ParseMultipartForm(10 * 1024); err == nil {
			email := strings.ToLower(strings.TrimSpace(r.FormValue(emailFormName)))
			if strings.HasSuffix(email, ".ru") {
				w.Header().Set("Content-Type", contentType)
				_, _ = w.Write(successBody())
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// maxRate and maxBurst are helpers to avoid zero values in log output.
func maxRate(r int) int {
	if r == 0 {
		return defaultRPM
	}
	return r
}
func maxBurst(b int) int {
	if b == 0 {
		return defaultBurst
	}
	return b
}
