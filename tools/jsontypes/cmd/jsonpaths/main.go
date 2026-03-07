package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/therootcompany/golib/tools/jsontypes"
)

const (
	name        = "jsonpaths"
	description = "Infer types from JSON. Generate code."
)

var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	fmt.Fprintf(w, "%s\n", description)
}

// headerList implements flag.Value for repeatable -H flags.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(val string) error {
	if !strings.Contains(val, ":") {
		return fmt.Errorf("header must be in 'Name: Value' format")
	}
	*h = append(*h, val)
	return nil
}

func main() {
	// Exit cleanly on Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr)
		os.Exit(130)
	}()

	var headers headerList
	flag.Var(&headers, "H", "add HTTP header (repeatable, e.g. -H 'X-API-Key: abc')")
	anonymous := flag.Bool("anonymous", false, "skip all prompts; use heuristics and auto-inferred names")
	askTypes := flag.Bool("ask-types", false, "prompt for each type name instead of auto-inferring")
	bearer := flag.String("bearer", "", "set Authorization: Bearer token")
	cookie := flag.String("cookie", "", "send cookie (name=value or Set-Cookie format)")
	cookieJar := flag.String("cookie-jar", "", "read cookies from Netscape cookie jar file")
	format := flag.String("format", "json-paths", "output format: json-paths, go, json-schema, json-typedef, typescript, jsdoc, zod, python, sql")
	timeout := flag.Duration("timeout", 20*time.Second, "HTTP request timeout for URL inputs")
	noCache := flag.Bool("no-cache", false, "skip local cache for URL inputs")
	user := flag.String("user", "", "HTTP basic auth (user:password, like curl)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE\n  %s [flags] [file | url]\n\n", name)
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		flag.PrintDefaults()
	}

	// Handle version/help before flag parse
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg == "-V" || arg == "--version" || arg == "version" {
			printVersion(os.Stdout)
			os.Exit(0)
		}
		if arg == "help" || arg == "-help" || arg == "--help" {
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout)
			flag.CommandLine.SetOutput(os.Stdout)
			flag.Usage()
			os.Exit(0)
		}
	}

	flag.Parse()

	var input io.Reader
	var baseName string // base filename for .paths and .answers files
	inputIsStdin := true
	// Build extra HTTP headers from flags
	var extraHeaders http.Header
	if *bearer != "" || *user != "" || *cookie != "" || *cookieJar != "" || len(headers) > 0 {
		extraHeaders = make(http.Header)
	}
	for _, h := range headers {
		name, value, _ := strings.Cut(h, ":")
		extraHeaders.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if *bearer != "" {
		extraHeaders.Set("Authorization", "Bearer "+*bearer)
	}
	if *user != "" {
		extraHeaders.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(*user)))
	}
	if *cookie != "" {
		extraHeaders.Add("Cookie", parseCookieFlag(*cookie))
	}
	if *cookieJar != "" {
		cookies, err := readCookieJar(*cookieJar)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading cookie jar: %v\n", err)
			os.Exit(1)
		}
		for _, c := range cookies {
			extraHeaders.Add("Cookie", c)
		}
	}

	if args := flag.Args(); len(args) > 0 && args[0] != "-" {
		arg := args[0]
		if strings.HasPrefix(arg, "https://") || strings.HasPrefix(arg, "http://") {
			r, err := fetchOrCache(arg, *timeout, *noCache, extraHeaders)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			defer r.Close()
			input = r
			baseName = stripExt(slugify(arg))
		} else {
			f, err := os.Open(arg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			input = f
			baseName = stripExt(arg)
		}
		inputIsStdin = false
	} else {
		input = os.Stdin
	}

	var data any
	dec := json.NewDecoder(input)
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	a, err := jsontypes.NewAnalyzer(inputIsStdin, *anonymous, *askTypes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer a.Close()

	// Load prior answers if available
	if baseName != "" && !*anonymous {
		a.Prompter.LoadAnswers(baseName + ".answers")
	}

	rawPaths := a.Analyze(".", data)
	formatted := jsontypes.FormatPaths(rawPaths)

	switch *format {
	case "go":
		fmt.Print(jsontypes.GenerateGoStructs(formatted))
	case "json-typedef":
		fmt.Print(jsontypes.GenerateTypedef(formatted))
	case "json-schema":
		fmt.Print(jsontypes.GenerateJSONSchema(formatted))
	case "typescript", "ts":
		fmt.Print(jsontypes.GenerateTypeScript(formatted))
	case "jsdoc":
		fmt.Print(jsontypes.GenerateJSDoc(formatted))
	case "zod":
		fmt.Print(jsontypes.GenerateZod(formatted))
	case "python", "py":
		fmt.Print(jsontypes.GeneratePython(formatted))
	case "sql":
		fmt.Print(jsontypes.GenerateSQL(formatted))
	case "json-paths", "paths", "":
		for _, p := range formatted {
			fmt.Println(p)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q (use: json-paths, go, json-schema, json-typedef, typescript, jsdoc, zod, python, sql)\n", *format)
		os.Exit(1)
	}

	// Save outputs
	if baseName != "" {
		pathsFile := baseName + ".paths"
		if err := os.WriteFile(pathsFile, []byte(strings.Join(formatted, "\n")+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not write %s: %v\n", pathsFile, err)
		}

		if !*anonymous {
			answersFile := baseName + ".answers"
			if err := a.Prompter.SaveAnswers(answersFile); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not write %s: %v\n", answersFile, err)
			}
		}
	}
}

func stripExt(name string) string {
	if idx := strings.LastIndexByte(name, '.'); idx > 0 {
		return name[:idx]
	}
	return name
}

// slugify converts a URL to a filesystem-safe filename in the current directory.
func slugify(rawURL string) string {
	s := rawURL
	for _, prefix := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, prefix)
	}

	path := s
	query := ""
	if idx := strings.IndexByte(s, '?'); idx >= 0 {
		path = s[:idx]
		query = s[idx+1:]
	}

	if query != "" {
		var kept []string
		for _, param := range strings.Split(query, "&") {
			name := param
			if idx := strings.IndexByte(param, '='); idx >= 0 {
				name = param[:idx]
			}
			nameLower := strings.ToLower(name)
			if isSensitiveParam(nameLower) {
				continue
			}
			if len(param) > len(name)+21 {
				continue
			}
			kept = append(kept, param)
		}
		if len(kept) > 0 {
			path = path + "-" + strings.Join(kept, "-")
		}
	}

	var buf strings.Builder
	lastHyphen := false
	for _, r := range path {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' {
			buf.WriteRune(r)
			lastHyphen = false
		} else if !lastHyphen {
			buf.WriteByte('-')
			lastHyphen = true
		}
	}
	name := strings.Trim(buf.String(), "-")
	if len(name) > 200 {
		name = name[:200]
	}
	return name + ".json"
}

var sensitiveParams = []string{
	"secret", "token", "code", "key", "apikey", "api_key",
	"password", "passwd", "auth", "credential", "session",
	"access_token", "refresh_token", "client_secret",
}

func isSensitiveParam(name string) bool {
	for _, s := range sensitiveParams {
		if name == s || strings.Contains(name, s) {
			return true
		}
	}
	return false
}

func fetchOrCache(rawURL string, timeout time.Duration, noCache bool, extraHeaders http.Header) (io.ReadCloser, error) {
	if !noCache {
		path := slugify(rawURL)
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			f, err := os.Open(path)
			if err == nil {
				fmt.Fprintf(os.Stderr, "using cached ./%s\n  (use --no-cache to re-fetch)\n", path)
				return f, nil
			}
		}
	}

	body, err := fetchURL(rawURL, timeout, extraHeaders)
	if err != nil {
		return nil, err
	}

	if noCache {
		return body, nil
	}

	path := slugify(rawURL)
	data, err := io.ReadAll(body)
	body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not cache response: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "cached to ./%s\n", path)
	}

	return io.NopCloser(strings.NewReader(string(data))), nil
}

func fetchURL(url string, timeout time.Duration, extraHeaders http.Header) (io.ReadCloser, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 0,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			MaxIdleConns:          1,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	for name, vals := range extraHeaders {
		for _, v := range vals {
			req.Header.Add(name, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if isTimeout(err) {
			return nil, fmt.Errorf("request timed out after %s (use --timeout 60s to increase timeout for slow APIs)", timeout)
		}
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, resp.Status)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "json") && !strings.Contains(ct, "javascript") {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected Content-Type %q (expected JSON)", ct)
	}

	return struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp.Body, 256<<20),
		Closer: resp.Body,
	}, nil
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return strings.Contains(err.Error(), "deadline exceeded") ||
		strings.Contains(err.Error(), "timed out")
}

func parseCookieFlag(raw string) string {
	s := raw
	for _, prefix := range []string{"Set-Cookie:", "Cookie:"} {
		if strings.HasPrefix(s, prefix) {
			s = strings.TrimSpace(s[len(prefix):])
			break
		}
		lower := strings.ToLower(s)
		lowerPrefix := strings.ToLower(prefix)
		if strings.HasPrefix(lower, lowerPrefix) {
			s = strings.TrimSpace(s[len(prefix):])
			break
		}
	}
	if idx := strings.IndexByte(s, ';'); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	return s
}

func readCookieJar(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cookies []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		name := fields[5]
		value := fields[6]
		cookies = append(cookies, name+"="+value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cookies, nil
}
