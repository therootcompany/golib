package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type MainConfig struct {
	name   string
	cookie string
	secret string
}

func main() {
	cfg := MainConfig{}

	flag.StringVar(&cfg.secret, "secret", "", "The secret used to sign the cookie (same as in Express)")
	flag.StringVar(&cfg.name, "name", "", "Optional: cookie name (just for display)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: express-cookie-parse [flags]

Parses a raw browser Cookie: header string and inspects each cookie.
Also verifies Express.js signed cookie (cookie-parser) format.

Examples:
  cookie-inspect "session=s:user123.J%%2BsOPk...; lang=en"
  echo 'session=s:payload.sig; theme=dark' | cookie-inspector --secret "my-secret"

Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) > 0 {
		cfg.cookie = args[0]
	}
	if cfg.cookie == "" {
		// Try reading from stdin
		data, err := os.ReadFile("/dev/stdin")
		if err != nil || len(data) == 0 {
			fmt.Fprintln(os.Stderr, "Error: Provide cookie value via --cookie or pipe to stdin")
			flag.Usage()
			os.Exit(1)
		}
		cfg.cookie = strings.TrimSpace(string(data))
	}
	fmt.Println("Cookies:", cfg.cookie)

	var cookies []*http.Cookie
	c, err := http.ParseSetCookie(cfg.cookie)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse Cookie header: %v\n", err)
		os.Exit(1)
	}
	cookies = append(cookies, c)

	for _, c := range cookies {
		inspectCookie(c, cfg.secret)
	}
}

func inspectCookie(c *http.Cookie, secret string) {
	fmt.Printf("Cookie: %s\n", c.Name)
	fmt.Printf("%+#v\n\n", c)
	cookieVal, err := url.QueryUnescape(c.Value)
	if err != nil {
		cookieVal = c.Value
	}
	fmt.Printf("%s\n\n", c.Value)
	fmt.Printf("%s\n\n", cookieVal)

	if !strings.HasPrefix(cookieVal, "s:") {
		fmt.Println("   Not an express cookie (no 's:' prefix)")
		return
	}

	fmt.Println("   looks like express.js signed format (s:payload.signature)")
	payload64, sig64, err := DecodeSignedValue(cookieVal)
	if err != nil {
		fmt.Printf("  Decoding express payload failed: %v\n", err)
		return
	}

	data64 := payload64
	parts := strings.Split(payload64, ".")
	if len(parts) == 3 {
		data64 = parts[1]
	}
	if data, err := base64.StdEncoding.DecodeString(data64); err != nil {
		fmt.Printf("  Base64 decode failed: %v\n", err)
	} else {
		fmt.Printf("  Base64 decoded (std): %s\n", string(data))
	}

	if secret == "" {
		fmt.Println("  (Verification skipped — provide --secret to check signature)")
	} else {
		if err := VerifyHMAC(payload64, sig64, secret); err != nil {
			fmt.Printf("  Verification failed: %v\n", err)
			return
		}
		fmt.Printf("  Verified payload.\n")
	}
}

func EncodeSignedValue(value, sig string) string {
	return url.QueryEscape("s:" + value + "." + sig)
}

// SignCookie creates an Express-style signed cookie value.
//
//	"s:" + rawValue + "." + base64url(signature)
//
// This is exactly what cookie-signature.sign(value, secret) produces in Node.js.
// The result can be set directly as cookie.Value (or via http.Cookie).
func SignValue(value, secret string) string {
	if secret == "" {
		panic(fmt.Errorf("secret is empty"))
	}

	// Compute HMAC-SHA256 of the raw value (not base64!)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	signature := mac.Sum(nil)

	// base64url, no padding — exactly as cookie-signature does
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Final format: s:value.signature
	return sigB64
}

func DecodeSignedValue(signed string) (string, string, error) {
	signed, err := url.QueryUnescape(signed)
	if err != nil {
		return "", "", err
	}
	withoutPrefix := signed[2:]

	dotIdx := strings.LastIndex(withoutPrefix, ".")
	if dotIdx == -1 {
		return "", "", fmt.Errorf("missing '.' separator")
	}

	payload := withoutPrefix[:dotIdx]
	sigReceived := withoutPrefix[dotIdx+1:]

	return payload, sigReceived, nil
}

func VerifyHMAC(expressPayload, expressSig, cookieSecret string) error {
	if cookieSecret == "" {
		return fmt.Errorf("no secret provided")
	}

	mac := hmac.New(sha256.New, []byte(cookieSecret))
	mac.Write([]byte(expressPayload))
	expectedSig := mac.Sum(nil)

	expectedB64 := base64.RawURLEncoding.EncodeToString(expectedSig)

	if !hmac.Equal([]byte(expectedB64), []byte(expressSig)) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}
