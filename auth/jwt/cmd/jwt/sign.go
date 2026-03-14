package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// rawClaims wraps a map so it satisfies jwt.Claims and marshals to
// arbitrary JSON. GetIDTokenClaims is a stub — the sign path only needs
// json.Marshal, not validation.
type rawClaims map[string]any

func (r rawClaims) GetIDTokenClaims() *jwt.IDTokenClaims {
	return &jwt.IDTokenClaims{}
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("jwt sign", flag.ContinueOnError)
	keyFlag := fs.String("key", "", "private key source: file path or inline JWK JSON")
	timeFlag := fs.String("time", "", "reference time for relative claims (ISO 8601 or Unix epoch; default: now)")
	expFlag := fs.String("exp", "", "expiration: duration from --time (e.g. 15m, 1h) or absolute epoch")
	nbfFlag := fs.String("nbf", "", "not-before: duration relative to --time (e.g. -5s, 30s) or absolute epoch")
	iatFlag := fs.String("iat", "", "issued-at: duration relative to --time (e.g. -1h, +0s) or absolute epoch (default: --time)")
	issFlag := fs.String("iss", "", "issuer claim")
	subFlag := fs.String("sub", "", "subject claim")
	audFlag := fs.String("aud", "", "audience claim (comma-separated for multiple)")
	jtiFlag := fs.String("jti", "", "JWT ID claim")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resolve reference time.
	refTime, err := parseTime(*timeFlag)
	if err != nil {
		return fmt.Errorf("--time: %w", err)
	}

	// Load private key.
	keySource, err := resolvePrivateKeySource(*keyFlag)
	if err != nil {
		return err
	}
	privKeys, err := loadPrivateKeys(keySource)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	signer, err := jwt.NewSigner(privKeys)
	if err != nil {
		return err
	}

	// Read claims JSON from positional arg or stdin.
	var claims rawClaims
	if fs.NArg() > 0 {
		input, err := readInput(fs.Arg(0))
		if err != nil {
			return fmt.Errorf("read claims: %w", err)
		}
		if err := json.Unmarshal([]byte(input), &claims); err != nil {
			return fmt.Errorf("parse claims JSON: %w", err)
		}
	} else {
		claims = make(rawClaims)
	}

	// Apply claim flags — flags override JSON values.
	if *issFlag != "" {
		claims["iss"] = *issFlag
	}
	if *subFlag != "" {
		claims["sub"] = *subFlag
	}
	if *audFlag != "" {
		parts := strings.Split(*audFlag, ",")
		if len(parts) == 1 {
			claims["aud"] = parts[0]
		} else {
			claims["aud"] = parts
		}
	}
	if *jtiFlag != "" {
		claims["jti"] = *jtiFlag
	}

	// Apply time-based claims.
	if *iatFlag != "" {
		v, err := parseTimeOrDuration(*iatFlag, refTime)
		if err != nil {
			return fmt.Errorf("--iat: %w", err)
		}
		claims["iat"] = v
	} else if _, ok := claims["iat"]; !ok {
		// Default iat to reference time.
		claims["iat"] = refTime.Unix()
	}

	if *expFlag != "" {
		v, err := parseTimeOrDuration(*expFlag, refTime)
		if err != nil {
			return fmt.Errorf("--exp: %w", err)
		}
		claims["exp"] = v
	}

	if *nbfFlag != "" {
		v, err := parseTimeOrDuration(*nbfFlag, refTime)
		if err != nil {
			return fmt.Errorf("--nbf: %w", err)
		}
		claims["nbf"] = v
	}

	token, err := signer.SignToString(claims)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	fmt.Fprintln(os.Stdout, token)
	return nil
}

// resolvePrivateKeySource resolves the key source from flag or env vars.
func resolvePrivateKeySource(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if v := os.Getenv("JWT_PRIVATE_KEY"); v != "" {
		return v, nil
	}
	if v := os.Getenv("JWT_PRIVATE_KEY_FILE"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no key provided: use --key, JWT_PRIVATE_KEY, or JWT_PRIVATE_KEY_FILE")
}

// parseTime parses a time string as ISO 8601, Unix epoch, or returns now if empty.
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Now(), nil
	}

	// Try Unix epoch (integer).
	if epoch, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(epoch, 0), nil
	}

	// Try ISO 8601 formats.
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unrecognized time format %q (use ISO 8601 or Unix epoch)", s)
}

// parseTimeOrDuration parses a value that is either:
//   - A duration relative to refTime (e.g. "15m", "-1h", "+30s")
//   - An absolute Unix epoch (e.g. "1700000000")
//
// Returns the resolved Unix timestamp.
func parseTimeOrDuration(s string, refTime time.Time) (int64, error) {
	// Try as duration first (handles "15m", "+1h", "-30s").
	// Go's time.ParseDuration doesn't handle the leading '+' but we can strip it.
	durStr := s
	if strings.HasPrefix(durStr, "+") {
		durStr = durStr[1:]
	}
	if d, err := time.ParseDuration(durStr); err == nil {
		return refTime.Add(d).Unix(), nil
	}

	// Try as absolute epoch.
	if epoch, err := strconv.ParseInt(s, 10, 64); err == nil {
		return epoch, nil
	}

	return 0, fmt.Errorf("unrecognized value %q (use duration like 15m or Unix epoch)", s)
}

// newSignerFromKeys creates a signer, auto-deriving Use="sig" for keys.
func newSignerFromKeys(keys []jwk.PrivateKey) (*jwt.Signer, error) {
	for i := range keys {
		if keys[i].Use == "" {
			keys[i].Use = "sig"
		}
	}
	return jwt.NewSigner(keys)
}
