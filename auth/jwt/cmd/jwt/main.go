// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Command jwt is a CLI tool for signing, verifying, inspecting, and
// generating JSON Web Tokens and Keys.
//
// Usage:
//
//	jwt sign    --key <key> [claims]      sign claims into a compact JWT
//	jwt inspect [token]                   decode and display token details
//	jwt verify  --key <key> [token]       verify signature and validate claims
//	jwt keygen  [--alg EdDSA]             generate a fresh private key
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "sign":
		err = cmdSign(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: jwt <command> [options]

Commands:
  sign      Sign claims into a compact JWT
  inspect   Decode and display token details
  verify    Verify signature and validate claims
  keygen    Generate a fresh private key (JWK)

Run 'jwt <command> --help' for details on each command.
`)
}

// --- sign ---

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
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: jwt sign [options] [claims-json]\n\n")
		fmt.Fprintf(os.Stderr, "Sign claims into a compact JWT and print to stdout.\n\n")
		fmt.Fprintf(os.Stderr, "Claims may be a JSON string, file path, or piped via stdin.\n")
		fmt.Fprintf(os.Stderr, "Flags override any values present in the claims JSON.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment:\n")
		fmt.Fprintf(os.Stderr, "  JWT_PRIVATE_KEY       inline JWK JSON (fallback for --key)\n")
		fmt.Fprintf(os.Stderr, "  JWT_PRIVATE_KEY_FILE  file path (fallback for --key)\n")
	}
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

// --- inspect ---

// inspectResult is the JSON output structure for inspect and verify.
type inspectResult struct {
	Header    json.RawMessage `json:"header"`
	Claims    json.RawMessage `json:"claims"`
	Protected string          `json:"protected"`
	Payload   string          `json:"payload"`
	Signature string          `json:"signature"`

	// Discovery fields (inspect only).
	JWKsURL *string          `json:"jwks_url,omitempty"`
	JWK     *json.RawMessage `json:"jwk,omitempty"`

	Verified  bool     `json:"verified"`
	Validated bool     `json:"validated"`
	Errors    []string `json:"errors,omitempty"`
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("jwt inspect", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: jwt inspect [token]\n\n")
		fmt.Fprintf(os.Stderr, "Decode a JWT and display header, claims, and token details.\n\n")
		fmt.Fprintf(os.Stderr, "If the issuer (iss) looks like a URL, attempts OIDC/OAuth2\n")
		fmt.Fprintf(os.Stderr, "discovery to fetch public keys and verify the signature.\n\n")
		fmt.Fprintf(os.Stderr, "Token may be a string, file path, or piped via stdin.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Read token from positional arg or stdin.
	var arg string
	if fs.NArg() > 0 {
		arg = fs.Arg(0)
	}
	tokenStr, err := readInput(arg)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}

	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}

	result := buildInspectResult(jws)

	// Unmarshal claims to check iss for discovery.
	var claims jwt.IDTokenClaims
	if err := jwt.UnmarshalClaims(jws, &claims); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("unmarshal claims: %v", err))
	}

	// Opportunistic OIDC/OAuth2 discovery.
	exitCode := 0
	if claims.Iss != "" && looksLikeURL(claims.Iss) {
		keys, jwksURL, discoveryErr := tryDiscovery(claims.Iss)
		if jwksURL != "" {
			result.JWKsURL = &jwksURL
		}
		if discoveryErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("discovery: %v", discoveryErr))
			// Non-zero exit if JWKS URL found but no usable keys.
			if jwksURL != "" {
				exitCode = 1
			}
		}
		if len(keys) > 0 {
			verifier := jwt.NewVerifier(keys)
			if err := verifier.Verify(jws); err == nil {
				result.Verified = true
				// Find the matching key.
				hdr := jws.GetHeader()
				for _, k := range keys {
					if k.KID == hdr.KID {
						raw, _ := json.Marshal(k)
						msg := json.RawMessage(raw)
						result.JWK = &msg
						break
					}
				}
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("verify: %v", err))
			}
		}
	}

	// Run basic validation.
	validator := &jwt.RFCValidator{}
	details, valErr := validator.Validate(&claims, time.Now())
	if valErr == nil {
		result.Validated = true
	} else {
		for _, d := range details {
			result.Errors = append(result.Errors, d.Error())
		}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(data))

	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// buildInspectResult creates the base inspect result from a decoded JWS.
func buildInspectResult(jws *jwt.JWS) inspectResult {
	protected := string(jws.GetProtected())
	payload := string(jws.GetPayload())
	signature := base64.RawURLEncoding.EncodeToString(jws.GetSignature())

	// Decode header and claims for display.
	headerJSON, _ := base64.RawURLEncoding.DecodeString(protected)
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(payload)

	return inspectResult{
		Header:    json.RawMessage(headerJSON),
		Claims:    json.RawMessage(claimsJSON),
		Protected: protected,
		Payload:   payload,
		Signature: signature,
	}
}

// looksLikeURL returns true if s looks like an HTTP(S) URL.
func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

// tryDiscovery attempts OIDC then OAuth2 discovery from an issuer URL.
// Returns any keys found, the JWKS URL (if discovered), and any error.
func tryDiscovery(issuer string) (keys []jwk.PublicKey, jwksURL string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try OIDC first.
	keys, err = jwk.FetchOIDC(ctx, issuer, nil)
	if err == nil && len(keys) > 0 {
		jwksURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
		return keys, jwksURL, nil
	}

	// Try OAuth2.
	keys, err = jwk.FetchOAuth2(ctx, issuer, nil)
	if err == nil && len(keys) > 0 {
		jwksURL = strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server"
		return keys, jwksURL, nil
	}

	// Try direct JWKS at issuer/.well-known/jwks.json.
	directURL := strings.TrimRight(issuer, "/") + "/.well-known/jwks.json"
	keys, _, fetchErr := jwk.FetchURL(ctx, directURL, nil)
	if fetchErr == nil && len(keys) > 0 {
		return keys, directURL, nil
	}

	if err != nil {
		return nil, "", err
	}
	return nil, "", fetchErr
}

// --- verify ---

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("jwt verify", flag.ContinueOnError)
	keyFlag := fs.String("key", "", "public key source: file path, URL (https://), or inline JWK/JWKS JSON")
	gracePeriod := fs.Duration("grace-period", 0, "clock skew tolerance for time-based claims (e.g. 5s)")
	ignoreExp := fs.Bool("ignore-exp", false, "do not fail on expired tokens")
	ignoreNBF := fs.Bool("ignore-nbf", false, "do not fail on not-yet-valid tokens")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: jwt verify [options] [token]\n\n")
		fmt.Fprintf(os.Stderr, "Verify a JWT signature and validate claims.\n\n")
		fmt.Fprintf(os.Stderr, "Token may be a string, file path, or piped via stdin.\n")
		fmt.Fprintf(os.Stderr, "If --key points to a private key, the public key is derived.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment:\n")
		fmt.Fprintf(os.Stderr, "  JWT_PUBLIC_JWK        inline JWK JSON (fallback for --key)\n")
		fmt.Fprintf(os.Stderr, "  JWT_PRIVATE_KEY        inline private JWK (derives public key)\n")
		fmt.Fprintf(os.Stderr, "  JWT_PRIVATE_KEY_FILE   file path to private key\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Read token from positional arg or stdin.
	var arg string
	if fs.NArg() > 0 {
		arg = fs.Arg(0)
	}
	tokenStr, err := readInput(arg)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}

	// Load public keys.
	keySource, err := resolvePublicKeySource(*keyFlag)
	if err != nil {
		return err
	}
	pubKeys, err := loadPublicKeys(keySource)
	if err != nil {
		// Fall back to deriving public from private key.
		pubKeys, err = loadPublicKeysFromPrivate(keySource)
		if err != nil {
			return fmt.Errorf("load key: %w", err)
		}
	}

	verifier := jwt.NewVerifier(pubKeys)

	// Decode and verify.
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}

	result := buildInspectResult(jws)

	verifyErr := verifier.Verify(jws)
	if verifyErr == nil {
		result.Verified = true
		// Find the matching key.
		hdr := jws.GetHeader()
		for _, k := range pubKeys {
			if k.KID == hdr.KID {
				raw, _ := json.Marshal(k)
				msg := json.RawMessage(raw)
				result.JWK = &msg
				break
			}
		}
	} else {
		result.Errors = append(result.Errors, fmt.Sprintf("verify: %v", verifyErr))
	}

	// Unmarshal and validate claims.
	var claims jwt.IDTokenClaims
	if err := jwt.UnmarshalClaims(jws, &claims); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("unmarshal claims: %v", err))
	} else {
		validator := &jwt.RFCValidator{
			ValidatorCore: jwt.ValidatorCore{
				GracePeriod: *gracePeriod,
				IgnoreExp:   *ignoreExp,
				IgnoreNBF:   *ignoreNBF,
			},
		}
		details, valErr := validator.Validate(&claims, time.Now())
		if valErr == nil {
			result.Validated = true
		} else {
			for _, d := range details {
				result.Errors = append(result.Errors, d.Error())
			}
		}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(data))

	if len(result.Errors) > 0 {
		os.Exit(1)
	}
	return nil
}

// resolvePublicKeySource resolves the key source from flag or env vars.
// Falls back to private key env vars (caller derives public from private).
func resolvePublicKeySource(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	if v := os.Getenv("JWT_PUBLIC_JWK"); v != "" {
		return v, nil
	}
	if v := os.Getenv("JWT_PRIVATE_KEY"); v != "" {
		return v, nil
	}
	if v := os.Getenv("JWT_PRIVATE_KEY_FILE"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("no key provided: use --key, JWT_PUBLIC_JWK, JWT_PRIVATE_KEY, or JWT_PRIVATE_KEY_FILE")
}

// --- keygen ---

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("jwt keygen", flag.ContinueOnError)
	alg := fs.String("alg", "EdDSA", "algorithm: EdDSA, ES256, ES384, ES512, RS256")
	kid := fs.String("kid", "", "key ID (auto-computed from thumbprint if empty)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: jwt keygen [options]\n\n")
		fmt.Fprintf(os.Stderr, "Generate a fresh private key and print as JWK to stdout.\n")
		fmt.Fprintf(os.Stderr, "The corresponding public key is printed to stderr.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	var pk *jwk.PrivateKey
	var err error

	switch *alg {
	case "EdDSA":
		pk, err = jwk.NewPrivateKey()
	case "ES256":
		pk, err = keygenEC(elliptic.P256())
	case "ES384":
		pk, err = keygenEC(elliptic.P384())
	case "ES512":
		pk, err = keygenEC(elliptic.P521())
	case "RS256":
		pk, err = keygenRSA()
	default:
		return fmt.Errorf("unsupported algorithm %q (use EdDSA, ES256, ES384, ES512, or RS256)", *alg)
	}
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	if *kid != "" {
		pk.KID = *kid
	}

	data, err := json.MarshalIndent(pk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(data))

	// Print public key to stderr for convenience.
	pub := pk.PublicKey()
	pubData, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	fmt.Fprintf(os.Stderr, "# public key:\n%s\n", pubData)

	return nil
}

func keygenEC(curve elliptic.Curve) (*jwk.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	pk := &jwk.PrivateKey{Signer: priv}
	kid, err := pk.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("compute thumbprint: %w", err)
	}
	pk.KID = kid
	return pk, nil
}

func keygenRSA() (*jwk.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pk := &jwk.PrivateKey{Signer: priv}
	kid, err := pk.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("compute thumbprint: %w", err)
	}
	pk.KID = kid
	return pk, nil
}

// --- shared helpers ---

// readInput resolves a positional argument to its content string.
//
//  1. If arg is "" or "-", read from stdin.
//  2. If arg is a file path that exists on disk, read the file.
//  3. Otherwise treat arg as a literal string.
func readInput(arg string) (string, error) {
	if arg == "" || arg == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Try as file path first.
	if _, err := os.Stat(arg); err == nil {
		data, err := os.ReadFile(arg)
		if err != nil {
			return "", fmt.Errorf("read file %q: %w", arg, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Treat as literal string.
	return arg, nil
}

// readSource reads data from a source string — either a file path or inline JSON.
func readSource(source string) ([]byte, error) {
	// If it looks like JSON (starts with '{' or '['), treat as inline.
	trimmed := strings.TrimSpace(source)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return []byte(trimmed), nil
	}

	// Otherwise treat as file path.
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("read key file %q: %w", source, err)
	}
	return data, nil
}

// loadPrivateKeys loads private key(s) from a source string.
// The source can be a file path or inline JWK/JWKS JSON.
//
// Accepts both a single JWK {"kty":..., "d":...} and a JWKS {"keys":[...]}.
func loadPrivateKeys(source string) ([]jwk.PrivateKey, error) {
	data, err := readSource(source)
	if err != nil {
		return nil, err
	}

	// Try as single private key JWK.
	var pk jwk.PrivateKey
	if err := json.Unmarshal(data, &pk); err == nil {
		return []jwk.PrivateKey{pk}, nil
	}

	// Try as JWKS with private keys.
	var rawKeys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &rawKeys); err == nil && len(rawKeys.Keys) > 0 {
		var keys []jwk.PrivateKey
		for i, raw := range rawKeys.Keys {
			var k jwk.PrivateKey
			if err := json.Unmarshal(raw, &k); err != nil {
				return nil, fmt.Errorf("key[%d]: %w", i, err)
			}
			keys = append(keys, k)
		}
		return keys, nil
	}

	return nil, fmt.Errorf("no private key found in source (missing \"d\" field?)")
}

// loadPublicKeys loads public key(s) from a source string.
// The source can be a URL (https://), a file path, or inline JWK/JWKS JSON.
//
// Accepts both a single JWK {"kty":...} and a JWKS {"keys":[...]}.
func loadPublicKeys(source string) ([]jwk.PublicKey, error) {
	// URL: fetch remotely.
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		keys, _, err := jwk.FetchURL(ctx, source, nil)
		if err != nil {
			return nil, fmt.Errorf("fetch keys from %s: %w", source, err)
		}
		return keys, nil
	}

	data, err := readSource(source)
	if err != nil {
		return nil, err
	}

	// Try as single public key JWK.
	var pk jwk.PublicKey
	if err := json.Unmarshal(data, &pk); err == nil && pk.CryptoPublicKey != nil {
		return []jwk.PublicKey{pk}, nil
	}

	// Try as JWKS.
	var jwks jwk.JWKs
	if err := json.Unmarshal(data, &jwks); err == nil && len(jwks.Keys) > 0 {
		return jwks.Keys, nil
	}

	return nil, fmt.Errorf("no public key found in source")
}

// loadPublicKeysFromPrivate loads private keys and derives public keys from them.
func loadPublicKeysFromPrivate(source string) ([]jwk.PublicKey, error) {
	privKeys, err := loadPrivateKeys(source)
	if err != nil {
		return nil, err
	}
	pubs := make([]jwk.PublicKey, len(privKeys))
	for i := range privKeys {
		pubs[i] = *privKeys[i].PublicKey()
	}
	return pubs, nil
}
