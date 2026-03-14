package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

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
