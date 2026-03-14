package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("jwt verify", flag.ContinueOnError)
	keyFlag := fs.String("key", "", "public key source: file path, URL (https://), or inline JWK/JWKS JSON")
	gracePeriod := fs.Duration("grace-period", 0, "clock skew tolerance for time-based claims (e.g. 5s)")
	ignoreExp := fs.Bool("ignore-exp", false, "do not fail on expired tokens")
	ignoreNBF := fs.Bool("ignore-nbf", false, "do not fail on not-yet-valid tokens")
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
