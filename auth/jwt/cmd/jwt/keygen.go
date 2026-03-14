package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("jwt keygen", flag.ContinueOnError)
	alg := fs.String("alg", "EdDSA", "algorithm: EdDSA, ES256, ES384, ES512, RS256")
	kid := fs.String("kid", "", "key ID (auto-computed from thumbprint if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var pk *jwk.PrivateKey
	var err error

	switch *alg {
	case "EdDSA":
		pk, err = jwk.NewPrivateKey()
	case "ES256":
		pk, err = generateEC(elliptic.P256())
	case "ES384":
		pk, err = generateEC(elliptic.P384())
	case "ES512":
		pk, err = generateEC(elliptic.P521())
	case "RS256":
		pk, err = generateRSA()
	default:
		return fmt.Errorf("unsupported algorithm %q (use EdDSA, ES256, ES384, ES512, or RS256)", *alg)
	}
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	if *kid != "" {
		pk.KID = *kid
	}
	// KID is auto-computed by NewPrivateKey/generateEC/generateRSA via Thumbprint.

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

func generateEC(curve elliptic.Curve) (*jwk.PrivateKey, error) {
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

func generateRSA() (*jwk.PrivateKey, error) {
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
