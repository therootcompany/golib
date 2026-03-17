// Package jwt is a lightweight JWT/JWS/JWK library for JOSE, OIDC, and
// OAuth 2.1, designed from first principles for modern Go (1.26+)
// and current standards (OIDC Core 1.0 errata set 2, MCP).
//
// High convenience. Low boilerplate. Easy to customize. Focused:
//
//   - You're either building an Issuer (sign JWTs) or Relying Party (verifies and validates JWTs)
//   - You're implementing part of JOSE, OIDC or OAuth2 and may have a /jwks.json endpoint
//   - You probably do a little of all sides
//   - You want type-safe keys (but you don't want to have to type-switch on them)
//   - You almost always need custom Claims (token Payload)
//   - You almost never need a custom header (but [Header] / [RFCHeader] make it easy)
//   - You may also be implementing MCP support for Ai / Agents
//
// Rather than implementing to the spec article by article, this library implements by flow.
//
// This was created with Ai assistance to be able to iterate quickly over different design choices, but every line of the code has been manually reviewed for correctness, as well as many of the tests.
//
// # Design choices
//
// Convenience is not convenient if it gets in your way. This is a library, not
// a framework: it gives you composable pieces you call and control, not
// scaffolding you must conform to.
//
//   - Sane defaults for everything, without hiding anything you may need to inspect.
//   - There should be one obvious right way to do it.
//   - Claims are the most important builder-facing detail.
//   - Use simple embedding for maximum convenience without sacrificing optionality.
//   - [TokenClaims] for minimal auth info, [StandardClaims] for typical user info.
//     (both satisfy [Claims] for free via Go method promotion)
//   - [RawJWT.UnmarshalClaims] to get your custom type-safe claims effortlessly.
//   - [Validator] for typical auth validation - strict by default, permissive when configured
//     (or bring your own, or ignore it and do it how you like)
//     Use [NewIDTokenValidator] or [NewAccessTokenValidator] for sensible defaults.
//     A zero-value Validator returns [ErrMisconfigured] - always use a constructor.
//   - [RFCHeader] is always used in the standard way, and tightly coupled to signing and
//     verification - it stays fully customizable as part of the JWT interfaces
//     (embedding [RawJWT] and [RFCHeader] make it easy to satisfy [VerifiableJWT] or [SignableJWT])
//   - Accessible error details (so that you don't have to round trip just to get the next one)
//
// Key takeaway: Your claims are your own. You can take what you get for free, or add what you need at no cost to you.
//
// # Use case: Issuer (& Relying Party)
//
// You're building the thing that has the Private Keys, signs the tokens + verifies tokens and validates claims.
//   - create a [NewSigner] with the private keys
//   - use json.Marshal(&signer.WellKnownJWKs) to publish a /jwks.json endpoint
//   - use [Signer.SignToString] + [TokenClaims] or [StandardClaims] to create a token string
//     (or [Signer.Sign] + [Encode] for the signed JWT object)
//   - use [Signer.Verifier] to verify the JWT (bearer token)
//   - use [RawJWT.UnmarshalClaims] to get your user info
//   - use [Validator.Validate] to validate the claims (user info payload)
//   - use custom validation for your own Claims type, or by hand - dealer's choice
//
// # Use case: Relying Party
//
// You're building a thing that uses Public Keys to verify and validate tokens.
//   - you may already know the public keys (and redeploy when they change)
//   - or you fetch them at runtime from a /jwks.json endpoint (and cache and update periodically)
//   - Relying party, known keys: use [NewVerifier] with a []PublicKey slice.
//   - Relying party, remote keys: use keyfetch.KeyFetcher to cache and lazy-refresh keys.
//   - use [Verifier.VerifyJWT] to decode and verify in one call (or [Decode] + [Verifier.Verify] for two-step)
//   - use [RawJWT.UnmarshalClaims] to get your user info
//   - use [Validator.Validate] to validate the claims (user info payload)
//   - use custom validation for your own Claims type, or by hand - dealer's choice
//
// # Use case: MCP / Agents
//
// An MCP Host (the AI application) is a Relying Party to the MCP Server.
// The MCP Server may be an Issuer - minting tokens specifically for Agents
// to call your API - or it may be a Relying Party to your main auth system,
// forwarding tokens it received from an upstream Issuer.
//
// In either case the same building blocks apply: the Host verifies and
// validates tokens from the Server, and the Server either signs its own
// tokens ([NewSigner]) or verifies tokens from your auth provider
// ([NewVerifier] or keyfetch.KeyFetcher).
//
// # OAuth 2.1 Access Tokens
//
// For APIs that accept OAuth 2.1 access tokens (typ: "at+jwt", RFC 9068),
// use [NewAccessTokenValidator] with [TokenClaims] (which includes the
// client_id and scope fields):
//
//		v := jwt.NewAccessTokenValidator(issuers, audiences, "openid", "profile")
//		if err := v.Validate(nil, &claims, time.Now()); err != nil { /* ... */ }
//
//	  - [NewAccessToken] creates a JWS with the correct "at+jwt" typ header
//	  - [NewIDTokenValidator] creates a validator for OIDC ID tokens
//	  - [SpaceDelimited] is a slice that marshals as a space-separated string in JSON,
//	    with trinary semantics: nil (absent/omitzero), empty non-nil (present as ""),
//	    or populated ("openid profile")
//
// # Loading keys from files
//
// The keyfile package loads cryptographic keys from local files in JWK,
// PEM, or DER format. All functions auto-compute KID from the RFC 7638
// thumbprint when not already set:
//
//   - keyfile.LoadPrivatePEM / keyfile.LoadPublicPEM for PEM files
//   - keyfile.LoadPrivateDER / keyfile.LoadPublicDER for DER files
//   - keyfile.LoadPublicJWK / keyfile.LoadPrivateJWK / keyfile.LoadWellKnownJWKs for JWK/JWKS files
//
// For fetching keys from remote URLs, use keyfetch.FetchURL (JWKS endpoints)
// or keyfetch.FetchOIDC (OIDC discovery).
//
// # Security
//
// You don't need to be a crypto expert to use this library - but if you are, hopefully
// you find it to be the best you've ever used.
//
// 1. YAGNI: Don't implement what you don't need = less surface area = greater security.
//
// The researchers who write specifications are notorious for imagining every
// hypothetical - which has resulted in numerous security flaws over the years.
// There's nothing in here that I haven't seen in the wild and found useful.
// And I'm happy to extend if needed.
//
// 2. Verify AND Validate
//
// As an Issuer (owner) you [Signer.Sign] and then [Encode].
//
// As a Relying Party (client) you [Decode], [Verifier.Verify] and [Validator.Validate].
//
// Why not a single step? Because Claims (sometimes called "User" in other libs) is the thing
// you actually care about, and actually want type safety for. After trying various approaches
// with embedding and generics, what I landed on is that the most ergonomic type-safe way
// to Verify a JWT and Validate Claims is to have the two be separate operations.
//
// It's why you get to use this library as a library and how you get to have all of the
// convenience without sacrificing control and customization of the thing you're most likely
// to want to be able to customize (and debug).
//
// 3. Algorithms: The fewer the merrier.
//
// Only asymmetric (public-key) algorithms are implemented.
//
// You should use Ed25519. It's the end-game algorithm - all upside, no known
// downsides, and it's supported ubiquitously - Go, JavaScript, Web Browsers, Node, Rust,
// etc.
//
// Ed25519 is the recommended algorithm.
// ECDSA is provided for backwards compatibility with existing systems.
// RSA is provided only for backwards compatibility - it's larger, slower, with no real benefit.
//
//   - EC P-256  => ES256 (ECDSA + SHA-256, RFC 7518 §3.4)
//   - EC P-384  => ES384 (ECDSA + SHA-384)
//   - EC P-521  => ES512 (ECDSA + SHA-512)
//   - RSA       => RS256 (PKCS#1 v1.5 + SHA-256, RFC 7518 §3.3)
//   - Ed25519   => EdDSA (RFC 8037)
//
// Supported algorithms are derived automatically from the key type - you never
// configure alg directly.
//
// The verification process selects a key by matching the "kid" (KeyID) of token
// and the key and then checking "alg" before any cryptographic operation is attempted.
// An alg/key-type mismatch is a hard error.
package jwt
