# V1 Release Review

Pre-release audit for `github.com/therootcompany/golib/auth/jwt` v1.0.0.

## TODOs in code

- [x] **sign.go:52** — ~~TODO allow for non-signing keys~~ → Added `retiredKeys ...jwk.PublicKey` variadic to NewSigner.
- [x] **sign.go:79** — ~~TODO fail if not sig~~ → NewSigner now rejects Use != "sig".
- [x] **jwk/key.go:229** — ~~TODO if the private key had the wrong details~~ → Converted to regular comment; code is correct.
- [x] **jwk/fetch.go TODOs** — ~~return URL not keys / lift this up~~ → Refactored `fetchFromDiscovery` → `fetchDiscoveryURI`, returns `(string, error)`. FetchOIDC/FetchOAuth2 call FetchURL directly.

## Broken godoc links

- [x] All `[Validator.Validate]` → `[IDTokenValidator.Validate]` (lines 33, 45, 98, 1073).

## Package doc issues (jwt.go)

- [x] **Line 21** — Fixed garbled sentence.
- [x] **Line 69** — Fixed "Use simple type embedded" → "Use simple embedding".
- [ ] **Line 77** — References `[RawJWT]` and `[Header]` for satisfying
      `[VerifiableJWS]` or `[SignableJWS]` — is this still the recommended
      pattern? Confirm or update.
- [x] **Lines 96, 98** — Removed `jwt.` prefix, fixed `[Validator.Validate]`.
- [x] Added OAuth 2.0 access token section (`AccessTokenClaims`, `AccessTokenValidator`, `Scope`).
- [x] Added context accessors section (`WithIDTokenClaims`, etc.).
- [x] Added `keyfile` package section.
- [x] Added `jwk.Fetch` / `jwk.FetchURL` / `jwk.FetchOIDC` references.

## jose/errors.go doc accuracy

- [x] Fixed keyfile package reference and added `jwk.Fetch`.

## API surface questions

- [x] **jwk.ReadFile** vs **keyfile.LoadPublicJWKs** — Deprecated `jwk.ReadFile` in
      favor of `jwk.LoadPublicJWKs`. JWK Load functions canonical in `jwk` package;
      `keyfile` re-exports them.
- [x] **Cacheable struct** — `jwk.Fetch` returns `(*Cacheable, error)` with Data,
      MaxAge (Age-adjusted), ETag, and LastModified fields.
- [x] **fetchFromDiscovery return type** — Renamed to `fetchDiscoveryURI`, returns
      `(string, error)`. FetchOIDC/FetchOAuth2 call FetchURL with the returned URI.

## Error locality

- [x] Audited. `ErrUnsupportedKeyType`, `ErrUnsupportedCurve`, `ErrAlgConflict`
      are produced by `internal/jwa` which imports `jose`. Moving them to `jwk`
      would create a cycle (`jwk` imports `jwa` which would import `jwk`).
      `ErrInvalidKey` could move alone but would be inconsistent. Current design
      (all errors in leaf `jose` package) is correct.

## Test coverage gaps

- [x] Context accessors — added 4 tests.
- [ ] No tests for `KeyFetcher` (would need an httptest server).
- [ ] No tests for `jwk.Fetch` (new function).
- [ ] No tests for `jwk.ReadFile` / `jwk.LoadPublicJWKs`.
- [ ] No tests for `FetchOIDC` / `FetchOAuth2`.

## Test consolidation

- [x] Reviewed. All tests in `tests/` import third-party packages (go-jose, jwx,
      golang-jwt) and must stay in the separate module. No stdlib-only tests to move.

## Consistency

- [x] **Copyright years** — jwt.go, keyfile.go, jwk/parse.go say 2026;
      sign.go, fetcher.go, jwk/fetch.go, jwk/key.go say 2025. Correct per
      creation date — not a problem.
- [x] **Naming** — `jwk.ReadFile` deprecated. `jwk.LoadPublicJWKs` is the canonical
      function. `keyfile.ReadFile` returns raw bytes (different purpose).

## New features

- [ ] **ACME example** — Add `examples/acme/` demonstrating a custom header
      for ACME (RFC 8555) JWS usage. Shows the custom-header pattern for a
      real-world non-JWT use case.
- [ ] **NullBool type** for `*_verified` fields (e.g. `email_verified`,
      `phone_number_verified`). Semantics:
      - Serializes as `true` when true, `false` when corresponding value
        (email, phone) exists but not verified, `null` when not verified and
        corresponding value is absent.
      - Deserializes similarly (null → !Valid, true → true, false → false).
      - `*_verified` fields must NOT be omitted from output when their
        corresponding values are non-empty.
- [ ] **Encode validation** — `Encode` should fail (return error?) if
      components are not properly set, or if any of the 3 standard header
      members (alg, kid, typ?) are empty. Currently it silently produces
      a token with missing header fields.
- [x] **Custom rand.Reader for Signer** — Added `Rand io.Reader` field to Signer.
      If nil, `crypto/rand.Reader` is used. SignJWS uses `s.Rand` when set.
- [x] **Key validity check in NewSigner** — NewSigner performs a test sign+verify
      round-trip for each key via `validateSigningKey`. Catches bad keys at
      construction rather than first use.

## Files to check

- [x] `.gitignore` — added, excludes `cmd/jwt/jwt`.
- [x] No checked-in binaries found.
