## Remaining Review Items

### #19 — Package doc editing artifacts (jwt.go)

| Line | Issue | Response | Status |
|------|-------|----------|--------|
| 9 | Very long single line — consider wrapping | | |
| 21 | `This package implements So rather than implementing...` — garbled merge of two sentences | | |
| 38 | `2. Relying Party:` — stray numbering under heading | Intentional — "1." is the Issuer heading above | ✅ Keep |
| 41 | `use [New]` — should be `[NewVerifier]` | Fix | ✅ Fixed |
| 48-49 | `# Use case: MCP / Agents` section empty | Built out: MCP Host as RP to MCP Server; Server as Issuer or RP to main auth | ✅ Fixed |
| 58 | `building-facing` | `builder-facing` | ✅ Fixed |
| 65-66 | `always always` + `fully and customizable` | Fixed both | ✅ Fixed |
| 74 | `crypto export` | `crypto expert` | ✅ Fixed |
| 109 | `only is provided` | `provided only` | ✅ Fixed |
| 120-121 | Outdated kid matching description | | |

### #20 — TODO comments in production code

| File | Line | Comment | Notes |
|------|------|---------|-------|
| sign.go | 52 | `// TODO allow for non-signing keys (for key rotation)` | |
| sign.go | 79 | `// TODO fail if not sig` | |
| sign.go | 91 | `// TODO use slice rather than map, allow "none" or IgnoreKID` | **Stale** — Verifier already uses slice, no map |
| jwk/fetch.go | 99 | `// TODO this should return the URL, not the keys` | On `fetchFromDiscovery` |
| jwk/fetch.go | 123 | `// TODO lift this up` | On `FetchURL` call inside `fetchFromDiscovery` |
| jwk/key.go | 229 | `// TODO if the private key had the wrong details, it probably should have been caught earlier` | In `publicKeyOps` switch |

### #10 — Contradictory RFCValidator config

`RFCValidator` has fields like `Iss string` and `IgnoreIss bool`. Setting both
`Iss: "https://example.com"` and `IgnoreIss: true` is contradictory but produces
no warning. Current behavior: `IgnoreIss` wins — the `Iss` value is simply not
checked. Possible approaches:

- Rename `Ignore*` to `Optional*` or `Skip*`
- Return an error from `Validate` if both are set
- Leave as-is with a doc comment explaining precedence
