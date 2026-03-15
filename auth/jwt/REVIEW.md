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

| File | Line | Comment | Response | Status |
|------|------|---------|----------|--------|
| sign.go | 52 | `// TODO allow for non-signing keys (for key rotation)` | | |
| sign.go | 79 | `// TODO fail if not sig` | | |
| sign.go | 91 | `// TODO use slice rather than map, allow "none" or IgnoreKID` | **Stale** — removed | ✅ Fixed |
| jwk/fetch.go | 99 | `// TODO this should return the URL, not the keys` | | |
| jwk/fetch.go | 123 | `// TODO lift this up` | | |
| jwk/key.go | 229 | `// TODO if the private key had the wrong details, it probably should have been caught earlier` | | |

### #10 — Contradictory RFCValidator config

IgnoreIss overrides the Iss slice. Iss slice is the primary mechanism; IgnoreIss is a
blanket skip. When both are set, IgnoreIss wins — iss is not checked at all.
No warning needed. Added doc comments clarifying precedence. | ✅ Documented |
