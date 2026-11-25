# Agent guidance

- Private deployment notes live in `./agents/pii-secrets/` (untracked).
  These files may use real hostnames in their names — the by-role rule
  applies to tracked content only.
- Read the relevant deployment note before deploying or running a live
  smoke test.
- **Environment-specific values never leave their config files.**
  Anything specific to this environment, fleet, or deployment — real
  hostnames (`vms.example.net` style, tenant or guest names), private IPs
  (`192.168.x.x`-style from our networks), environment-specific ports,
  paths, usernames, credentials, test identifiers — belongs only in
  untracked config (`./agents/pii-secrets/`, `~/.config/agents/`,
  `~/.config/<vendor>/`). In source, tests, plans, docs, commit
  messages, and responses, refer to such values **by role** ("one of the
  fleet's routers", "the CFO site", "a tenant host"), never by name.
- The test for a value: is it a generic, well-known example (`example.com`,
  `127.0.0.1`, `192.0.2.x`, `user@example.com`)? If not, it is
  environment-specific and the rule above applies. Before writing any
  hostname, IP, port, path, or identity you learned from this
  environment: stop — confirm it is a generic example, or write a role
  reference and point at the config file that holds the real value.
- **Agent files live in this repo's `./agents/`** (untracked): plans in
  `./agents/plans/`, handoffs in `./agents/handoffs/`, todos in
  `./agents/todos/`, reviews in `./agents/reviews/`, vocabulary in
  `./agents/VOCAB.md`. Do not create `agents/` subdirectories next to
  packages.
- **Naming follows standard vocabulary** (the RFCs, the standard library).
  Naming decisions are recorded in `./agents/VOCAB.md`. Read it before naming
  identifiers; any noun that appears in none of the RFCs, the stdlib, or
  `VOCAB.md` is jargon and needs an entry there before it goes in code.
