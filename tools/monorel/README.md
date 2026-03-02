# monorel — Monorepo Release Tool

`monorel` automates the release workflow for Go binaries that live in a
monorepo, where each binary (or small group of binaries) has its own `go.mod`
and is versioned independently with **prefixed git tags** like
`auth/csvauth/v1.2.3`.

It handles the parts that goreleaser's open-source edition cannot do on its
own with a prefixed monorepo tag:

1. Generates a per-module `.goreleaser.yaml` that uses `{{ .Env.VERSION }}`
   instead of the tag name, so archive filenames stay clean.
2. Runs goreleaser in "build only" mode, then uses `gh release` to create and
   publish the GitHub release against the correct prefixed tag.

## Install

```sh
go install github.com/therootcompany/golib/tools/monorel@latest
```

## Prerequisites

| Tool | Purpose |
|------|---------|
| `git` | Tagging and history queries |
| [`goreleaser`](https://goreleaser.com/install/) | Cross-compilation and archive creation |
| [`gh`](https://cli.github.com/) | GitHub release creation and upload |

## Tag convention

Every module is tagged with a path prefix that matches its location relative
to the repository root:

```
<module-path>/v<semver>
```

Examples:

| Module directory | Tag |
|-----------------|-----|
| `auth/csvauth/` | `auth/csvauth/v1.2.3` |
| `cmd/tcpfwd/` | `cmd/tcpfwd/v0.9.1` |
| `io/transform/gsheet2csv/` | `io/transform/gsheet2csv/v2.0.0` |

## Subcommands

### `monorel init`

Bootstraps a module for monorepo releases:

1. Writes `.goreleaser.yaml` next to `go.mod` (skipped if the file already
   looks correct).
2. Commits it (only for new files — edits require manual review).
3. Creates an initial `v0.1.0` patch tag (skipped if there are already
   multiple un-tagged commits since the last stable tag).

```sh
# Single binary at the current directory's module root
monorel init .

# Binary nested under cmd/
monorel init ./cmd/csvauth

# Multiple binaries in the same module
monorel init ./cmd/gsheet2csv ./cmd/gsheet2env

# All modules recursively (useful for first-time repo setup)
monorel init --recursive .

# Also run `go mod init` + `go mod tidy` for any cmd/ children that
# have package main but no go.mod yet
monorel init --cmd --recursive .
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--recursive` | off | Find all main packages recursively under each path |
| `-A` | off | Include dot/underscore-prefixed directories |
| `--dry-run` | off | Print what would happen without writing or tagging |
| `--cmd` | off | Run `go mod init` + `go mod tidy` for unmodularised `cmd/` children |
| `--almost-all` | off | Widen build matrix to include esoteric platforms (see [Build matrix](#build-matrix)) |
| `--ios` | off | Add an iOS build entry (requires CGO_ENABLED=1 and Xcode) |
| `--android-ndk` | off | Add an Android NDK build entry (requires CGO_ENABLED=1 and NDK) |

---

### `monorel bump`

Creates the next semver tag at the module's latest commit.

```sh
monorel bump .                        # bump patch (default)
monorel bump -r minor ./cmd/csvauth   # bump minor
monorel bump -r major ./cmd/csvauth   # bump major
monorel bump --recursive .            # bump patch for all modules
monorel bump --force .                # bump even with no new commits
monorel bump --dry-run --recursive .  # preview without tagging
```

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `-r` | `patch` | Component to bump: `major`, `minor`, or `patch` |
| `--recursive` | off | Find all main packages recursively |
| `-A` | off | Include dot/underscore-prefixed directories |
| `--force` | off | If no new commits, create an empty bump commit and tag it |
| `--dry-run` | off | Print the tag that would be created without creating it |

---

### `monorel release`

The main release workflow. For each module it:

1. Writes (or validates) `.goreleaser.yaml`.
2. Prompts through each step interactively — or runs automatically with
   `--yes` / `--dry-run`.

```sh
# Single binary at the module root
monorel release .

# Multiple binaries in the same module
monorel release ./cmd/gsheet2csv ./cmd/gsheet2env

# All modules under the current directory
monorel release --recursive .

# Preview every step without running anything
monorel release --dry-run .

# Run all steps without prompting
monorel release --yes .
```

#### Release steps

For each module, `monorel release` runs these steps in order (each prompted
individually unless `--yes` is given):

1. **Create git tag** — skipped when a tag for this version already exists.
2. **Push commits and tags** — `git push && git push --tags`.
3. **Build with goreleaser** — `goreleaser release --clean --skip=validate,announce`
   with `VERSION=<semver>` set in the environment.
4. **Create GitHub release** — always created as `--draft --prerelease` so
   artifacts can be uploaded before the release goes public.
5. **Upload artifacts** — `gh release upload` with all `.tar.gz`, `.tar.zst`,
   `.zip`, and checksum files from `dist/`.
6. **Finalise release visibility** — removes `--draft` and/or `--prerelease`
   flags as appropriate (see `--draft` / `--prerelease` below).

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--recursive` | off | Find all main packages recursively |
| `-A` | off | Include dot/underscore-prefixed directories |
| `--dry-run` | off | Show each step without running it |
| `--yes` | off | Run all steps without prompting |
| `--force` | off | Overwrite `.goreleaser.yaml` without prompting if it has been modified |
| `--draft` | off | Keep the GitHub release in draft state after uploading |
| `--prerelease` | off | Keep the GitHub release marked as pre-release even for clean tags |
| `--almost-all` | off | Widen build matrix (see [Build matrix](#build-matrix)) |
| `--ios` | off | Generate an active iOS build entry |
| `--android-ndk` | off | Generate an active Android NDK build entry |

#### Draft and pre-release behaviour

Releases are always *created* as `--draft --prerelease`.  After uploading,
the finalise step adjusts visibility:

| Flags given | Result |
|-------------|--------|
| *(neither)* | Draft removed, pre-release removed for clean tags |
| `--prerelease` | Draft removed, pre-release **kept** |
| `--draft` | Draft **kept**, pre-release removed for clean tags |
| `--draft --prerelease` | Both **kept** (no finalise step) |

A *clean tag* is one without a pre-release suffix (no `-pre3` or `.dirty`).

---

## Build matrix

The generated `.goreleaser.yaml` targets `CGO_ENABLED=0` by default.
Platforms that require CGO or a special toolchain are only included when the
corresponding flag is given.

### Default matrix

| | Values |
|-|--------|
| `goos` | `darwin` `freebsd` `js` `linux` `netbsd` `openbsd` `wasip1` `windows` |
| `goarch` | `amd64` `arm` `arm64` `mips64le` `mipsle` `ppc64le` `riscv64` `wasm` |
| `goarm` | `6` `7` |

### `--almost-all`

Adds less-commonly-targeted platforms:

| | Added values |
|-|-------------|
| `goos` | `aix` `dragonfly` `illumos` `plan9` `solaris` |
| `goarch` | `386` `loong64` `mips` `mips64` `ppc64` `s390x` |
| `goamd64` | `v1` `v2` `v3` `v4` |

### `--ios`

Adds an active build entry:

```yaml
- id: <binary>-ios
  env:
    - CGO_ENABLED=1
  goos:
    - ios
  goarch:
    - arm64
```

Requires the Xcode toolchain.

### `--android-ndk`

Adds an active build entry:

```yaml
- id: <binary>-android
  env:
    - CGO_ENABLED=1
  goos:
    - android
  goarch:
    - arm64
```

Requires the [Android NDK](https://developer.android.com/ndk).

---

## Generated `.goreleaser.yaml`

`monorel` generates a config that:

- Uses `{{ .Env.VERSION }}` (plain semver like `1.2.3`) in all filenames so
  the prefixed monorepo tag (`auth/csvauth/v1.2.3`) never appears in archives
  or checksum files.
- Gives each binary its own `build.id` and `archive.ids` so that
  multi-binary modules produce separate archives per binary.
- Sets `release.disable: true` — goreleaser's built-in GitHub publisher is
  bypassed in favour of `gh release` (goreleaser Pro would be required to
  publish via a prefixed tag).

When `monorel init` or `monorel release` encounters an existing
`.goreleaser.yaml` it checks whether it is **compatible** (no stock
`{{ .ProjectName }}` template, at least one binary using `VERSION`).  If the
file is compatible it is left untouched, preserving any manual customisations
such as extra binaries, custom hooks, or signing steps.

### Multi-binary modules

When a module contains more than one binary, the shared build settings
(`env`, `ldflags`, `goos`, `goarch`, `goarm`) are factored out with a YAML
anchor to keep the file DRY:

```yaml
builds:
  - id: foo
    binary: foo
    <<: &build_defaults
      env:
        - CGO_ENABLED=0
      goos:
        - linux
        - darwin
        # ...

  - id: bar
    binary: bar
    main: ./cmd/bar
    <<: *build_defaults
```

---

## Version scheme

| State | Version | Tag |
|-------|---------|-----|
| Exactly at a stable tag | `1.2.3` | existing tag |
| *N* commits past `v1.2.3`, clean | `1.2.4-preN` | new tag created |
| Dirty working tree | `1.2.4-pre1.dirty` | no new tag |
| No prior tags | `0.1.0` | new tag created |
