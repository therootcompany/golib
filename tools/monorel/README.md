# [monorel](https://github.com/therootcompany/tree/main/tools/monorel/)

Manage independently-versioned modules and releases in a single repository.

- initializes monorepo-compatible `.goreleaser.yaml`
- bumps versions _correctly_ with `git` (tags by commit _to_ amodule)
- releases with `goreleaser` and `gh` (multi-arch, cross-compiled)
- single or multiple binaries per release

```sh
monorel release  --recursive ./tools/monorel/
```

Use git tags like this:

`git tag`:

```sh
v0.1.0
v0.1.1
cmd/sql-migrate/v1.0.2
cmd/sql-migrate/v2.0.3
io/transform/gsheet2csv/v1.0.4
io/transform/gsheet2csv/v1.0.5
tools/monorel/v0.6.5
tools/monorel/v1.0.0
```

to manage packaged releases for a project like this:

```sh
./                                  # v0.1.1
├── go.mod                          # (module-only)
├── cmd/
│   └── sql-migrate/                # cmd/sql-migrate/v2.0.3
│           ├── .goreleaser.yaml    # (module for binary)
│           └── go.mod
├── io/
│   └── transform/
│       └── gsheet2csv/             # io/transform/gsheet2csv/v1.0.5
│           ├── .goreleaser.yaml    # (module with 3 binaries)
│           ├── go.mod
│           └── cmd/
│               ├── gsheet2csv/
│               ├── gsheet2env/
│               └── gsheet2tsv/
└── tools/
    └── monorel/                    # tools/monorel/v1.0.0
        ├── .goreleaser.yaml        # (module for binaries)
        └── go.mod
```

# Install

`monorel` also uses

## Linux & macOS

```sh
webi monorel
source ~/.config/envman/PATH.env
```

## Go

```sh
webi go goreleaser gh
source ~/.config/envman/PATH.env
```

```sh
go install github.com/therootcompany/golib/tools/monorel@latest
```

# Usage

1. `init`
    ```sh
    monorel init --recursive ./
    ```
    Generates a `.goreleaser.yaml` in every module directory (next to each `go.mod`) that contains at least one command package (`package main`), configured to build and release all discovered binaries together (per each target build release package). Also tags an initial v0.1.0 if none is present.
    Uses a hard-coded command name with the `{{ .Env.VERSION }}` placeholder to sidestep monorepo config issues.
2. `bump`
    ```sh
    monorel bump --recursive ./
    ```
    Uses `git log -- <path>` and `git tag` to tag NOT the latest commit of the repo, but the most recent commit changing _in the module_, with the next semver version.
3. `release`
    ```sh
    monorel release --recursive ./
    ```
    Uses `goreleaser` to cross-compile a wide range of binaries and then creates a release with `gh` (the GitHub CLI) - first as a draft, then uploading the assets, then finalizing the release as public (non-draft).

## Init

Creates a `.goreleaser.yaml` for the `go.mod` of each `package main`.

```sh
monorel init --recursive ./
```

| Flag            | Default | Description                                                                                     |
| --------------- | ------- | ----------------------------------------------------------------------------------------------- |
| `--almost-all`  | off     | Widen build matrix to include esoteric platforms (see [Build matrix](#build-matrix))            |
| `--android-ndk` | off     | Adds _additional_ Android build entries (ones that require `CGO_ENABLED=1` and the Android NDK) |
| `--dry-run`     | off     | Print what would happen without writing or tagging                                              |
| `--ios`         | off     | Add an iOS build entry (requires `CGO_ENABLED=1` and Xcode)                                     |
| `--recursive`   | off     | Find all main packages recursively under each path                                              |

## Bump

Maths out the previous and proper next semver release.

```sh
monorel bump --recursive ./
```

| Flag          | Default | Description                                               |
| ------------- | ------- | --------------------------------------------------------- |
| `--dry-run`   | off     | Print the tag that would be created without creating it   |
| `--force`     | off     | If no new commits, create an empty bump commit and tag it |
| `--recursive` | off     | Find all main packages recursively                        |

## Release

Build all binaries, puts them in common package formats (`.tar.gz`, `.tar.zst`, `.zip`), creates a GitHub Release, uploads the packages, and makes the release public.

```sh
monorel release --recursive ./
```

| Flag           | Default | Description                                                       |
| -------------- | ------- | ----------------------------------------------------------------- |
| `--draft`      | off     | Keep the GitHub release in draft state after uploading            |
| `--dry-run`    | off     | Show each step without running it                                 |
| `--prerelease` | off     | Keep the GitHub release marked as pre-release even for clean tags |
| `--recursive`  | off     | Find all main packages recursively                                |
| `--yes`        | off     | Run all steps without prompting                                   |

### Interactive Prompts

1. **Create git tag** — skipped when a tag for this version already exists.
2. **Push commits and tags** — `git push && git push --tags`.
3. **Build with goreleaser** — `goreleaser release --clean --skip=validate,announce`
   with `VERSION=<semver>` set in the environment.
4. **Create GitHub release** — always created as `--draft --prerelease` so
   artifacts can be uploaded before the release goes public.
5. **Upload artifacts** — `gh release upload` with all `.tar.gz`, `.tar.zst`,
   `.zip`, and checksum files from `dist/`.
6. **Finalize release visibility** — removes `--draft` and/or `--prerelease`
   flags as appropriate (see `--draft` / `--prerelease` below).

# Build matrix

The generated `.goreleaser.yaml` targets `CGO_ENABLED=0` for by default.
Platforms that require CGO or a special toolchain are only included when the
corresponding flag is given.

The default matrix contains:

|           | Values                                                                |
| --------- | --------------------------------------------------------------------- |
| `goos`    | `darwin` `freebsd` `js` `linux` `netbsd` `openbsd` `wasip1` `windows` |
| `goarch`  | `amd64` `arm` `arm64` `mips64le` `mipsle` `ppc64le` `riscv64` `wasm`  |
| `goamd64` | `v1` `v2`                                                             |
| `goamd64` | `v3` `v4`                                                             |
| `goarm`   | `6` `7`                                                               |

`--almost-all` adds less-commonly-targeted platforms:

|           | Added values                                    |
| --------- | ----------------------------------------------- |
| `goos`    | `aix` `dragonfly` `illumos` `plan9` `solaris`   |
| `goarch`  | `386` `loong64` `mips` `mips64` `ppc64` `s390x` |
| `goamd64` | `v1` `v2` `v3` `v4`                             |

`--ios` adds an ios build entry, which requires the Xcode toolchain:

```yaml
- id: <binary>-ios
  env:
      - CGO_ENABLED=1
  goos:
      - ios
  goarch:
      - arm64
```

`--android-ndk` adds a build entry for Android/arm64, which requires the [Android NDK](https://developer.android.com/ndk):

```yaml
- id: <binary>-android
  env:
      - CGO_ENABLED=1
  goos:
      - android
  goarch:
      - arm64
```

# vs GoReleaser Pro

This isn't a replacement for [GoRoleaser Pro](https://goreleaser.com/pro/).

Although I wouldn't have created it if multi-module version management were available in a (free or paid) version of GoReleaser without a subscription, this handles _initialization_, _versioning_, and _releasing_ in the way that I've wanted for my workflow (and this repository).
