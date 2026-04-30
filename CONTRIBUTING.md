# Contributing to PromptZero

PromptZero is built primarily with [Claude](https://claude.ai) (Anthropic) — most of the codebase, including the agent loop, tool definitions, and tests, is generated and refined through AI collaboration. PRs are welcome but expect heavy AI involvement in review.

## Development setup

Requirements: Go 1.25+, [Task](https://taskfile.dev), [Pre-commit](https://pre-commit.com) (optional).

```bash
git clone https://github.com/xunholy/promptzero.git
cd promptzero
task dev:setup     # one-time: installs pinned golangci-lint
task build         # bin/promptzero with version ldflags stamped from git
```

## Common commands

| Command | What it does |
|---|---|
| `task build`               | Build with `-ldflags` stamping commit + date into `internal/version`. |
| `task test`                | Short test suite (skips slow timing-sensitive tests). |
| `task test:full`           | Full suite, matches CI. |
| `task lint`                | `golangci-lint run ./...` — errors with a friendly hint if not installed. |
| `task vet`                 | `go vet ./...`. |
| `task --list`              | Every available target. |
| `pre-commit run --all-files` | Run every pre-commit hook locally. |

## Cross-compilation

Tested platforms: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64.

```bash
GOOS=linux   GOARCH=arm64 go build -o promptzero-linux-arm64       ./cmd/promptzero
GOOS=darwin  GOARCH=arm64 go build -o promptzero-darwin-arm64      ./cmd/promptzero
GOOS=windows GOARCH=amd64 go build -o promptzero-windows-amd64.exe ./cmd/promptzero
```

> [!NOTE]
> **darwin builds need CGO** for `tinygo.org/x/bluetooth`. Build on macOS with `CGO_ENABLED=1 GOOS=darwin go build ./cmd/promptzero`. Linux-cross-compiled darwin binaries ship a stub that returns "rebuild on macOS with CGO" when BLE is attempted. The release pipeline handles this — `darwin/*` targets run on macOS runners.

## Code style

- **Smallest correct fix.** Avoid drive-by refactors.
- **No comments** unless the WHY is non-obvious. Don't restate what code does.
- **No error handling for impossible scenarios.** Trust framework guarantees; validate at boundaries (user input, external APIs).
- **CI runs `golangci-lint`** with `gofmt` enabled. Run `task lint` and `task vet` before committing.

## Tests

- Slow timing-sensitive tests are gated behind `testing.Short()`. `task test` is the quick suite; `task test:full` matches CI.
- The `internal/testmocks` package provides a deterministic Anthropic mock for agent loop tests.
- `cmd/pzrunner` is a non-interactive harness — same agent code as the REPL, JSON output. Use it to capture reproducible transcripts under `docs/transcripts/`.

## Release process

See [`docs/RELEASING.md`](docs/RELEASING.md). Tags matching `v*` trigger the release workflow which builds binaries for all five platforms, generates a CycloneDX SBOM, and signs checksums with cosign keyless.

## Reporting bugs

- **Code bugs / feature requests**: open an issue.
- **Security vulnerabilities**: see [`SECURITY.md`](SECURITY.md) — do **not** open a public issue.
