# Contributing to PromptZero

PromptZero is built primarily with [Claude](https://claude.ai) (Anthropic) — most of the codebase, including the agent loop, tool definitions, and tests, is generated and refined through AI collaboration. PRs are welcome but expect heavy AI involvement in review.

## First contribution (10 minutes)

```bash
git clone https://github.com/xunholy/promptzero.git
cd promptzero
task dev:setup       # one-time: install pinned golangci-lint
pre-commit install   # one-time: register the git hooks CI also runs
task test            # short suite — should pass on a fresh checkout
task build           # produces ./bin/promptzero
```

Make a change. Run `task test` and `task lint` while iterating, then `task ci` before you push (it runs the locally-reproducible CI gates — lint + vet + build + test:full + vuln — in one shot). Commit. Push. Open a PR. The rest of this file is reference material when you go deeper.

## Development setup

Requirements: Go 1.25+, [Task](https://taskfile.dev), [Pre-commit](https://pre-commit.com) (optional but recommended — same hooks CI runs).

## Working without hardware

You don't need a Flipper or Marauder to develop. The mock-transport harness in `cmd/pzrunner/` exercises the agent against scripted fake-device responses:

```bash
task build:runner
./bin/pzrunner ./examples/scenarios/basic.yaml
```

`pzrunner` is the right surface for testing tool dispatch, persona behaviour, agent flow control, audit semantics, and anything that doesn't strictly need real RF or USB.

## Package map

```
cmd/
  promptzero/        CLI entry — REPL, config, setup wiring
  pzrunner/          Hardware-free harness (fake transports)
  cliprobe/          Tool-catalog inspector (`-list-tools` etc.)
  flipper-validate/  End-to-end checks against a real Flipper
internal/
  agent/             Claude agent + tool dispatch + risk/confirm gates
  flipper/           Flipper transport + capability primitives
                     (Serial default, BLE optional)
  marauder/          ESP32 Marauder serial client
  audit/             Append-only audit log + query DSL (SQLite/WAL)
  tools/             Central Spec registry — one Spec per tool
                     (see internal/tools/security.go for a worked example)
  workflows/         Multi-step orchestrations (WiFi handshake, etc.)
  rules/             Reactive rule engine on the audit stream
  risk/              Tool risk classification (Low/Medium/High/Critical)
  validator/         Static validators for generated artefacts
  generate/          LLM-driven code generation pipeline
  web/               Embedded web UI server + WebSocket
  mcp/               MCP server adapter
  webhook/           Outbound HTTP event dispatcher
  observability/     Status panel, OpenTelemetry traces
```

## Common commands

| Command | What it does |
|---|---|
| `task build`                 | Build with `-ldflags` stamping commit + date into `internal/version`. |
| `task test`                  | Short test suite (skips slow timing-sensitive tests). |
| `task test:full`             | Full suite — matches CI. |
| `task lint`                  | `golangci-lint run ./...` — errors with a friendly hint if not installed. |
| `task vet`                   | `go vet ./...`. |
| `task vuln`                  | `govulncheck ./...` — CVE scan of deps + reachable stdlib. |
| `task ci`                    | The locally-reproducible CI gates in one command: lint + vet + build + test:full + vuln. Run before pushing. |
| `task usecases`              | Operator scenarios against a live Flipper. |
| `task eval`                  | Golden eval harness (mock transports). |
| `task --list`                | Every available target. |
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

## Testing conventions

- Slow / timing-sensitive tests are gated with `testing.Short()`. `task test` is the quick suite; `task test:full` matches CI.
- Tests run with `-race -count=1`. Don't share state across tests via package vars without a mutex; use `t.TempDir()` for filesystem fixtures.
- The `internal/testmocks` package provides a deterministic Anthropic mock for agent loop tests.
- New parsers / decoders should ship with at least a smoke test. Adversarial-input parsers (anything that ingests bytes from the Flipper or SD card) are good fuzz candidates — `go test -fuzz`.
- `cmd/pzrunner` is a non-interactive harness — same agent code as the REPL, JSON output. Use it to capture reproducible transcripts under `docs/transcripts/`.

## Commit and PR conventions

- **Commit messages** follow Conventional Commits in spirit but stay human-readable: `<type>(<scope>): <subject>` where `type` is one of `feat / fix / refactor / perf / test / docs / build / chore`. Example: `fix(security): gate RunTool with audit + confirm chokepoints`.
- Body lines wrap at ~72 characters and explain *why* before *what*. The diff already shows what changed; the message records the reasoning.
- PRs include a `## Test plan` checklist. CI runs build/test/lint/vuln (reproduce locally with `task ci`); manual hardware checks (when applicable) live in the test plan.

## Scope and review

PromptZero drives real RF and USB hardware. Two review concerns weigh more heavily than in most Go projects:

1. **Safety regressions.** Anything that touches `internal/agent/agent.go` (the dispatch + confirm gate), `internal/audit/`, or `internal/risk/risk.go` is read carefully for whether it preserves fail-closed semantics. The doc comments around `executeTool`, `RunTool`, `audit.RequireOpen`, `confirmCb`, and `SetReadOnly` are load-bearing — update them when behaviour changes. Note that `--read-only` (v0.19.0) is the operator-facing safety rail and refuses anything above `risk.Low` at dispatch; new tools must classify their `Risk` correctly so the rail stays sound.
2. **Surprising tool catalogues.** New tools should land in the registry, classify their risk, and pick a Group. The `TestToolGroup_AgreesWithSpecGroup` test guards against silent drift between persona-mode blocking and dynamic-catalog narrowing.

Out of scope: features that primarily exist to evade detection in attacker workflows. Defensive use, authorised pentesting, education, and CTF use cases are all welcome.

## Release process

See [`docs/RELEASING.md`](docs/RELEASING.md). Tags matching `v*` trigger the release workflow which builds binaries for all five platforms, generates a CycloneDX SBOM, and signs `checksums.txt` + `install.sh` with cosign keyless.

## Reporting bugs

- **Code bugs / feature requests**: open an issue. Please include the output of `promptzero version`, the OS / arch / Go version, and the smallest reproduction you can share.
- **Security vulnerabilities**: see [`SECURITY.md`](SECURITY.md) — do **not** open a public issue.
