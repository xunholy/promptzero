# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## Project

PromptZero — Go 1.25 CLI that drives a Flipper Zero + ESP32 Marauder
over USB serial via Claude tool use. Module path is
`github.com/xunholy/promptzero`. License is MIT.

## Dev setup

Run `task dev:setup` after cloning to install required dev tools
(pinned `golangci-lint`). `task --list` shows every available target.

## Common commands

- `task build` — build with `-ldflags` that stamp commit + date into
  `internal/version`.
- `task test` — short test suite (skips slow timing-sensitive tests).
- `task test:full` — full suite, matches CI.
- `task lint` — `golangci-lint run ./...`.
- `task vet` — `go vet ./...`.
- `pre-commit run --all-files` — run every pre-commit hook locally.

## Layout

- `cmd/promptzero/` — CLI entry point.
- `internal/agent/` — Claude agent + tool dispatch.
- `internal/flipper/` — Flipper serial transport + capability primitives.
- `internal/marauder/` — ESP32 Marauder serial client.
- `internal/audit/` — audit log + query DSL.
- `internal/version/` — build metadata populated via `-ldflags`.
- `internal/workflows/`, `internal/rules/`, `internal/risk/` — automation.
- `internal/web/`, `internal/mcp/`, `internal/webhook/` —
  external integrations.

## Tests

Slow timing-sensitive tests are gated behind `testing.Short()`. Use
`task test` for the quick suite and `task test:full` when you need
the full coverage CI runs.
