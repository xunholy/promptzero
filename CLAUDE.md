# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## Project

PromptZero — Go 1.25 CLI that drives a Flipper Zero + ESP32 Marauder
over USB serial via Claude tool use. Module path is
`github.com/xunholy/promptzero`. License is AGPL-3.0-or-later.

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
- `internal/flipper/` — Flipper transport + capability primitives.
  Transports: Serial USB (default) and BLE (optional, via
  `tinygo.org/x/bluetooth`).
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

## Documentation style

Keep doc comments **blocked above** the function, type, var/const, or
logical code section they describe — this keeps the executable lines
clean and scannable. Follow Go convention: exported-symbol comments
start with the symbol name (e.g. `// Decode attempts …`).

Reserve **trailing/inline** comments (`x := f() // …`) for the rare
case where the explanation belongs to that exact line and would lose
its meaning if moved — a non-obvious constant, a tricky single
expression. Default to a block comment above; only inline when the
note is genuinely line-specific.
