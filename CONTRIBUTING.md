# Contributing to PromptZero

Welcome. PromptZero is a Go 1.25 CLI that drives a Flipper Zero + ESP32
Marauder over USB serial via Claude tool use. License is
AGPL-3.0-or-later. Contributions are welcome — bug reports, fixes, new
tools, docs, examples, all of it.

This file is the contributor on-ramp. You don't need to read all of it
to send a one-line typo fix; the **First contribution**
section below should be enough. The rest is reference material when
you go deeper.

## First contribution (10 minutes)

```bash
git clone https://github.com/xunholy/promptzero.git
cd promptzero
task dev:setup       # one-time: install pinned golangci-lint
pre-commit install   # one-time: register the git hooks CI also runs
task test            # short suite — should pass on a fresh checkout
task build           # produces ./bin/promptzero
```

Make a change. Run `task test` and `task lint`. Commit. Push. Open
a PR. That's it. The rest of this file is a map for when you need
more context.

## Working without hardware

You don't need a Flipper or Marauder to develop. The mock-transport
harness in `cmd/pzrunner/` exercises the agent against scripted
fake-device responses:

```bash
task build:runner
./bin/pzrunner ./examples/scenarios/basic.yaml
```

`pzrunner` is the right surface for testing tool dispatch, persona
behaviour, agent flow control, audit semantics, and anything that
doesn't strictly need real RF or USB.

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
                     - Serial (default), BLE (optional)
  marauder/          ESP32 Marauder serial client
  audit/             Append-only audit log + query DSL (SQLite/WAL)
  tools/             Central Spec registry. Every tool is one Spec
                     + Handler. See spec.go for the contract.
  workflows/         Multi-step orchestrations (e.g. WiFi handshake)
  rules/             Reactive rule engine on the audit stream
  risk/              Tool risk classification (Low/Medium/High/Critical)
  validator/         Static validators for generated artefacts
                     (BadUSB, evil portal HTML)
  generate/          LLM-driven code generation pipeline
  web/               Embedded web UI server + WebSocket
  mcp/               MCP server adapter (host + tool exposure)
  webhook/           Outbound HTTP event dispatcher
  config/            YAML config loader
  observability/     Status panel, OpenTelemetry traces
```

If you're adding a new tool, the path is almost always:
`internal/tools/<your_tool>.go` with a `Spec` + `Handler` and a
`Register(spec)` in `init()`. See `internal/tools/security.go` for
a worked example.

## Common commands

```bash
task --list              # see every available task target
task build               # build with version ldflags stamped
task test                # short test suite (skips slow tests)
task test:full           # full suite (matches CI)
task lint                # golangci-lint
task vet                 # go vet
task vuln                # govulncheck — CVE scan of deps + reachable stdlib
task usecases            # operator scenarios against a live Flipper
task eval                # golden eval harness (mock transports)
```

## Testing conventions

* Slow / timing-sensitive tests are gated with `if testing.Short() {
  t.Skip(...) }` so `task test` stays fast for the inner loop. CI runs
  `task test:full` to cover the slow set.
* Tests run with `-race -count=1`. Don't share state between tests
  via package vars without a mutex; use `t.TempDir()` for filesystem
  fixtures.
* New parsers / decoders should ship with at least a smoke test.
  Adversarial-input parsers (anything that ingests bytes from the
  Flipper or SD card) are good fuzz candidates — `go test -fuzz`.

## Commit and PR conventions

* **Commit messages** follow Conventional Commits in spirit but stay
  human-readable: `<type>(<scope>): <subject>` where `type` is one of
  `feat / fix / refactor / perf / test / docs / build / chore`.
  Example: `fix(security): gate RunTool with audit + confirm chokepoints`.
* Body lines wrap at ~72 characters and explain *why* before *what*.
  The diff already shows what changed; the message exists to record
  the reasoning a reader can't reconstruct from the code alone.
* PRs include a `## Test plan` checklist. CI runs build/test/lint/vuln;
  manual hardware checks (when applicable) live in the test plan.

## Scope and review

PromptZero drives real RF and USB hardware. Two review concerns
weigh more heavily than in most Go projects:

1. **Safety regressions.** Anything that touches `internal/agent/agent.go`
   (the dispatch + confirm gate), `internal/audit/`, or
   `internal/risk/risk.go` is read carefully for whether it preserves
   fail-closed semantics. The doc comments around `executeTool`,
   `RunTool`, `audit.RequireOpen`, and `confirmCb` are load-bearing —
   please update them when behaviour changes.
2. **Surprising tool catalogues.** New tools should land in the
   registry, classify their risk, and pick a Group. The
   `TestToolGroup_AgreesWithSpecGroup` test guards against silent
   drift between persona-mode blocking and dynamic-catalog narrowing.

Out of scope: features that primarily exist to evade detection in
attacker workflows. Defensive use, authorized pentesting, education,
and CTF use cases are all welcome.

## Reporting issues

* Bug reports: please include the output of `promptzero version`,
  the OS / arch / Go version, and the smallest reproduction you can
  share.
* Security issues: see [SECURITY.md](SECURITY.md) for the disclosure
  flow.

## License

By contributing, you agree your contributions will be licensed under
AGPL-3.0-or-later, the same license as the rest of the project.
