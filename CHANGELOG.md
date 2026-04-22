# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-22

Landmark release — every item in the P0 and P1 tranches of
`docs/specs/roadmap.md` is delivered. Major additions span agent
reliability, operator UX, report generation, snapshot-based undo,
and MITRE ATT&CK-aware tooling.

### Added

#### Agent reliability (P0)
- **Anthropic prompt caching** on the system prompt + tool catalog
  (`cache_control: ephemeral`). Sessions longer than 3 turns drop
  ~70–90% input-token cost and 1–2 s first-token latency. Cache
  hit-rate visible via `/stats cache`.
- **Cost-tier per-tool model routing.** Personas declare
  `models: {classify: haiku, generate: sonnet, plan: sonnet,
  exploit: opus}` in YAML; the agent picks the right tier per call.
- **`flipper.state` oracle** injected on every turn as a
  `<device-state>` JSON block so the model stops burning tool calls
  on "what's connected?" / "what mode are you in?" questions.
- **Dynamic tool-catalog narrowing (opt-in)** via Haiku-tier router
  that picks relevant tool groups; 60–80% fewer tool-description
  tokens on scoped turns. Falls back to full catalog on any router
  failure. Enable with `EnableDynamicCatalog`.
- **Reflexion-on-error loop** — tool failures trigger a classify-
  tier self-critique appended inside `<reflection>` tags. Capped
  at 3 reflections per user turn.
- **Prompt-injection quarantine** — hardware-returned output (WiFi
  SSIDs, NFC tag URIs, storage reads, etc.) wrapped in
  `<untrusted-hardware-output>` tags; ANSI / control-byte
  sanitisation; system-prompt clause tells the model to treat those
  blocks as data, never instructions.

#### Quality + differentiation (P1)
- **MITRE ATT&CK integration.** New `internal/attack` package with
  14 curated techniques and 30+ tool-to-technique mappings.
  Audit entries tag every tool call with the ATT&CK path.
  Per-session constraint via `/attack set T1557.004 T1499`.
- **Structured handoff artifact.** Each session autosave captures
  `{findings, open_threads, blocked, device_state_at_compact}` so
  `/session resume` prepends the handoff as a `<handoff-resume>`
  user message and the model picks up exactly where it left off.
- **`/rewind` SD snapshots.** Every SD write (fileformat_edit,
  storage_copy / rename, generator deploys, parametric builders)
  snapshots the pre-write content. Supports `/rewind <id>`,
  `/rewind <n>` pop-N-count, `/rewind list`, and dry-run.
- **Detector abstraction.** `rules.DetectorEngine` runs
  LLM-as-judge detectors concurrently after each tool call.
  Built-in detectors: `wifi_deauth_success`,
  `pmkid_capture_validity`, `nfc_clone_fidelity`. Verdicts
  surface as `<detector-verdict>` JSON in tool output and in
  `/report` output.
- **Session `/report` generator.** `internal/report` package
  renders a Markdown engagement report with risk-tier breakdown,
  tool usage table, MITRE ATT&CK coverage heatmap (with deep
  links), detector verdicts, and timeline. Save with
  `/report <session-id> save`.
- **OpenTelemetry GenAI exporter.** Honours
  `OTEL_EXPORTER_OTLP_ENDPOINT`; emits `gen_ai.*` spans per agent
  turn + child tool-call spans with input/output/cache token
  attributes. Noop when unset.
- **Parametric file builders.** New tools `subghz_build`,
  `rfid_build`, `ir_build`, `nfc_build`, and
  `subghz_bruteforce_generate` synthesise correctly-framed
  Flipper files from typed parameters. NFC UID byte-length
  validated against device type.
- **Boxed TX preview + `[R]evise`.** High/critical confirm
  prompts render a Unicode-boxed preview with frequency-in-MHz
  annotations. Operator presses `r` to enter a revision prompt;
  the agent skips the tool and re-plans with the operator's
  edit. Backed by a 2s enforced delay gate.
- **Few-shot examples** on high-priority tool descriptions
  (`subghz_transmit`, `subghz_receive`, `nfc_emulate`,
  `rfid_write`, `badusb_execute`, `wifi_evil_portal_start`).
- **Chain-of-verification** on `generate_*` tools. A Haiku-tier
  verifier checks the generated content for known failure modes
  (evil-portal form action, BadUSB OS mismatch, out-of-band
  SubGHz frequency, etc.). Blocks deploy at severity high/critical
  unless the operator passes `verify_bypass`.
- **Deterministic response parsers** for Marauder
  `scanap` / `list -a` / `list -c`, Flipper `nfc_detect`,
  `storage info`, and `subghz rx`. Model sees structured JSON
  instead of free-form output.
- **Structured `ToolError`** replacing the free-form
  `"error: ..."` string. Carries `code`, `tool`, `message`,
  `excerpt`, `remediation`, `retryable`, and optional
  `device_state` at failure time.

#### REPL + observability
- `/rewind`, `/report`, `/attack`, `/stats` slash commands.
- Cache hit-rate + cache-read / cache-creation tokens in
  `cost.Snapshot` and `/cost` output.
- OpenTelemetry traces with `gen_ai.*` attributes.

### Changed

- `ConfirmFunc` return type widened from `Decision` to
  `ConfirmResponse{Decision, Revision}` to carry revision text
  alongside the decision. All in-tree callers updated (REPL, web,
  e2e tests).
- `Agent.SetUsageCallback` now receives a `Usage` struct with
  cache tokens alongside input / output totals.
- `fileformat_edit`, `storage_copy`, `storage_rename`, and every
  `generate_*` path snapshot their destination before writing so
  `/rewind` can restore.

### Fixed

- NFC UID byte-length mismatch in `BuildNFC` (4-byte UID on NTAG215
  would previously produce a syntactically valid but semantically
  wrong file; now rejected with a clear error).
- UTF-8-safe truncation in `ToolError.Excerpt` and
  `HandoffArtifact` previews — multi-byte runes no longer split.
- `snapshotBeforeWrite` propagates caller `ctx` so the warn-log
  carries the turn's trace ID.
- Path-traversal guard on `/report <id> save` — session IDs are
  restricted to alphanumeric + `_-`.

### Security

- Hardware-returned strings sanitised + wrapped in
  `<untrusted-hardware-output>` tags before reaching the model,
  closing a class of prompt-injection vectors where a malicious
  SSID / NFC URI could direct the agent.
- 2 s enforced confirm-delay on high-risk actions (Warp-style).

### Removed

- **BREAKING:** MQTT bridge and the `mqtt:` config block. No surveyed
  competitor shipped an equivalent and every use case MQTT covered here
  is already handled by webhooks or audit consumers. Drops the
  `github.com/eclipse/paho.mqtt.golang` dependency, the `/mqtt` REPL
  command, the `promptzero_mqtt_publishes_total` metric, and the `mqtt`
  rule-action kind + `topic` field. Migrate any MQTT subscribers to
  webhook subscriptions (`webhooks:` in config) — same payloads, same
  lifecycle events.

### Added

- Bearer-token auth on `/api`, `/metrics`, and `/ws`. Set `web.token` in
  config or `PROMPTZERO_WEB_TOKEN` in the environment; HTTP callers send
  `Authorization: Bearer <token>` and the browser passes `?token=<token>`
  on the WebSocket URL. Leaving the token empty preserves the old
  no-auth behaviour; the server prints a red warning when that combines
  with a non-loopback bind.
- `web.cors_origins` allow-list for the WebSocket Origin header. Empty
  (default) means same-origin only — the previous `*` wildcard is gone.
- `GET /api/auth` — open endpoint reporting `{"required": bool}` so the
  browser shell knows whether to prompt for a token before opening the
  WebSocket.

### Changed

- Default Claude model bumped from `claude-sonnet-4-6` to `claude-opus-4-7`
  for the agent and the vision analyzer. Existing `model:` values in
  user config override the default; cost pricer already knew about
  opus-4-7 so no math surprises.

## [0.1.0] - 2026-04-18

### Added

- Flipper Zero capability-gap primitives (42 new operations) with mock-backed tests.
- Operator-mode persona registry and `/persona` slash command.
- Filesystem-triggered agent mode via repeatable `--watch` paths.
- Audit query DSL: `/audit find`, `/audit tail`, `/audit top`.
- Composite workflows: `hw_recon_blackbox_device`, `nfc_badge_pipeline`,
  `garage_door_triage`, `phys_pentest_badge_walk`, `badusb_target_profile`,
  `rolljam_lab_demo`, `wifi_target_to_hashcat`.
- Structural read/edit/diff for Flipper `.sub`, `.nfc`, `.ir`, `.rfid` files.
- Outbound HTTP webhooks covering tool, risk, workflow, and audit events.
- Publish-only MQTT bridge for state and event streams.
- Structured `slog` logging with correlation IDs across REPL, agent, and audit.
- `/debug` slash command and Prometheus `/metrics` endpoint.
- Token cost tracking with offline-mode detection.
- Reactive rules engine subscribed to the audit observer.
- BadUSB sandbox preflight validator surfacing Critical/Warn/Info findings.
- BLE transport scheme reserved as a Phase-B stub.
- `--marauder-port` flag for overriding the Marauder serial device.

### Changed

- Flipper package refactored onto a `Transport` interface with a concrete
  serial implementation.
- Pty-based mock migrated to the new `Transport` interface.
- **License: MIT → AGPL-3.0-or-later.** Aligns with the offensive-security
  tooling norm (Metasploit, Nuclei, etc.) so downstream hosted services
  must publish modifications. No change for end users running locally.

### Fixed

- CI green: resolved remaining `gofmt`, `staticcheck`, and `unused` findings
  surfaced by `golangci-lint`.

### Security

- Marauder CLI invocations now sanitise user-supplied strings before shelling
  out.
- BadUSB preflight flags unsafe payloads before execution.

[Unreleased]: https://github.com/xunholy/promptzero/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/xunholy/promptzero/releases/tag/v0.3.0
[0.1.0]: https://github.com/xunholy/promptzero/releases/tag/v0.1.0
