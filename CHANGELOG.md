# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-04-24

Tool-registry refactor. Every tool used to live in three places —
`internal/mcp/server.go` (MCP `s.add()`), `internal/agent/tools.go`
(Anthropic schema declaration), `internal/agent/agent.go` (dispatch
switch case) — and drift between those layers caused real
user-facing bugs (device_info vs system_info naming drift,
storage_write registered in MCP but undispatched in the agent,
nfc_dump_protocol sending the wrong protocol token to Momentum).

This release collapses those three paths into a single
`internal/tools` registry. Every tool now lives in exactly one
`Spec{}` definition; both MCP and the agent dispatcher consume the
same registry. Adding a new tool is one edit instead of three;
naming drift, risk drift, and "MCP missing what agent has" become
structurally impossible.

### Changed

- **`internal/tools` is now the single source of truth for every
  tool.** 179 Specs split across 33 files by category
  (`system.go`, `storage.go`, `subghz.go`, `ir.go`, `nfc.go`,
  `rfid.go`, `ibutton.go`, `badusb.go`, `js.go`, `fileformat.go`,
  `wifi.go`, `marauder.go`, `nrf24.go`, `loader.go`, `hw.go`,
  `audit.go`, `target.go`, `vision.go`, `rag.go`, `generate.go`,
  `build.go`, `workflows.go`). Each Spec carries Name, optional
  Aliases, Description, Schema, Required, Risk, Group, AgentOnly,
  and Handler. The agent's `dispatch()` and the MCP server's
  registration both iterate `tools.All()`.
- **`Spec.Aliases` handles synonym tools.** `device_info` is the
  canonical name; `system_info` is registered as an alias. Both
  resolve to the same Handler via `tools.Get`. The MCP adapter
  advertises both names; the agent's Anthropic schema declares
  both.
- **`Deps` is the dependency bag both modes inject.** `Flipper`,
  `Marauder`, `Audit`, `Config` are always wired; the LLM-only
  facilities (`Generator`, `GenLLM`, `Vision`, `Snapshot`,
  `SessionID`, `RAG`, `TargetMem`, `WorkflowConfirm`) are nil for
  MCP mode. `AgentOnly: true` Specs are excluded from the MCP
  surface; they're the only handlers permitted to dereference the
  LLM-only fields.
- **`Deps.SnapshotBeforeWrite` lifted as a helper** so handlers
  that clobber SD content (`storage_write`, `storage_copy`,
  `storage_rename`, `fileformat_edit`, all `*_build`,
  `generate_*`, `nfc_read_save`, `run_payload`,
  `generate_deploy_run`) call one method instead of duplicating
  the snapshot-then-write dance per handler.
- **`Deps.RequireMarauder` lifted as a helper** for WiFi tool
  nil-tolerance.

### Added

- **`storage_write` is now exposed to the LLM via the agent.**
  Previously only MCP clients could call it; the agent could only
  write structured payloads via `generate_*` / `*_build`. The
  bare-bytes write path closes that gap. Risk: Medium.
- **Hardware integration harnesses under `cmd/`** (`hwtest`,
  `mifaretest`, `webtest`, `clitest`) used by the orchestrator
  between every wave of the migration. The harnesses ship with the
  repo and remain reusable for future changes.
- **48 KB migration runbook** at `docs/refactor/registry-migration.md`
  with the full pre-refactor inventory, per-wave tool assignments,
  worked migration template, edge-case coverage, and acceptance
  criteria.

### Fixed

- **`device_info` ↔ `system_info` naming drift.** The MCP
  catalogue used `device_info`; the agent dispatch only matched
  `system_info`. The registry's alias mechanism fixes this — both
  names now resolve.

### Removed

- **All `s.add()` calls in `internal/mcp/server.go`.** Server
  shrunk from 1,204 to 276 lines.
- **All `case "<name>":` branches in `internal/agent/agent.go`'s
  `dispatch()`.** Function shrunk from a 700-line switch to a
  4-line registry lookup. Whole file shrunk from 2,927 to 1,233
  lines.
- **All hand-written `tool()` declarations in
  `internal/agent/tools.go`.** File shrunk from 825 to 145 lines;
  Anthropic schema is now derived from the registry.

## [0.3.3] - 2026-04-23

Scanner-loop fix for Momentum firmware. The v0.3.2 work got the loop
iterating correctly but still reported "no tag detected" on a card
that was clearly in range, because the parser and detection signal
were tuned for the older firmware output shape that includes a
`UID:` line. Momentum's scanner subcommand emits only
`Protocols detected: Mifare Classic` (no UID/ATQA/SAK) — the loop
kept retrying until timeout looking for a UID that will never appear
at this layer.

### Changed

- **Scanner-loop detection signal now matches Momentum's shape.**
  `looksLikeNFCDetection` recognises both the older
  `UID:` / `UID =` form AND the newer `Protocols detected:` /
  `Protocol detected:` form. The loop breaks immediately on either
  so live scan time drops from the full 8 s timeout budget to
  ~1.2 s when a card is present.
- **`ParseNFCDetect` fills `Type` from `Protocols detected:`** when
  no explicit `Type:` line is present. Callers see
  `Detected=true` with a concrete protocol family even on firmware
  that doesn't emit UID from scanner alone.

### Fixed

- **NFC use case reported "no tag detected" on a card in range.**
  Root cause: older detection signal only accepted `UID:` as a
  "card present" marker. Now fixed — live-Flipper `task usecases
  -- -category=nfc` run with a Mifare Classic on the reader
  reports `detected Mifare Classic` in 1.2 s.
- **`nfc_read_save` handler was silent about the Momentum UID gap.**
  Now returns an actionable message pointing at
  `nfc_dump_protocol` + `loader_mfkey` when scanner detected a
  Classic family but didn't provide UID, so operators know the
  next step instead of staring at a half-done scan.

### Verified

- `task test:full` — every package passes with `-race`
  (new `TestParseNFCDetect_MomentumProtocolOnly` locks the parser
  against this regression).
- `task eval` — **12/12 scenarios** pass.
- `golangci-lint run ./...` — 0 issues.
- Live-Flipper `task usecases` with Mifare Classic on reader:
  **pass=16 skip=3 fail=0** (unchanged counts, NFC detection
  latency 8.7 s → 1.2 s, correct protocol family reported).

## [0.3.2] - 2026-04-22

Two live-Flipper session bugs caught by a new operator-task harness —
both classes of "the tool returned success but did the wrong thing",
which is the category of failure that most reliably makes the agent
thrash. Fixed at the primitive layer so every tool inherits the
improvement.

### Added

- **`cmd/flipper-usecases` — operator-task runner.** Complementary to
  `flipper-validate`: that binary tests primitives one-by-one; this
  one tests *intent*, running realistic short natural-language
  prompts ("scan this NFC card" / "what's on my Flipper" / "listen
  on 433 MHz for 3 seconds") and reporting concise results. 19 use
  cases across health / storage / nfc / rfid / subghz / ir / bt /
  apps / feedback / deliberate-skip categories. Runs against a live
  Flipper via the existing serial transport — no LLM required. New
  `task usecases` target.

### Fixed

- **NFC subshell exit left the CLI in the `[nfc]>:` context.** After
  `NFCDetect` returned (especially on the no-detect path), subsequent
  `subghz rx` / `ir rx` / `bt hci_info` commands were rejected by the
  subshell with "could not find command" — yet primitives leaked the
  rejection text as successful empty output, so the agent saw
  `success=true` and retried downstream operations on corrupted state.
  Fix: belt-and-braces exit sequence (Ctrl+C → exit → CR round-trip
  → optional retry) that verifies the main shell is responsive
  before returning.
- **`Exec` / `ExecLongCtx` treated "could not find command" output as
  a silent success.** Every primitive above these now surfaces a
  structured `cli rejected "<verb>": <rejection-text>` error when
  the firmware didn't recognise the command — so the agent (and the
  use-case runner) see the real state instead of an empty-but-OK
  response.
- **`flipper-usecases` SD-info summary showed 0 GB** because the
  runner read `fs["total"]` / `fs["free"]` while `StorageFSInfoMap`
  emits `totalSpace` / `freeSpace`. Now reads the correct keys.

### Verified

- `task test:full` — every package passes with `-race` (two new
  `TestExec_UnknownCommandSurfacesAsError` /
  `TestExec_EmptySuccessStaysSuccess` regression locks).
- `task eval` — **12/12 scenarios** pass (unchanged from v0.3.1).
- `golangci-lint run ./...` — 0 issues.
- Live-Flipper `task usecases` run against Momentum firmware:
  **pass=16 skip=3 fail=0** across all nine non-skip categories.
  Before this release the same run returned incorrect data on
  SD info, IR, BT, apps, and SubGHz duration — all now correct.

## [0.3.1] - 2026-04-22

Quality-raising tranche (Batches A–G) plus two direct operator-feedback
fixes that landed after the live-Flipper run. The broad theme: stop the
agent from thrashing on tasks an operator can do manually in seconds.

### Added

#### Quality layers
- **Extended thinking + prospective reflection** (Batch A). Persona YAML
  gains a `thinking:` map with per-tier token budgets (Sonnet/Opus).
  Critical-risk tools get a Haiku-backed pre-dispatch critique appended
  as `<prospective-critique>` so the main model can back off before
  transmitting.
- **Per-tool context sheets + target memory** (Batch B). `internal/toolctx`
  bundles compile-time cheat sheets auto-appended to tool descriptions
  (Princeton TE timing, ATQA/SAK layouts, BadUSB delay rules, and more).
  `internal/targetmem` persists per-target facts (BSSIDs, UIDs, freq
  tuples) across sessions via SQLite; new `target_remember` /
  `target_recall` / `target_forget` tools.
- **Verify-everywhere on parametric builders** (Batch C). `subghz_build`
  / `rfid_build` / `ir_build` / `nfc_build` now run the Haiku verifier
  on the output bytes before the SD-card write. High/critical verdicts
  block unless `verify_bypass=true`. New RFID verifier prompt added.
- **BM25 documentation RAG** (Batch D). `internal/rag` with embedded
  corpus and `docs_search` tool. Pure-Go lexical retrieval — no
  embedding service required. Tokeniser splits snake_case tool names
  so `pmkid` matches `wifi_sniff_pmkid`.
- **Adversarial scenarios + confidence scoring** (Batch E).
  `internal/confidence` pre-dispatch scorer abstains on missing
  required keys or placeholder values (TODO / fixme / `<fill_in>`).
  Three new eval scenarios (confidence, prompt-injection quarantine,
  placeholder vocabulary).
- **Fine-tuning dataset export** (Batch F). `internal/trainset` +
  `/export training-set <path>` in the REPL. JSONL and OpenAI chat
  formats. `--success-only` and `--min-level` filters.
- **Fine-tune operator runbook** (Batch G). `docs/fine-tuning.md` —
  Axolotl QLoRA config, hardware sizing, vLLM serving recipe, explicit
  reminder that a local fine-tune does not replace the safety stack.

#### NRF24 Mousejack toolkit (end-to-end)
Research-first delivery: Momentum firmware has no nrf24 CLI; everything
routes through the Sniffer + Mousejacker FAPs. This release builds the
full toolkit around that surface.

- `nrf24_sniff_start` (Medium) — launches the NRF24 Sniffer FAP.
- `nrf24_list_targets` (Low) — parses `/ext/apps_data/nrfsniff/addresses.txt`
  with case normalisation and malformed-line warnings.
- `nrf24_payload_build` (Medium) — synthesises DuckyScript for
  `/ext/mousejacker/<name>.txt` with a mousejack-specific 5000 ms DELAY
  cap (2.4 GHz injection loses sync on longer pauses). Runs the BadUSB
  static validator — same lexical surface, free destructive-pattern
  detection.
- `nrf24_mousejack_start` (Critical) — launches the Mousejacker FAP.
- `workflow_mousejack` — composes list_targets → build_payload →
  re-gate FAP launch via `ConfirmSubtool` → launch. Approving the
  composite no longer silently approves keystroke injection.

#### NFC scan-and-save
- `nfc_read_save` (Medium) — the missing "scan this fob" tool.
  Composes `NFCDetect → DeviceType mapping → BuildNFC → verify → write`
  to `/ext/nfc/scanned_<uid>.nfc`. Type mapping covers NTAG213/215/216,
  Classic 1K/4K, Ultralight, DESFire. Classic-family tails the output
  with a pointer at `loader_mfkey` + `loader_mifare_nested` so the
  model proposes key-recovery rather than stopping at UID-only.

#### Campaigns, Eval, and Operator UX
- **Campaigns** (`workflow_*` composite) — declarative multi-step
  engagements with dependency gating and when-clauses.
- **Golden eval harness** — `task eval` runs 12 scenarios covering
  handoff, snapshots, ATT&CK constraints, detectors, tool errors,
  campaigns, confidence, prompt-injection quarantine, placeholder
  vocabulary, mousejack payload validation, NRF24 target parsing,
  and NFC read-save file shape.
- **WPA3 / SAE capture path** — `wifi_sniff_sae` tool wrapping the
  Marauder's raw sniff with a 60 s default and the
  deauth → capture recipe documented in-result.
- **SubGHz multi-band sweep** — `subghz_freq_sweep` generates one
  bruteforce .sub per frequency (315/433.92/868/915 MHz) in one call.
- **MIFARE attack-chain grounding** — cheat sheets for `loader_mfkey`,
  `loader_mifare_nested`, `loader_nfc_magic`, `loader_picopass`,
  `loader_seader`. The primitives already existed; the model now has
  cached guidance on when to chain each.

### Fixed

- **NFC `scanner` subcommand is one-shot on Momentum** — previously
  `NFCDetect` ran it once (~1 s) and returned "Target lost" if the
  card wasn't already on the reader when the call fired. Now loops
  the subcommand inside the nfc subshell until detection or the
  caller's timeout budget is exhausted, matching the on-device Read
  button's UX.
- **`nfc_read_save` success=true on no-detect** — used to return the
  helper string with `err=nil`, so audit recorded success and the
  agent retried forever. Now returns an error on no-detect; audit
  shows `success=false` and the agent surfaces a clean prompt to
  the operator instead of thrashing.
- **Quarantine bypass via `fileformat_read`** — SD-card file values
  are attacker-writable; the read path now wraps output in
  `<untrusted-hardware-output>`.
- **`wifi_deauth` description contradicted its Critical risk tier** —
  replaced "No restrictions" with "AUTHORIZED LAB/PENTEST USE ONLY"
  + FCC 47 CFR § 15 pointer.
- **Workflow per-primitive re-gating** — composite workflows like
  `workflow_badusb_target_profile` no longer silently approve the
  internal `badusb_run` call. `ConfirmSubtool` hook re-asks via the
  same idle-timeout confirm path.
- **`Run()` held `a.mu` across the 5-minute confirm gate** — added
  `turnMu` for turn serialisation; `a.mu` is released around
  `confirmWithIdleTimeout` so `SetPersona` / `RunTool` / status
  readers can proceed during operator idle.
- **`requiredKeys` rebuilt the tool catalog on every dispatch call** —
  2-5 ms tax per tool call eliminated via `sync.Once` cache.
- **RAG index lazy-init held `a.mu` for the 100-500 ms corpus build** —
  moved outside the lock via double-check locking.
- **`--min-level=<typo>` silently dropped the filter** in the
  trainset exporter. Unknown levels now reject up front instead of
  mapping to the zero value.
- **`targetmem` and `confidence` packages shipped as orphans** —
  `targetmem` now wired via CLI setup + three live tools; `confidence`
  runs in `executeTool` before `dispatch` and abstains on weak inputs
  with a `low-confidence input` tool error.
- **Snapshot retention was unbounded** — `snapshot.Manager.Rotate`
  trims per-session history to `DefaultRetention = 100` entries,
  invoked lazily from `storeSnapshot`.
- **NFC verifier too lenient** — prompt now catches SAK/DeviceType
  mismatch, MIFARE Classic sector-trailer Access Bits errors,
  missing/zero KeyA/KeyB, block-count overflow, NDEF-on-Classic.

### Verified

- `task test:full` — every package passes with `-race`.
- `task eval` — **12/12 scenarios** pass.
- `golangci-lint run ./...` — 0 issues.
- Live Flipper validator (Momentum firmware, real Mifare Classic
  on the reader): **39 pass / 0 fail / 8 skip**. `NFCDetect(8s)`
  returns `Protocols detected: Mifare Classic` in ~9 s wall-clock.

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
