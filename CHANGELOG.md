# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.2] - 2026-04-27

### Added

- **Dpad drives the live mirror via RPC** (`Gui.SendInputEventRequest`).
  When the operator holds the screen mirror, dpad presses are routed
  through the held RPC session as a new WS frame `screen_input
  {button, event_type}` — the dpad is no longer locked out while
  mirror owns the serial port. The dpad auto-hides outside mirror
  mode (it'd just 409 against the locked CLI input/send), and gets a
  bright orange tint + "MIRROR" badge while you're holding it.
  Each tap dispatches `PRESS → SHORT → RELEASE` to match what
  qFlipper sends — the firmware's RPC input handler does NOT
  synthesise SHORT from press/release the way the hardware path
  does, so apps subscribing to `InputTypeShort` need the explicit
  event.

- **Live LCD screen mirror in the web UI** (qFlipper-style). New
  **Device** rail item opens a panel that streams the Flipper's
  128×64 framebuffer to a Canvas at the device's native ~30 fps,
  upscaled with nearest-neighbour. Acquire is exclusive (one session
  at a time) and gated behind a confirmation modal warning the
  operator that all chat / file / input operations pause while the
  mirror is active. Auto-releases on navigate-away, browser close,
  or 30 s without a keepalive. Visibility-aware: rendering pauses
  when the tab is hidden but the lock stays held.
- **Flipper protobuf RPC client** (`internal/flipper/rpc/`). Vendors
  the upstream `.proto` files at a pinned commit (license noted in
  `LICENSE_NOTICE.md` — upstream is currently unspecified), generates
  Go bindings (committed under `pb/`), and implements the
  length-prefixed framing + a typed `Open` / `Close` / `Ping` /
  `StartScreenStream` / `StopScreenStream` surface. `Open` drains
  the firmware's CLI echo of `start_rpc_session\r` then verifies the
  RPC transition with a Ping handshake, so callers get a clean error
  instead of a misparsed first frame.
- **`*flipper.Flipper.EnterRPC`**: takes the flipper mutex, switches
  the transport into RPC mode, and returns the RPC client + a
  release closure that restores CLI mode and re-handshakes the
  prompt before unlocking. CLI methods (`ExecCtx`, `ExecLongCtx`,
  `StreamCtx`, `WriteFileCtx`) now reject with `ErrInRPCMode` while
  RPC is active so a stale concurrent CLI op can't corrupt the
  protobuf framing.
- **WebSocket `screen_*` taxonomy**: inbound `screen_acquire`,
  `screen_release`, `screen_keepalive`; outbound `screen_state`
  (broadcast on every transition with `holder_session_id` + `reason`),
  `screen_error`, plus binary `screen_frame` (1-byte format version +
  1024-byte packed framebuffer). Newest-frame-only forwarder on the
  server keeps input-to-render latency below one device frame even
  when the WS writer is slow.
- **Audit entries**: `web.screen.start` (medium risk),
  `web.screen.stop` (low risk).
- **Taskfile**: `proto:gen` and `proto:check` targets for protobuf
  binding regeneration.

### Changed

- `/api/fs/*`, `/api/input/send`, and `/api/device` now return 409
  Conflict with `{"error":"flipper screen mirror is active",
  "code":"mirror_active","retry_after_release":true}` while a mirror
  session is held. Frontend renders inline messages (no modals).
- Agent chat (`text` + `audio` WS frames) returns an `error` event
  to the originating session when mirror is active, instead of
  queueing a turn that would fail downstream.
- `/api/debug` snapshot includes a new `state.mirror_active: bool`
  field for diagnostic dumps.

### Fixed

- **RPC handshake retry loop** — `start_rpc_session\r` echo length
  varies between firmware builds and device states; a single 300 ms
  drain wasn't always enough and the first protobuf read could
  misparse. `Open()` now retries the Ping up to 5 times with a 150 ms
  drain between attempts.
- **Cross-platform build** — production handlers (`api_fs.go`,
  `api_input.go`, `api_screen.go`) carried `//go:build linux` tags
  inherited from the test pattern, breaking darwin/windows builds.
  Tags moved to test files only. `internal/flipper/mock` and
  `internal/testmocks` (Linux pty) and `cmd/webtest` (POSIX signals)
  now declare their constraints explicitly.
- **CLI 409 polling spam** — the frontend's 30s `/api/device` poll
  was logged by the browser as "failed resource load" while mirror
  was active. Skip the poll entirely while held; status arrives via
  `screen_state` WS frames anyway.
- **Arrow glyphs match** — left dpad arrow used U+25C4 (POINTER), all
  others used the TRIANGLE family. Normalised to `▲ ▼ ◀ ▶` so they
  read as the same icon set.

### Changed

- Settings rail icon swapped from sun-burst (circle + 8 radial lines)
  to a proper 8-tooth cog SVG.
- Category landing screen badge `RUN ▶` shortened to `RUN` — reads
  cleaner alongside the LOW/MED/HIGH siblings.
- Prompt bar prefix `promptzero>` shortened to `>` — brand already
  lives in the status bar.

## [0.9.1] - 2026-04-26

### Added

- **Direct Flipper navigation in the web UI** (qFlipper-style file
  browser + virtual D-pad), running alongside the existing chat. New
  rail item **Files** opens a two-pane SD-card browser with read-only
  preview of `.sub` / `.nfc` / `.rfid` / `.ir` / `.txt` formats; binary
  files render as base64. Action buttons in the preview (Replay, Emulate,
  Send, Run) synthesise a chat turn so the existing risk-confirm flow
  applies — no new risk surface. Upload, delete, mkdir, rename are gated
  behind in-pane confirms and audited as `web.fs.*`.
- **D-pad SCROLL ↔ DEVICE toggle**: the on-screen d-pad now optionally
  forwards button events to the Flipper via `POST /api/input/send`,
  audited as `web.input.send`. Default mode (`scrollback`) preserves
  the existing chat-navigation behaviour.
- **`/api/fs/*` endpoints**: `list`, `read` (256 KiB cap), `stat`,
  `upload` (1 MiB cap, configurable via `Server.SetMaxUploadBytes`),
  `delete`, `mkdir`, `rename`. All require bearer auth and reject paths
  outside `/ext`.
- **`/api/input/send`** for short-event button dispatch.
- **UI-context plumbing**: a new `ui_context` WebSocket frame tells the
  agent which file the operator is currently browsing; the agent prompt
  gains a `<ui-context view="..." path="..."/>` line so questions like
  "what is this?" land in the right context. View values are
  allowlisted server-side to prevent prompt-attribute injection.
- **Awesome Flipper Zero ecosystem index**
  (`docs/awesome-flipper-zero-projects.md`): flat catalog of every
  Flipper-Zero-adjacent repo discovered as of 2026-04-26, plus an
  appendix flagging adversarial bundles for the firmware-allowlist /
  payload-blocklist Specs.

### Changed

- **`--web` mode starts without a Flipper attached** so the operator
  can open the cockpit and plug the device in later. REPL and `--mcp`
  modes keep the original fatal connect behaviour.
- Web UI shell now fills the entire viewport on every breakpoint
  instead of the boxed `min(1280px, 96vw)` cap; bezel screws and the
  redundant "PZ" wordmark icon removed. Subtle "BUILT BY XUNHOLY"
  watermark added in the LCD bottom-right.
- Subsystem rail items (Sub-GHz, RFID, NFC, IR, iButton, GPIO, Bad
  USB, Apps, Marauder) now open a category landing screen listing
  likely tools/attacks. Low-risk read-only items (e.g. "List installed
  FAPs", "Read tag") show `RUN ▶` and dispatch immediately; med/high
  risk or items with `<placeholder>` parameters prefill the prompt
  for review.
- Every sub-screen (settings root + children, audit, report, files,
  category) now has an on-screen `◀ BACK` button. Files screen back
  walks up the directory tree before exiting; settings children pop
  to the settings menu first.
- Sub-screen rail items now use the LCD palette on hover (legible
  against the orange background), and all chevrons normalised to the
  same Unicode glyph and 8 px size.

### Removed

- **PromptZero Companion FAP**: dropped the on-device status renderer
  (`fap/companion/`, `internal/flipper/companion/`,
  `cmd/install-companion-fap/`, `bin/fap/`, `setupCompanion`,
  `Server.SetCompanion`, `CompanionConfig`, the `fap:companion:*`
  Taskfile targets). The Flipper CLI refuses commands while any FAP is
  open ("this command cannot be run while an application is open"), so
  a host that drives the device over CLI cannot also have an on-device
  companion app running. The risk-confirm gate now lives only in the
  REPL/web surfaces.

## [0.9.0] - 2026-04-26

First tagged release since v0.5.0. Collapses four development tranches
(v0.6 OSS-expansion → v0.9 web redesign) into a single semver release;
the per-tranche labels in commit subjects remain as historical markers.

### Added — v0.9 web redesign

- **Flipper-themed web UI** (`internal/web/static/`): rewritten with a
  hardware-shell layout — bezel chrome, dot-matrix LCD scrollback, side
  rail, and chunky d-pad. Reactive across desktop / tablet / phone with
  safe-area insets, hover-none and reduced-motion paths, ≥44 px touch
  targets, and iOS zoom suppression. All agent-originated content goes
  through `createElement` + `textContent`; no `innerHTML` carries
  untrusted data.
- **Typed `/api/device` sections** for the new status bar: `flipper`,
  `marauder`, `ble`, `sd` (uint64 bytes), `battery.percent` (numeric).
  Existing string-shaped fields preserved for back-compat.
- **PromptZero Companion FAP** (`fap/companion/`,
  `internal/flipper/companion/`, `cmd/install-companion-fap/`):
  optional Flipper application that renders agent events on the device
  LCD and lets OK/Back answer the high-risk confirm gate. NopSink is
  the default — operators without the FAP run unchanged.
- **Marauder firmware lazy-probe**: non-blocking goroutine populates
  `marauder.firmware` after connect; first `/api/device` returns empty,
  subsequent return populated.
- **canbus tool**: expanded coverage and first unit test file.

### Fixed — v0.9

- crypto1 polish: small bug fixes and expanded fixtures across mfcuk,
  mfkey32, mfoc, and RecoverFast (iterations on the v0.7 native ports).
- Faultier client + tool spec touch-ups (faultier, firmware_extract,
  mifare, spec).

### Added — v0.6 OSS-expansion: outbound federation + cracker primitives

Driven by a multi-agent dev team: 1 lead + 3 parallel engineers (Crypto1,
KeeLoq, pcap) + cross-cutting wiring on the lead thread. ~7000 LOC
across 9 new packages.

- **`internal/mcpfed/`** (new) — outbound MCP client federating external
  servers as native Specs. Stdio/HTTP/SSE transports, sandbox profiles
  (none/docker/bwrap/firejail) wired via `transport.WithCommandFunc`,
  prefix `__` namespacing within Anthropic's 64-char tool-name limit,
  schema pass-through via `mcp.Tool.RawInputSchema`, MCP annotation →
  `risk.Level` mapping (DestructiveHint→Critical, ReadOnlyHint→Low,
  OpenWorldHint→+1 tier), one-shot retry on `ErrTransportClosed` plus
  background health pings. Boot integration in
  `cmd/promptzero/setup.go:setupMCPFederation`; config block in
  `config.example.yaml` under `mcp_clients:[]` with six high-leverage
  examples (FuzzingLabs hub, pm3-mcp, Hashcat-MCP, BloodHound-MCP-AI,
  Burp, GhidraMCP). Operator guide:
  `docs/integrations/mcp-federation.md`.

- **`internal/keeloq/`** (new) — pure-Go KeeLoq cipher
  (32-bit block, 64-bit key, 528 rounds, NLFSR with S-box 0x3A5C742E),
  CPU brute-force sharded across `runtime.NumCPU()` (~12M keys/sec on a
  16-core host), and a manufacturer-key dictionary covering HCS-200/300/360/410.
  Specs: `keeloq_decrypt` (Low), `keeloq_dictionary` (Medium),
  `keeloq_bruteforce` (Critical). Closed-loop verified plus published
  test vector cross-checked against an independent Python reference.

- **`internal/pcap/`** (new) — pure-Go libpcap classic writer +
  radiotap-header builder (link-types 1/105/127). Closes the WiFi
  capture → hashcat chain in `workflow_wifi_target_to_hashcat`.

- **`internal/defense/`** (new) — Wall-of-Flippers heuristic classifier
  for BLE advertisements. Detects Apple Continuity spam (action types
  outside the published set), Microsoft Swift Pair malformed payloads,
  Samsung sentinel model-id, Google Fast Pair repeated-byte signatures,
  and Flipper service UUID 0xFE60. Stateful `Tracker` adds high-frequency
  MAC-rotation detection. Spec: `defense_classify_advertisement` (Low).

- **`internal/containerbridge/`** (new) — shared sandboxed `docker run`
  runner powering three new Specs:
  - `urh_decode_sub` (Low, GroupFlipperSubGHz) — PentHertz/urh-ng SubGHz
    classifier across 327 known protocols.
  - `firmware_extract` (Medium, GroupFlipperHW) — onekey-sec/unblob
    recursive firmware extractor.
  - `fap_build` (Medium, GroupGen) — flipperdevices/ufbt SDK build with
    optional Flipper-side deploy.

- **`internal/tools/corpora.go`** (new) — three read-only Specs that
  search operator-curated asset directories (no third-party content
  bundled — license clarity + staleness avoidance):
  - `ir_irdb_lookup` — Lucaslhm/Flipper-IRDB layout.
  - `evil_portal_template_pick` — HTML/JS templates by brand+language.
  - `badusb_payload_search` — Ducky-script grep by goal keyword.
  Default paths from `PZ_IRDB_DIR`, `PZ_EVIL_PORTAL_DIR`, `PZ_BADUSB_DIR`.

### Changed

- **`internal/risk/`** — added `Register/Unregister` runtime overlay so
  federated MCP tools (and any post-init Spec) publish risk levels
  without touching the static `toolLevels` map. `Classify` consults the
  overlay first; static fallback unchanged.
- **`internal/config/`** — added `MCPClients []yaml.Node` field for raw
  federation config. Decoded by `mcpfed.ParseClientConfigs` so config
  remains independent of the federation runtime.

### Registry

- 188 → 198 Specs (+10 native + N federated at runtime).

### Hardware backends (Wave 0b / 3c / 3d / 3e / 4a / 4b)

Six new device backends added — all written against documented
upstream protocols, no bench validation in this session, users
exercise on real hardware:

- **HTTP transport** (Wave 0b) — `internal/flipper/transport/http.go`.
  Targets jblanked/FlipperHTTP-compatible servers. Long-poll recv +
  streaming POST send + bearer-token auth + custom-path overrides.
  `http://host:port[/?token=...&send_path=...&recv_path=...]` URL
  scheme parallel to `serial://` and `ble://`. Decouples agent from
  physical USB session.

- **Faultier glitcher** (Wave 3c) — `internal/faultier/` (329 + 170 +
  222 + 208 + 353 LOC across client/protocol/mock/protocol_test/
  client_test). Six Specs in `internal/tools/faultier.go`:
  `glitch_arm` / `glitch_fire` / `glitch_set_pulse` / `glitch_sweep` /
  `glitch_disarm` / `glitch_status`. Wire protocol mirrored from
  hextreeio/faultier-python.

- **CANbus** (Wave 3d) — `internal/tools/canbus.go`. Six Specs:
  `canbus_init` / `canbus_sniff_start` / `canbus_sniff_stop` /
  `canbus_inject` / `canbus_replay` / `canbus_info`. Bridges to
  ElectronicCats/flipper-MCP2515-CANBUS .fap via the existing
  `flipper_raw_cli` mechanism.

- **Bus Pirate 5** (Wave 3e) — `internal/buspirate/` (engineer-written
  client/parser/mock with comprehensive tests). Seven Specs in
  `internal/tools/buspirate.go`: `buspirate_mode` / `buspirate_i2c_scan` /
  `buspirate_spi_dump` / `buspirate_uart_bridge` / `buspirate_voltages` /
  `buspirate_pin_set` / `buspirate_pin_read`. PIO-driven I2C up to
  500 kHz, much faster than Flipper GPIO bit-banging.

- **Bruce ESP32** (Wave 4a + 4b absorbed) — `internal/bruce/`. Twelve
  Specs in `internal/tools/bruce.go`: `bruce_capabilities` /
  `bruce_wifi_scan` / `bruce_wifi_5g_scan` / `bruce_wifi_deauth` /
  `bruce_evil_twin` / `bruce_zigbee_scan` / `bruce_lora_scan` /
  `bruce_ir_send` / `bruce_ir_receive` / `bruce_badusb_run` /
  `bruce_nfc_read` / `bruce_raw_cli`. Boot-banner parser detects
  ESP32-C5 (HasFiveGHz=true), M5Stack family (Cardputer / M5Stick /
  T-Display / CYD), and IR hardware presence. Evil-M5Project hardware
  uses a Bruce-compatible serial dialect, so it's covered by the same
  backend.

### MIFARE Classic key recovery (Wave 1a + 1c)

`internal/crypto1/` filled in end-to-end:
- `Init`, `Crypt`, `EncCrypt`, `CryptFeedback`, `Prng`, `clockLFSR`
  — all clean-room implementations of the Garcia et al. ESORICS 2008
  algorithm.
- Filter functions `fa` / `fb` / `fc` and bit helpers wired per the
  paper's tap arrangement.

`internal/crypto1/mfkey32.go`:
- `Recover` / `RecoverWithRange` — Courtois-style LFSR rollback against
  two captured authentication exchanges. Closed-loop verified with
  three synthetic key vectors.
- `AuthEncrypt` — simulates the reader-side auth so callers can produce
  test vectors without hardware.

`internal/tools/mifare.go` rewired:
- `mfkey32_recover` returns `status="found"` with the recovered key.
  Default 16-bit search range completes in ~70 ms; operators pass
  `search_range_bits` up to 48 for full keyspace.
- `mfoc_attack` and `mfcuk_attack` return `status="live_nfc_required"`
  with an error pointing operators at the federated `pm3-mcp` MCP
  server (their canonical libnfc form requires live NFC reader access
  which the Flipper's USB CLI doesn't expose).

`internal/tools/hardnested.go` (Wave 1c) — `mifare_hardnested_host`
Spec wraps `nfc-tools/mfoc-hardnested` in a sandboxed container for
Plus / EV1 hardened-nonce key recovery. Default image
`ghcr.io/nfc-tools/mfoc-hardnested:latest`; operators override via
`HARDNESTED_IMAGE` env or `image` argument.

### Boot integration

`cmd/promptzero/setup.go` gains `setupBruce` / `setupFaultier` /
`setupBusPirate` parallel to `setupMarauder`, all wired into
`cmd/promptzero/main.go`'s startup sequence. `internal/agent/agent.go`
gains `SetBruce` / `SetFaultier` / `SetBusPirate` setters and
forwards the new clients into `a.deps()` so handlers see them via
`tools.Deps.{Bruce,Faultier,BusPirate}`.

`internal/config/config.go` adds `BruceConfig`, `FaultierConfig`, and
`BusPirateConfig` types under `bruce:` / `faultier:` / `buspirate:`
YAML keys.

### Registry

- 198 → 230 Specs (+32 native Specs in this batch).
- All 32 new Specs explicitly classified in
  `internal/risk/risk.go`'s `toolLevels` map.
- `TestRegistrySize` / `TestRegistryCoverage` / `TestRiskCoverage`
  green; full module passes `go test -race -short ./...`.

### Deferred to v0.6.1+

- Wave 1b — pure-Go `mfoc_attack` / `mfcuk_attack` offline
  implementations with state-propagation across nested authentications.
  Today operators handle this via federated `pm3-mcp` for the live
  case, or pre-process captures into mfkey32 tuples and call
  `mfkey32_recover` directly.
- `mfkey32_recover` partial-state-enumeration optimization — current
  impl is O(2^32) within the configured `search_range_bits` budget
  and adequate for the common case (default keys, low-entropy keys);
  full 2^48 needs the Garcia §4 filter-selectivity technique to be
  agent-fast.
- Pure-Go `mifare_hardnested_host` reimplementation (the ~2 kloc
  bitslice optimisation in `nfc-tools/mfoc-hardnested`). Container
  bridge ships today.

## [0.5.0] - 2026-04-25

v0.5 opens the offensive-capability expansion track. This release
absorbs attack-tool coverage from established pentest projects as
**native Go code** — no outbound MCP federation, no runtime deps on
external tools, `go build` still produces a single binary. Five
shipping deliverables across research, firmware introspection,
offline key recovery, host-side security recon, and CI tooling.

Driven end-to-end by a 12-agent development team: 1 architect + 4
parallel researchers + 5 parallel engineers (2 retries after the
first pair stalled) + 1 tester + 1 security reviewer, orchestrated
through the same wave + hardware-gate pattern that shipped v0.4.

### Added — offensive capabilities

- **`firmware_introspect` Spec** (Low risk, `GroupFlipperSystem`) —
  capability oracle. Returns the connected Flipper's fork
  (OFW/Unleashed/Momentum/Xtreme/RogueMaster), version band, commit,
  build date, and a 23-flag feature bitmap the LLM consults before
  any fork-gated tool call. Eliminates trial-and-error on heterogeneous
  firmware. Backed by 15 real `device_info` fixtures (3 per fork) and
  expanded detection rules for 8 new capabilities beyond the v0.4 set.

- **`iclass_loclass_recover` Spec** (High, `GroupFlipperNFC`) — pure-Go
  port of the loclass attack against HID iCLASS Elite (High Security).
  Recovers per-site `Kcus` from 8 captured reader-authentication
  exchanges. Algorithm from García/de Koning Gans/Verdult/Meriac
  ESORICS 2012; clean-reimpl, not a source-port. All 5 published
  sub-primitive vectors (Hash0, Hash1, Hash2, PermuteKey, DoReaderMAC)
  pass. Offline only — no card I/O.
  New package: `internal/iclass/` (1,296 LOC).

- **4 Tier-1 host-side recon Specs** in new `internal/tools/security.go`
  (group: `GroupSecurity`):
  - `hash_identify` (Low) — heuristic hash-format detection for
    MD5/SHA-1/SHA-256/SHA-512/NTLM/bcrypt/Argon2 etc.
  - `hash_crack_dictionary` (Critical) — pure-Go offline dictionary
    attack. Algorithms include NTLM (MD4 of UTF-16LE) and bcrypt.
  - `port_scan_tcp` (High) — TCP connect scan via `net.Dial` with
    concurrency cap and per-port timeout.
  - `http_enum_common` (High) — directory/file enumeration against
    HTTP servers with built-in wordlist corpus.

- **`internal/wordlists/`** — embedded password + directory wordlist
  subsets (SecLists top-N + dirb common.txt subset). Exposed as MCP
  resources (`promptzero://wordlists/...`) and consumable by the
  Tier-1 recon Specs.

- **`mfoc_attack`, `mfcuk_attack`, `mfkey32_recover` Specs** (High,
  `GroupFlipperNFC`) — registered as **stubs** for v0.5. Handlers
  return a structured "scheduled for v0.5.1" message with operator
  workaround (use `loader_mfkey` FAP for in-device mfkey32; use
  `nfc_dump_protocol mfc` for capture). The 34 KB algorithm
  reference at `docs/refactor/mifare-algorithms.md` is the
  substantive v0.5 contribution here; v0.5.1's wave-2 lands the
  `internal/crypto1/` impl + replaces the stub Handlers.

### Added — tooling & research

- **`cmd/coverage-diff`** — scrapes awesome-flipperzero lists
  (djsime1, RogueMaster, xMasterX, jamisonderek, UberGuidoZ), parses
  tool/verb names, diffs against `internal/tools/` Spec names, outputs
  a markdown report of what's available upstream that PromptZero
  doesn't yet expose. New GitHub workflow runs it weekly with
  `continue-on-error: true`.

- **Research corpus** at `docs/refactor/`:
  - `firmware-matrix.md` (48 KB) — per-fork `device_info` field
    reference, CLI verb diff, version-band regexes, capability
    bitmap; flags 5 errors in the architect's initial runbook.
  - `mifare-algorithms.md` (34 KB) — Crypto1 LFSR tap resolution
    (conflict between mfoc and proxmark3 was notation-only, not
    algorithmic), filter truth tables, 5 test vectors.
  - `iclass-loclass-algorithm.md` (24 KB) — loclass sub-primitive
    vectors and synthetic fixture path (avoids GPL provenance on
    iceman's `iclass_dump.bin`).
  - `mcp-feature-extraction.md` (50 KB) — capability inventory for
    4 reference MCPs (mcp-security-hub, pentest-mcp, Hashcat-MCP,
    pm3-mcp), Tier 1/2/3 triage for future ports.
  - `v0.5-runbook.md` (34 KB) — per-engineer assignments, capability
    bitmap design, Crypto1 cipher contract, license posture
    classification.

### Changed

- **Capability bitmap** in `internal/flipper/capabilities.go` expanded
  from the v0.4 baseline. Three `Stock` defaults corrected (research
  caught 3 wrong values in the v0.4 code):
  - `PowerInfoCmd` stock default flipped to `info power` (no modern
    fork uses `power_info` as a top-level verb).
  - `SubGHzRxRawHasFilePath` stock default flipped to `false` (every
    modern fork streams `subghz rx_raw <freq>` to stdout).
  - `NFCFlaggedArgs` gated on `FirmwareAPIMajor` (modern OFW
    dev/1.x ships flagged NFC CLI).

- **MCP server** (`internal/mcp/server.go`) gains `promptzero://` URI
  resource scheme for embedded wordlists, plus a documentation
  block clarifying the `_confirmed` ↔ Risk-tier equivalence that
  operators migrating from pm3-mcp expect.

### Deferred to v0.5.1

- **Crypto1 cipher full implementation** — the v0.5 wave's most
  algorithmically tight scope; two engineer attempts did not converge
  against the 5 test vectors within the engineering window. The
  skeleton + vectors + algorithm doc ship in v0.5; the impl moves to
  v0.5.1 via interactive vector-driven debugging.
- **Mifare offline crackers** (mfoc/mfcuk/mfkey32 full Handlers)
  unblock once Crypto1 lands.
- **loclass synthetic capture generator CSN selection** — end-to-end
  round-trip test is skipped in v0.5 (`TestLoclassEndToEnd`). The
  actual attack works on real 8-capture input; only the fixture
  generator's Swende-optimal CSN search needs the v0.5.1 followup.
- **`mifare_hardnested_recover`** — seed direction at Meijer-Verdult
  2015 WOOT paper (table-free statistical variant, ~10× slower but
  pure-Go friendly with no 250 GB precomputed tables).

### Tool registry

Registry size: 184 → **188** Specs. Net: +1 firmware_introspect, +4
Tier-1 security, +3 Mifare stubs, +1 iclass_loclass_recover.

### Verified

- `task test:full` — every package passes with `-race`
- `task lint` — 0 issues
- All 4 hardware harnesses green (`hwtest` 23/23, `mifaretest` 12/12,
  `webtest` 9/9, `clitest` 5/5) against real Flipper Zero Momentum
  mntm-dev.
- Default persona unrestricted — every new Spec accessible.
- `TestRiskCoverage` enforces 100% risk-classification coverage of
  the 188 Specs.

## [0.4.1] - 2026-04-24

Patch release: fixes a session-killing bug in conversation-history
compaction that affected any operator running long sessions where the
first prompt invoked a tool (the common case).

### Fixed

- **`compactHistoryLocked` orphaned tool_use at messages.1** when
  `a.history[1]` was an assistant message containing a `tool_use` block
  and `a.history[2]` was the matching user `tool_result`. The hardcoded
  anchor `a.history[:2]` discarded the `tool_result` on first compaction
  (history > 100 entries), leaving the orphan in place. The Anthropic
  API then rejected every subsequent turn with HTTP 400:

      messages.1: `tool_use` ids were found without `tool_result`
      blocks immediately after: toolu_XXXX. Each `tool_use` block
      must have a corresponding `tool_result` block in the next
      message.

  The bug was reproduced by a 35-prompt CLI smoke test (`cmd/cliyolo`)
  that hit it at prompt 24/35 once the live session crossed
  maxHistory. Fix: extend the anchor end forward (up to 8 entries) when
  the last anchor message has a `tool_use`, swallowing the matching
  `tool_result`. Fall back to dropping the anchor entirely if the
  pairing is malformed (defensive).

### Added

- **`cmd/cliyolo`** — PTY-driven CLI runner with a 35-prompt
  non-destructive test set covering every Flipper subsystem (system,
  storage, hardware, NFC, SubGHz, IR, RFID, iButton, audit, BadUSB
  validate, workflow, storage round-trip). Exits non-zero on
  regression so it's CI-ready. Used to prove the fix end-to-end.
- **`cmd/cliprobe`** — minimal one-shot PTY probe used during
  diagnosis. Useful for triaging future REPL issues without burning
  through the full harness.
- Two regression tests in `internal/agent/history_test.go`:
  - `TestCompactHistoryLocked_AnchorWithToolUseExtended` — pins the
    cliyolo failure shape (first turn invokes a tool, history saturates,
    no orphan in compacted result).
  - `TestCompactHistoryLocked_AnchorMalformedDropsAnchor` — confirms
    the drop-anchor fallback when the pairing is broken.

### Verified

- All 4 hardware harnesses pass (`hwtest`, `mifaretest`, `webtest`,
  `clitest`) on a real Flipper Zero (Momentum mntm-dev).
- `cliyolo` 35/35 PASS in 19 minutes against the live device.
- `task test:full` — every package passes with `-race`.
- `task lint` — 0 issues.

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
