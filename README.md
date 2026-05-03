<p align="center">
  <img src=".github/assets/banner.png" alt="promptzero - AI-powered Flipper Zero operator" width="560">
</p>

---

> **"Describe it. Generate it. Deploy it. Run it."**

PromptZero is a natural language AI operator for the [Flipper Zero](https://flipperzero.one). Talk to your Flipper like you'd talk to a person. It generates payloads, deploys them, and executes them - all from a single sentence.

---

> [!WARNING]
> **This project is heavily under active development.**
> APIs, commands, and interfaces will change without notice. Expect breaking changes, rough edges, and incomplete features. Do not use in any environment where reliability matters.

> [!NOTE]
> **This project is built entirely with AI.**
> The codebase, architecture, tool definitions, and documentation were developed using [Claude](https://claude.ai) (Anthropic). While research was conducted against official firmware source code and documentation, bugs from AI-generated code are expected. Review all generated payloads before deployment.

> [!CAUTION]
> **This software is provided strictly for educational and authorized security research purposes only.**
>
> - Only use on devices and networks you own or have explicit written authorization to test
> - Unauthorized access to computer systems, networks, and radio frequencies is illegal in most jurisdictions
> - The authors assume no liability for misuse of this software
> - You are solely responsible for ensuring compliance with all applicable local, state, federal, and international laws
> - This tool is intended for penetration testers, security researchers, and hardware enthusiasts operating within legal boundaries
>
> **By using this software, you acknowledge that you understand and accept full responsibility for your actions.**

---

## Overview

- **[What It Does](#what-it-does)** — capabilities at a glance, [tool surface](#160-tools-across-5-subsystems), [agent-layer features](#agent-layer-features-v030)
- **[Quick Start](#quick-start)** — [prerequisites](#prerequisites) · [install](#install) · [configure](#configure) · [environment variables](#environment-variables) · [examples](#examples) · [run](#run) · [try it](#try-it) · [transport options](#transport-options)
- **[Modes](#modes)** — [CLI](#cli-default) · [Web UI](#web-ui---web) · [Voice](#voice---voice) · [MCP Server](#mcp-server---mcp)
- **[Generation Pipeline](#generation-pipeline)** — [payload types](#supported-payload-types) · [multi-provider generation](#multi-provider-generation)
- **[Flipper Zero Compatibility](#flipper-zero-compatibility)** — [firmware forks](#firmware) · [serial protocol](#serial-protocol) · [Marauder devboard](#marauder-wifi-devboard)
- **[Building](#building)** — [cross-compilation](#cross-compilation)
- **[License](#license)**

---

## What It Does

PromptZero connects to your Flipper Zero (and optional ESP32 Marauder WiFi devboard) over USB serial, then lets you control everything through natural language powered by Claude.

```
promptzero> make me a Starbucks WiFi captive portal
  Generated and deployed evil_portal to /ext/apps_data/evil_portal/index.html
  Evil portal started on Marauder devboard

promptzero> scan for nearby WiFi networks and deauth the strongest one
  Found 12 access points. Strongest: "NETGEAR-5G" (-31 dBm, channel 6)
  Selected AP 0. Deauth attack running...

promptzero> create a BadUSB payload that opens a reverse shell on Windows
  Generated and deployed badusb to /ext/badusb/generated_payload.txt
  Ready to execute - plug into target and run

promptzero> what's this?  [photo of a remote control]
  That's a Samsung BN59 series TV remote using the Samsung32 IR protocol.
  I can generate a complete remote file. Want me to create it?
```

### 268+ Tools Across 5 Subsystems

| Subsystem | Tools | Capabilities |
|-----------|-------|-------------|
| **Flipper Zero** | 89 | Sub-GHz TX/RX, IR TX/RX, NFC detect/emulate, RFID read/write/emulate, iButton, GPIO, BadUSB, storage, app launcher |
| **ESP32 Marauder** | 51 | WiFi scan, deauth, beacon spam, probe flood, PMKID capture, evil portal, BLE spam, BT scanning, skimmer detection, network recon, wardriving, MAC spoofing |
| **AI Generation** | 12 | Evil portal HTML, BadUSB DuckyScript, Sub-GHz `.sub` files, IR `.ir` remotes, NFC `.nfc` tags from natural language — **plus parametric builders** (`subghz_build`, `rfid_build`, `ir_build`, `nfc_build`, `subghz_bruteforce_generate`) that synthesise correctly-framed files from typed parameters |
| **Intelligence** | 2 | Vision analysis (photo -> device ID + attack vector), SD card app/signal discovery |
| **Audit** | 3 | SQLite audit log with MITRE ATT&CK technique tags, session export (JSON), statistics |

### Agent-layer features (v0.3.0)

| Layer | Feature | Why |
|---|---|---|
| **Cost** | Anthropic prompt caching + cost-tier model routing | ~70–90% input-token reduction on 3+ turn sessions; recon on Haiku / exploit on Opus |
| **Reliability** | Reflexion-on-error + structured `ToolError` | Auto-critique on tool failure; machine-readable error codes for audit / report / detector consumers |
| **Safety** | Prompt-injection quarantine + boxed TX preview + `[R]evise` | Hardware output wrapped as data; high-risk confirms show frequency/modulation/hex with a 2 s delay; `r` to revise instead of deny |
| **Grounding** | `<device-state>` oracle on every turn | Model always knows fork / firmware / battery / SD / transport |
| **Operator UX** | `/rewind`, `/report`, `/attack`, `/stats` | Undo SD writes; Markdown engagement reports with ATT&CK heatmap; per-session technique constraint; prompt-cache hit-rate |
| **Integration** | OpenTelemetry GenAI spans | `gen_ai.*` semantic conventions; honours `OTEL_EXPORTER_OTLP_ENDPOINT`; noop when unset |
| **Quality** | Detector engine + chain-of-verification | LLM-as-judge on WiFi deauth / PMKID / NFC clone; Haiku pre-deploy verification on generated payloads with severity-blocked deploys |

---

## Quick Start

### Prerequisites

> [!IMPORTANT]
> - **Flipper Zero** — modded firmware supported (Momentum, Unleashed, or RogueMaster)
> - **Anthropic API key** (`ANTHROPIC_API_KEY`)
> - **Optional:** ESP32 Marauder WiFi devboard, OpenAI API key (for voice), sox (for CLI voice)
> - **Building from source only:** Go 1.25+

> [!NOTE]
> **WSL2 users:** USB devices aren't passed through to WSL by default. Install [usbipd-win](https://github.com/dorssel/usbipd-win) on Windows, then from an admin PowerShell:
> ```powershell
> usbipd list
> usbipd bind --busid <BUSID>      # one-time
> usbipd attach --wsl --busid <BUSID>
> ```
> The Flipper will then appear as `/dev/ttyACM0` inside WSL.

### Install

**Prebuilt binary (Linux & macOS, amd64/arm64):**

```bash
curl -fsSL https://github.com/xunholy/promptzero/releases/latest/download/install.sh | sh
```

The script is fetched from the latest release artifacts (immutable per
release tag) rather than `main`, so a compromised tip-of-`main` cannot
swap your installer mid-curl. The script then downloads the matching
release binary, verifies its SHA-256 against the release's
`checksums.txt`, and installs `promptzero` into the first writable
directory of: `$XDG_BIN_HOME`, `~/.local/bin`, or `/usr/local/bin`. Run
`sh install.sh --help` for flags (`--version`, `--prefix`).

If you prefer to inspect before piping, download and audit first:

```bash
curl -fsSLO https://github.com/xunholy/promptzero/releases/latest/download/install.sh
less install.sh   # review
sh install.sh
```

Once installed, let the CLI keep itself current:

```bash
promptzero version --check       # print current, flag if a newer release exists
promptzero upgrade               # atomic self-replace to the latest release
promptzero upgrade --dry-run     # show the plan without touching disk
promptzero upgrade --version v0.2.0   # pin
```

**Guardrails on `upgrade`:** refuses to downgrade, refuses to replace a
dev build, verifies the SHA-256 against the release's `checksums.txt`,
runs the candidate binary with `--version` before swapping, and does an
atomic rename so a failed download never leaves a half-written install.
Pass `--force` if you genuinely need to bypass any of those.

Windows users: download the `.zip` from the
[releases page](https://github.com/xunholy/promptzero/releases).
Self-upgrade isn't supported on Windows — a running `.exe` can't be
replaced atomically.

**From source:**

```bash
git clone https://github.com/xunholy/promptzero.git
cd promptzero
task dev:setup   # one-time: install pinned golangci-lint
task build       # stamps version ldflags from git
```

### Configure

```bash
cp config.example.yaml config.yaml
# Edit config.yaml - set your API key and serial port
```

Or use environment variables:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."          # optional, for voice
export OPENROUTER_API_KEY="sk-or-..."   # optional, for multi-model generation
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `ANTHROPIC_API_KEY` | Claude API key for the main agent (required unless `api_key` is set in config). |
| `OPENAI_API_KEY` | OpenAI key for Whisper voice transcription (optional). |
| `OPENROUTER_API_KEY` | OpenRouter key when `--gen-provider openrouter` is in use. |
| `PROMPTZERO_CONFIG` | Path to the config file; overrides the default search path. |
| `PROMPTZERO_WEB_TOKEN` | Bearer token for the web UI; overrides `web.token`. |
| `PROMPTZERO_LOG_LEVEL` | Operator-only log level (`debug` \| `info` \| `warn` \| `error`); overrides `observability.log_level`. |
| `PROMPTZERO_SERIAL_DEBUG` | Any non-empty value dumps Flipper serial I/O to stderr. |

### Examples

The [`examples/`](examples/) directory ships operator-ready templates you
can copy into `~/.promptzero/` to get started:

| File | Purpose |
|------|---------|
| [`examples/config.yaml`](examples/config.yaml) | Fully-commented config template covering every section (serial, marauder, web, watch, webhooks, observability, validator, cost, rules). |
| [`examples/rules.yaml`](examples/rules.yaml) | Three reactive rules: critical alerts, Mifare auto-triage, risk-level log breadcrumbs. |
| [`examples/personas/red-team-day.yaml`](examples/personas/red-team-day.yaml) | Authorised engagement persona — full offensive surface, `risk_threshold: high`. |
| [`examples/personas/blue-team-audit.yaml`](examples/personas/blue-team-audit.yaml) | Read-only forensic persona — no transmit/emulate/write, `risk_threshold: low`. |
| [`examples/personas/ctf-shelf.yaml`](examples/personas/ctf-shelf.yaml) | CTF puzzle persona — heavy on file-format surgery, audit replay, and multi-angle decode. |
| [`examples/personas/hw-lab.yaml`](examples/personas/hw-lab.yaml) | Hardware bench persona — GPIO/I2C/OneWire/UART/SPI only, vision-first pinout. |

### Run

```bash
# CLI mode (default)
promptzero

# Web UI
promptzero --web

# Web UI on custom port with WiFi devboard
promptzero --web --web-port 3000 --wifi

# CLI with voice input
promptzero --voice

# MCP server (for Claude Desktop / Claude Code)
promptzero --mcp

# Use local Ollama for payload generation (zero exfiltration)
promptzero --gen-provider ollama --ollama-model qwen2.5-coder:14b

# Everything at once
promptzero --web --wifi --voice
```

> [!TIP]
> If you built from source, the examples above become `./bin/promptzero …` — or add `bin/` to your `PATH`.

### Try It

With the REPL running, paste this at the `promptzero>` prompt:

```
promptzero> what's connected?
```

Expected response (Low risk, read-only):

```
Flipper Zero — firmware 0.99.1, hardware v7.4
Battery 84 % | SD card 4.1 GB free / 7.4 GB total
```

### Transport options

Every CLI command, web session, and MCP invocation talks to the Flipper through a pluggable **transport**. The default (`serial://`) covers 99% of setups — USB cable to the Flipper — but you can also drive the Flipper **wirelessly over BLE** without a cable, or attach a mock PTY for tests.

Select a transport by setting `serial.transport_url` in your config, or the `--transport` CLI flag. The flag overrides the config.

| Scheme                         | Example                                         | When to use                                                     |
|--------------------------------|-------------------------------------------------|-----------------------------------------------------------------|
| `serial://`                    | `serial:///dev/ttyACM0?baud=230400`             | Default. USB CDC-ACM. Fastest + most reliable.                  |
| `ble://`                       | `ble://AA:BB:CC:DD:EE:FF` (Linux/Windows) <br> `ble://e127efc1-05ec-...` (macOS) | Wireless. No cable. Slower (~2–8 kB/s) but fine for most verbs. |
| `mock://`                      | `mock:///dev/pts/5`                             | Test harness pty slave. Used by `internal/flipper/mock`.        |

> [!NOTE]
> **Marauder** has no wireless control surface in upstream firmware — `marauder.port` is always a serial `/dev/ttyUSB0`-style path. Only the Flipper supports BLE.

#### BLE over Flipper Zero

The `ble://` URL accepts three forms, picked automatically by shape:

| Form | Example | Where it works |
|---|---|---|
| Hardware MAC | `ble://80:E1:26:69:6E:55` | Linux, Windows |
| CoreBluetooth UUID | `ble://e127efc1-05ec-ce53-014e-b79fee9117fa` | macOS only — UUID is per-Mac |
| Device LocalName | `ble://Unholy` | Any platform; fallback when the above are inconvenient |

To find the right identifier, run:
```bash
promptzero --ble-discover
```
This scans for ~8 s and prints visible peripherals with name, address, and RSSI, then suggests the strongest-signal Flipper as a copy-pasteable URL.

**Pairing prerequisite (Linux / BlueZ):** the adapter needs to know the device before PromptZero can connect.
```bash
bluetoothctl scan on        # until you see your Flipper
bluetoothctl pair AA:BB:CC:DD:EE:FF
bluetoothctl trust AA:BB:CC:DD:EE:FF
```

**Pairing prerequisite (macOS):** pair the Flipper once via **System Settings → Bluetooth** so CoreBluetooth caches its identifier UUID. After that PromptZero takes the direct-connect fast path on every reconnect — no scan, no MAC lookup, just `retrievePeripherals(withIdentifiers:)` under the hood (the same pattern Apple recommends and tools like `bleak` and `swift-bluetooth-cli` use).

> macOS hides hardware BLE MACs from apps for privacy, so the address PromptZero uses is the per-Mac CoreBluetooth identifier UUID — stable on this Mac for the life of the pairing, but **different on every other Mac**. Re-run `--ble-discover` if you move the config to another machine.

**macOS build:** the upstream `tinygo.org/x/bluetooth` package needs CGO. The release pipeline builds darwin/amd64 + darwin/arm64 binaries on macOS runners with `CGO_ENABLED=1`, so the standard `install.sh` does the right thing. If you're building from source, do it on the Mac:
```bash
CGO_ENABLED=1 GOOS=darwin go build ./cmd/promptzero
```
Cross-compiled darwin binaries from a Linux host ship a stub that returns a clear "rebuild on macOS with CGO" error when BLE is attempted.

**Limitations:**
- **WSL cannot do BLE.** Windows doesn't pass Bluetooth through to the Linux guest. Use USB + `usbipd` for WSL, or run PromptZero natively.
- **Throughput is ~10× slower** than USB. A `log_stream` or a long `subghz rx` capture is noticeably less responsive, but every wrapper works — the CLI protocol is identical over the Flipper's serial GATT service.
- **Range** is Bluetooth-normal (~10 m Class 2 in practice).

All 152 tools work unchanged over BLE — capabilities detection, NFC subshell, loader close-via-back-button, everything. The transport layer is the only thing that changes.

---

## Modes

### CLI (default)

Interactive REPL. Type natural language commands, get results.

```
promptzero> scan the SD card and show me what signals I have saved
promptzero> transmit the garage door signal
promptzero> read the NFC tag on my desk
```

### Web UI (`--web`)

Dark-themed browser interface at `http://localhost:8080`. Includes:
- Chat interface with real-time WebSocket communication
- Status indicators and conversation management

**Flipper feedback:** When the web UI (or CLI REPL) drives a turn, the Flipper's blue LED lights up for the duration of that turn and turns off once the agent finishes — a quick physical signal that the agent is actively working. The CLI REPL also notes this on startup: `blue LED while agent is working`.

#### Auth

The web UI supports a shared bearer token. Set it in config —

```yaml
web:
  host: "0.0.0.0"
  port: 8080
  token: "a-long-random-string"
  cors_origins: []   # empty = same-origin only
```

— or via `PROMPTZERO_WEB_TOKEN` in the environment. HTTP callers send
`Authorization: Bearer <token>`; the browser negotiates the WebSocket
with `Sec-WebSocket-Protocol: bearer, <token>` (the server echoes
`bearer` back on success). The token is picked up from a `#token=…` URL
fragment on first load and saved to `sessionStorage`, so you can share a
login link once and forget. Leaving the token empty keeps the legacy
no-auth behaviour; the server prints a red warning if that combines
with a non-loopback bind.

PromptZero speaks plain HTTP on purpose — terminate TLS at a reverse
proxy (Caddy, Traefik, nginx) or a Tailscale/Cloudflare tunnel. There is
no built-in TLS listener; the homelab stacks you'd run this on already
have a better answer for certs than the binary would.

### Voice (`--voice`)

Push-to-talk in CLI mode. Press Enter with no text to record via microphone (requires `sox`). Audio is transcribed via OpenAI Whisper, then processed as a normal command.

Voice mode (optional) requires `sox` for microphone capture and playback:
```
Ubuntu/Debian:  apt install sox
macOS (brew):   brew install sox
Arch:           pacman -S sox
```

### MCP Server (`--mcp`)

Runs as a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio. Add to your Claude Desktop or Claude Code config:

> [!TIP]
> ```json
> {
>   "mcpServers": {
>     "promptzero": {
>       "command": "/path/to/promptzero",
>       "args": ["--mcp"]
>     }
>   }
> }
> ```

---

## Generation Pipeline

The core differentiator. Describe what you want in plain English and PromptZero creates it, writes it to the Flipper, and runs it.

| Command | What happens |
|---------|-------------|
| `"make me a Google login portal"` | AI generates pixel-perfect HTML -> writes to `/ext/apps_data/evil_portal/index.html` -> starts evil portal |
| `"create a reverse shell payload for macOS"` | AI generates DuckyScript with Flipper-specific commands -> writes to `/ext/badusb/` -> ready to execute |
| `"I need a Samsung TV remote with all the buttons"` | AI generates .ir file with NEC/Samsung32 protocol commands -> writes to `/ext/infrared/` |
| `"generate a 433MHz garage door signal"` | AI generates .sub file with correct encoding -> writes to `/ext/subghz/` |

### Supported payload types

- **Evil Portal** - Single-file HTML captive portals (form action `/get`, fields `email`/`password`, max 20KB, no external resources)
- **BadUSB** - Flipper-compatible DuckyScript with extended commands (`STRINGLN`, `HOLD`/`RELEASE`, `MOUSEMOVE`, `MEDIA`, `SYSRQ`, `ID` spoofing)
- **Sub-GHz** - `.sub` files in both parsed key format (52 protocols) and RAW format (timing data)
- **Infrared** - `.ir` files with 14 protocols (NEC, Samsung32, RC5, RC6, SIRC, etc.) and raw signals
- **NFC** - `.nfc` files (Mifare Classic, NTAG/Ultralight, ISO14443)

### Multi-provider generation

> [!TIP]
> The generation pipeline can use different LLM providers independently of the main Claude agent. Use Ollama for zero-exfiltration local generation.

```bash
# Default: Claude generates payloads
promptzero

# Local Ollama: payloads never leave your machine
promptzero --gen-provider ollama --ollama-model llama3.1

# OpenRouter: use any model for generation
promptzero --gen-provider openrouter
```

---

## Flipper Zero Compatibility

### Firmware

Tested against modded firmware with all features unlocked:

| Firmware | Status |
|----------|--------|
| **Momentum** (formerly Xtreme) | Primary target |
| **Unleashed** | Supported |
| **RogueMaster** | Supported |
| **Official (OFW) 1.x** | Supported (reduced feature set - locked frequencies, no extra protocols) |

> [!NOTE]
> Official firmware locks Sub-GHz TX to region-specific ISM bands and blocks rolling code protocols. Modded firmware unlocks the full CC1101 range (300-348 MHz, 387-464 MHz, 779-928 MHz) and enables TX for all 52 supported protocols.

### Serial Protocol

- **Connection**: USB CDC ACM (`/dev/ttyACM0` on Linux)
- **Baud rate**: Irrelevant for CDC ACM virtual serial (set to 230400 by convention)
- **DTR**: Must be asserted (handled automatically)
- **Command terminator**: `\r` (CR, 0x0D)
- **Prompt**: `>: ` (with ANSI escape stripping for subshells like `[nfc]>: `)
- **File writes**: Uses `storage write_chunk` protocol (not interactive `storage write`)

### Marauder (WiFi Devboard)

- **Firmware**: ESP32 Marauder v1.11.1+
- **Connection**: USB CDC ACM (`/dev/ttyACM1` for official Flipper WiFi devboard)
- **Baud rate**: 115200
- **Command terminator**: `\n`
- **Prompt**: `> `

---

## Building

Preferred workflow uses [Task](https://taskfile.dev):

```bash
task dev:setup      # One-time: install pinned golangci-lint
task build          # Build with version ldflags stamped from git
task test           # Short test suite (<5s)
task test:full      # Full suite, matches CI
task lint           # golangci-lint run ./...
task --list         # See every available target
```

### Cross-compilation

```bash
GOOS=linux GOARCH=arm64 go build -o promptzero-linux-arm64 ./cmd/promptzero
GOOS=darwin GOARCH=arm64 go build -o promptzero-darwin-arm64 ./cmd/promptzero
GOOS=windows GOARCH=amd64 go build -o promptzero-windows-amd64.exe ./cmd/promptzero
```

---

## License

[AGPL-3.0-or-later](LICENSE). If you host a modified promptzero as a network
service, you must publish your source changes under the same license.

---

<sub>Built with [Claude](https://claude.ai) by [xunholy](https://github.com/xunholy)</sub>
