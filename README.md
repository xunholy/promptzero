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

### 97 Tools Across 5 Subsystems

| Subsystem | Tools | Capabilities |
|-----------|-------|-------------|
| **Flipper Zero** | 34 | Sub-GHz TX/RX, IR TX/RX, NFC detect/emulate, RFID read/write/emulate, iButton, GPIO, BadUSB, storage, app launcher |
| **ESP32 Marauder** | 51 | WiFi scan, deauth, beacon spam, probe flood, PMKID capture, evil portal, BLE spam, BT scanning, skimmer detection, network recon, wardriving, MAC spoofing |
| **AI Generation** | 7 | Evil portal HTML, BadUSB DuckyScript, Sub-GHz .sub files, IR .ir remotes, NFC .nfc tags - all from natural language descriptions |
| **Intelligence** | 3 | Vision analysis (photo -> device ID + attack vector), SD card app/signal discovery, device registry |
| **Audit** | 3 | SQLite audit log, session export (JSON), statistics |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         USER INPUT                               │
│              CLI / Web UI / Voice / MCP Client                   │
└──────────────┬───────────────────────────────────┬───────────────┘
               │                                   │
               v                                   v
┌──────────────────────────┐         ┌─────────────────────────────┐
│   Claude Agent (tool use)│         │   Generation Pipeline       │
│   97 tools / audit log   │────────>│   Claude / Ollama / OpenRouter│
│   risk classification    │         │   generate -> deploy -> run │
└──────────┬───────────────┘         └─────────────────────────────┘
           │
     ┌─────┴──────┐
     │             │
     v             v
┌──────────┐  ┌───────────┐
│ Flipper  │  │ Marauder  │
│ Zero     │  │ ESP32     │
│ USB ACM  │  │ USB ACM   │
│ (serial) │  │ (serial)  │
└──────────┘  └───────────┘
```

---

## Quick Start

### Prerequisites

> [!IMPORTANT]
> - **Flipper Zero** with modded firmware (Momentum, Unleashed, or RogueMaster)
> - **Go 1.25+** (required by dependencies)
> - **Anthropic API key** (`ANTHROPIC_API_KEY`)
> - **Optional:** ESP32 Marauder WiFi devboard, OpenAI API key (for voice), sox (for CLI voice)

> [!NOTE]
> **WSL2 users:** USB devices aren't passed through to WSL by default. Install [usbipd-win](https://github.com/dorssel/usbipd-win) on Windows, then from an admin PowerShell:
> ```powershell
> usbipd list
> usbipd bind --busid <BUSID>      # one-time
> usbipd attach --wsl --busid <BUSID>
> ```
> The Flipper will then appear as `/dev/ttyACM0` inside WSL.

### Install

```bash
git clone https://github.com/xunholy/promptzero.git
cd promptzero
make build
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

### Run

```bash
# CLI mode (default)
./bin/promptzero

# Web UI
./bin/promptzero --web

# Web UI on custom port with WiFi devboard
./bin/promptzero --web --web-port 3000 --wifi

# CLI with voice input
./bin/promptzero --voice

# MCP server (for Claude Desktop / Claude Code)
./bin/promptzero --mcp

# Use local Ollama for payload generation (zero exfiltration)
./bin/promptzero --gen-provider ollama --ollama-model qwen2.5-coder:14b

# Everything at once
./bin/promptzero --web --wifi --voice
```

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
- Browser-based voice recording (no sox needed)
- Status indicators and conversation management

### Voice (`--voice`)

Push-to-talk in CLI mode. Press Enter with no text to record via microphone (requires `sox`). Audio is transcribed via OpenAI Whisper, then processed as a normal command.

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
./bin/promptzero

# Local Ollama: payloads never leave your machine
./bin/promptzero --gen-provider ollama --ollama-model llama3.1

# OpenRouter: use any model for generation
./bin/promptzero --gen-provider openrouter
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

The original `make` targets still work for build/run/clean/tidy/lint.

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
