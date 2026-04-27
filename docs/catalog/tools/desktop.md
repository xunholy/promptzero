---
type: reference
category: tool
subcategory: desktop
created: 2026-04-27
snapshot: 2026-04-27
---

# Desktop Tools & CLI Utilities

Desktop tools and CLI utilities form the backbone of the Flipper Zero developer workflow. This catalog covers official desktop GUIs, build systems, language bindings, and community-built command-line helpers for working with Flipper Zero over USB, serial, or RPC. Tools span the full lifecycle: firmware flashing, file management, FAP development, backup/restore, and CI/CD automation. Entries are drawn from the official `flipperdevices` GitHub organisation and the wider community, and reflect the state of each project as of the snapshot date.

## Legend

| Column | Values |
|--------|--------|
| Stars | `~Xk` (approximate) or `N/A` |
| Last Commit | `YYYY-MM` |
| Status | `active` = committed to in last 12 months; `stale` = no commit in 12–24 months; `archived` = repo archived |

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| qFlipper | https://github.com/flipperdevices/qFlipper | flipperdevices | ~5k | 2025-12 | GPL-3.0 | active | Official desktop GUI: firmware update, file manager, logs |
| uFBT (micro Flipper Build Tool) | https://github.com/flipperdevices/flipperzero-ufbt | flipperdevices | ~1k | 2026-04 | MIT | active | FAP development environment; FAP upload |
| fbt (Flipper Build Tool) | https://github.com/flipperdevices/flipperzero-firmware/blob/dev/fbt | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Official SCons-based build system |
| flipperzero-tools (Python CLI) | https://github.com/flipperdevices/flipperzero-tools | flipperdevices | ~800 | 2025-10 | MIT | active | Official Python CLI for USB/serial commands |
| flipperzero-protobuf | https://github.com/flipperdevices/flipperzero-protobuf | flipperdevices | ~500 | 2026-04 | MIT | active | Official Flipper RPC protobuf definitions + bindings |
| VS Code Flipper extension | https://github.com/flipperdevices/vscode-flipper | flipperdevices | ~300 | 2025-11 | MIT | active | VS Code extension for FAP development |
| Flipper serial monitor (VS Code) | https://github.com/paulober/flipper-zero-vscode | paulober | ~200 | 2025-09 | MIT | active | Serial monitor + FAP debug VS Code extension |
| goflipper (Go library) | https://github.com/nicholasgasior/goflipper | nicholasgasior | ~100 | 2024-04 | MIT | stale | Go library for Flipper Zero USB/serial RPC |
| flipperzero-rs (Rust) | https://github.com/dcz-self/flipperzero-rs | dcz-self | ~300 | 2025-08 | MIT | active | Rust bindings for Flipper Zero FAP development |
| flipper-zero-dart | https://github.com/vespr-wallet/flipper_zero_dart | vespr-wallet | ~100 | 2024-06 | MIT | stale | Dart/Flutter bindings for Flipper RPC |
| FlipperBridge (serial proxy) | https://github.com/v1nc/floppyzero | v1nc | ~200 | 2024-03 | MIT | stale | Serial bridge between Flipper and host for RPC |
| FlipperScripts | https://github.com/DrunkBatman/FlipperScripts | DrunkBatman | ~200 | 2024-06 | MIT | stale | Shell scripts for common Flipper USB tasks |
| flipper-zero-tutorials tools | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/tools | jamisonderek | ~2k | 2026-03 | MIT | active | File conversion and management CLI tools |
| Kuronons FZ graphics | https://github.com/Kuronons/FZ_graphics | Kuronons | ~500 | 2025-10 | MIT | active | Flipper animation/graphics management tool |
| flipper-node (Node.js) | https://github.com/nicknisi/flipper-zero | nicknisi | ~100 | 2024-05 | MIT | stale | Node.js serial library for Flipper RPC |
| flipper-builder | https://github.com/Just-Some-Bots/flipper-builder | Just-Some-Bots | ~300 | 2024-08 | MIT | stale | Automated FAP build system (multi-firmware matrix) |
| RogueMaster fbt | https://github.com/RogueMaster/flipperzero-firmware-wPlugins/blob/main/fbt | RogueMaster | N/A | 2026-04 | GPL-3.0 | active | RogueMaster extended build scripts |
| xMasterX bundle CI | https://github.com/xMasterX/all-the-plugins/blob/dev/.github/workflows | xMasterX | N/A | 2026-03 | MIT | active | CI that builds every FAP against multiple firmware targets |
| flipper-backup script | https://github.com/nicholasgasior/goflipper | nicholasgasior | N/A | 2024-04 | MIT | stale | Backup/restore script for Flipper SD via USB |
| ufbt-action (GitHub Action) | https://github.com/nicholasgasior/ufbt-action | nicholasgasior | ~100 | 2024-07 | MIT | stale | GitHub Actions action for FAP build in CI |
| flipper-zero-action | https://github.com/nicholasgasior/flipper-zero-action | nicholasgasior | ~80 | 2024-07 | MIT | stale | GitHub Actions action for firmware flash |
| Flipper Lab (web/desktop) | https://lab.flipper.net | flipperdevices | N/A | 2026-04 | proprietary | active | Official web + desktop app catalog + firmware updater |
| flipper-mass-upload | https://github.com/DrunkBatman/FlipperScripts/blob/main/mass_upload.sh | DrunkBatman | N/A | 2024-06 | MIT | stale | Bulk file upload script via Flipper USB storage |
| flipper-auto-update | https://github.com/FalsePhilosopher/badusb-playground/tree/main/scripts | FalsePhilosopher | ~600 | 2025-03 | MIT | stale | Cron-based Flipper firmware auto-update daemon |
| sub2sub converter | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/subghz/tools | jamisonderek | N/A | 2026-03 | MIT | active | Sub-GHz file format converter |

## See also

- [Automation Scripts & Helper Tools](scripts.md) — shell/Python scripts that wrap these CLI tools
- [Web-Based Tools & Online Decoders](web.md) — browser-based companions and online decoders
- [File Format Parsers & Protocol Decoders](parsers.md) — language libraries for reading Flipper file formats
