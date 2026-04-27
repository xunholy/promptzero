---
type: reference
category: tool
subcategory: scripts
created: 2026-04-27
snapshot: 2026-04-27
---

# Automation Scripts & Helper Tools

Automation scripts glue together Flipper Zero hardware, desktop tools, and external services into repeatable workflows. This catalog covers shell and Python scripts for bulk file operations, firmware automation, signal format conversion, CI/CD pipelines, and bot integrations. Many scripts are thin wrappers around `uFBT`, `fbt`, or the Flipper USB serial API; others are standalone converters that translate foreign formats (Proxmark3 `.eml`, Pronto IR, PCAP) into Flipper-native files. The official `flipperdevices` build scripts and community CI workflows are included alongside hobbyist helper scripts.

## Legend

| Column | Values |
|--------|--------|
| Stars | `~Xk` (approximate GitHub stars) or `N/A` for sub-paths within larger repos |
| Last Commit | `YYYY-MM` |
| Status | `active` = committed to in last 12 months; `stale` = no commit in 12–24 months; `archived` = repo archived |

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| UberGuidoZ scripts | https://github.com/UberGuidoZ/Flipper/tree/main/scripts | UberGuidoZ | ~15k | 2026-04 | MIT | active | Shell scripts for bulk file operations |
| fbt scripts | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/scripts | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Build system scripts (flash, debug, package) |
| uFBT helper scripts | https://github.com/flipperdevices/flipperzero-ufbt/tree/dev/scripts | flipperdevices | ~1k | 2026-04 | MIT | active | uFBT helper scripts (FAP upload, device detect) |
| FlipperScripts | https://github.com/DrunkBatman/FlipperScripts | DrunkBatman | ~200 | 2024-06 | MIT | stale | Bash scripts for common Flipper USB tasks |
| sub2sub converter | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/subghz/tools | jamisonderek | ~2k | 2026-03 | MIT | active | Sub-GHz file format converter |
| nfc2flipper | https://github.com/equipter/nfc2flipper | equipter | ~200 | 2024-04 | MIT | stale | Proxmark3/ACR122 dump → Flipper .nfc converter |
| IR-to-flipper scripts | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/infrared | jamisonderek | N/A | 2026-03 | MIT | active | Pronto/LIRC → Flipper .ir converter |
| fuzz-gen.py | https://github.com/derskythe/flipperzero-subghz-bruteforcer/tree/main/scripts | derskythe | ~2k | 2025-08 | GPL-3.0 | active | Python Sub-GHz fuzz payload generator |
| flipper-zero-telegram-bot | https://github.com/nicholasgasior/fztgbot | nicholasgasior | ~100 | 2024-06 | MIT | stale | Telegram bot for Flipper remote trigger |
| nfc-key-extractor.py | https://github.com/AloneLiberty/FlipperNested/tree/main/scripts | AloneLiberty | ~1k | 2025-08 | GPL-3.0 | active | Extract recovered MFC keys from FlipperNested |
| sub-analyzer.py | https://github.com/jamisonderek/flipper-zero-tutorials/blob/main/subghz | jamisonderek | N/A | 2026-03 | MIT | active | Parse and visualize .sub files (matplotlib) |
| rfid-convert.py | https://github.com/AdeelK93/FlipperZero-RFID | AdeelK93 | ~200 | 2024-05 | MIT | stale | Python RFID format converter |
| ir-to-broadlink.py | https://github.com/smartHomeHub/SmartIR/tree/master/tools | smartHomeHub | ~4k | 2025-12 | MIT | active | Flipper .ir → Broadlink/HA format converter |
| sub-replay-scheduler | https://github.com/darmiel/flipper-playlist | darmiel | ~600 | 2024-06 | MIT | stale | Sub-GHz replay playlist scheduler |
| flipper-ci-scripts | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/.ci | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Official CI/CD build, test, package scripts |
| ufbt-ci workflows | https://github.com/flipperdevices/flipperzero-ufbt/tree/dev/.github/workflows | flipperdevices | N/A | 2026-04 | MIT | active | uFBT CI workflow (FAP build matrix) |
| flipper-bundle-checker | https://github.com/xMasterX/all-the-plugins/blob/dev/.github/workflows | xMasterX | N/A | 2026-03 | MIT | active | Builds every FAP against multiple firmware targets |
| nfc-parser-scripts | https://github.com/nicholasgasior/nfc-parser | nicholasgasior | ~80 | 2024-04 | MIT | stale | Python NDEF record parsing scripts |
| flipper-auto-update | https://github.com/FalsePhilosopher/badusb-playground/tree/main/scripts | FalsePhilosopher | ~600 | 2025-03 | MIT | stale | Cron firmware auto-update daemon |
| proxmark-to-flipper | https://github.com/nicholasgasior/pm3-to-fz | nicholasgasior | ~100 | 2024-05 | MIT | stale | Proxmark3 eml → Flipper .nfc converter |
| mass-upload.sh | https://github.com/DrunkBatman/FlipperScripts/blob/main/mass_upload.sh | DrunkBatman | N/A | 2024-06 | MIT | stale | Bulk file upload script over Flipper USB |
| flipper-discord-bot | https://github.com/nicholasgasior/flipper-discord | nicholasgasior | ~100 | 2024-08 | MIT | stale | Discord bot for Flipper commands |
| rtl_433 decode pipeline | https://github.com/merbanan/rtl_433 | merbanan | ~10k | 2026-04 | GPL-2.0 | active | rtl_433 → MQTT → Flipper cross-decode pipeline |
| flipper-prometheus-exporter | https://github.com/nicholasgasior/flipper-prometheus | nicholasgasior | ~60 | 2024-05 | MIT | stale | Prometheus metrics exporter for Flipper status |
| flipper-grafana-dashboard | https://github.com/nicholasgasior/flipper-grafana | nicholasgasior | ~60 | 2024-06 | MIT | stale | Grafana dashboard for Flipper audit logs |

## See also

- [Desktop Tools & CLI Utilities](desktop.md) — GUI and CLI tools that these scripts typically wrap
- [File Format Parsers & Protocol Decoders](parsers.md) — libraries the Python scripts depend on
- [Web-Based Tools & Online Decoders](web.md) — browser equivalents for one-off conversions
