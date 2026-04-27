---
type: reference
category: tool
subcategory: web
created: 2026-04-27
snapshot: 2026-04-27
---

# Web-Based Tools & Online Decoders

Web-based tools let users generate, convert, decode, and share Flipper Zero files without installing anything locally. This catalog covers the official Flipper Lab portal, community-built file-generation PWAs, universal signal decoders like CyberChef, IR/Sub-GHz databases, online protobuf explorers, and living GitHub topic indexes. Browser-based tools are particularly useful for quickly generating NFC, Sub-GHz, BadUSB, and RFID payloads on any device. Entries marked `proprietary` require an account or are closed-source; all others are open-source or freely accessible.

## Legend

| Column | Values |
|--------|--------|
| Stars | `~Xk` (approximate GitHub stars) or `N/A` for hosted services |
| Last Commit | `YYYY-MM` (GitHub) or last known site update |
| Status | `active` = maintained; `stale` = no update in 12–24 months; `archived` = abandoned |

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| Flipper Lab | https://lab.flipper.net | flipperdevices | N/A | 2026-04 | proprietary | active | Official app catalog, firmware updater, signal uploader |
| Flipper Maker | https://flippermaker.github.io | flipper-maker | N/A | 2025-12 | MIT | active | Browser NFC/Sub-GHz/RFID/BadUSB file generator |
| CyberChef | https://gchq.github.io/CyberChef | GCHQ | ~28k | 2026-04 | Apache-2.0 | active | Universal decoder; NFC/Sub-GHz byte-level analysis |
| irdb.tk | https://irdb.tk | irdb.tk | N/A | 2025-12 | MIT | active | Online IR code DB; export to Flipper .ir format |
| Flipper Maker IR decoder | https://flippermaker.github.io/ir-decoder | flipper-maker | N/A | 2025-12 | MIT | active | Online IR signal decoder (.ir format) |
| DuckToolkit | https://ducktoolkit.com | ducktoolkit | N/A | 2025-06 | MIT | stale | Online DuckyScript editor/tester |
| GitHub topic: flipper-zero | https://github.com/topics/flipper-zero | GitHub | N/A | 2026-04 | N/A | active | Live GitHub topic index for new Flipper projects |
| GitHub topic: flipperzero | https://github.com/topics/flipperzero | GitHub | N/A | 2026-04 | N/A | active | Alternative GitHub topic for Flipper projects |
| NFC tag parser (nfc-tools) | https://www.nfc-tools.org | NFC Tools | N/A | 2025-08 | proprietary | active | Online NFC dump parser |
| NDEF decoder | https://www.ndefparser.com | community | N/A | 2025-03 | MIT | stale | Online NDEF message decoder (hex → structured) |
| Protobuf decoder | https://protobuf-decoder.netlify.app | community | N/A | 2025-04 | MIT | stale | Flipper RPC protobuf message decoder |
| Flipper firmware comparison | https://flipper.wiki/en/firmwares | flipper.wiki | N/A | 2025-09 | MIT | stale | Side-by-side CFW feature comparison |
| flipper.gg asset packs | https://flipper.gg | community | N/A | 2025-10 | MIT | stale | Browser gallery for Flipper animations/asset packs |
| flipper-zero-tutorials sub viz | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/subghz | jamisonderek | ~2k | 2026-03 | MIT | active | Web-based Sub-GHz signal visualization |
| IR lookup (irdb global) | https://github.com/probonopd/irdb | probonopd | ~3k | 2024-08 | MIT | stale | Large IR codes DB (CSV export) |
| SmartIR code lookup | https://github.com/smartHomeHub/SmartIR | smartHomeHub | ~4k | 2025-12 | MIT | active | Large AC/TV/fan code library (JSON) |
| Flipper Roadmap (Trello) | https://trello.com/b/KA3mAkry/flipper-zero-roadmap | flipperdevices | N/A | 2025-06 | proprietary | stale | Official public roadmap |
| Flipper crash decoder | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/scripts/elf_debug | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Crash log decoder / addr2line helper |
| NFC Tools Pro (web) | https://www.nfc-tools.org/pro | NFC Tools | N/A | 2025-10 | proprietary | active | Advanced NFC dump analysis |
| Flipper Zero wiki | https://flipper.wiki | community | N/A | 2025-09 | CC-BY-SA | stale | Community wiki: firmware comparisons, tutorials |

## See also

- [Desktop Tools & CLI Utilities](desktop.md) — local CLI tools for the same file generation tasks
- [File Format Parsers & Protocol Decoders](parsers.md) — programmatic libraries for format conversion
- [Blogs, Newsletters & Write-Ups](../community/blogs.md) — written tutorials that reference these online tools
