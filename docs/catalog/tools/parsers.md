---
type: reference
category: tool
subcategory: parsers
created: 2026-04-27
snapshot: 2026-04-27
---

# File Format Parsers & Protocol Decoders

Flipper Zero uses a family of plain-text and binary file formats — `.sub`, `.nfc`, `.rfid`, `.ibtn`, `.ir`, `.fap` — plus a Protobuf-over-serial RPC protocol. This catalog collects the libraries, parsers, and decoders across languages (Python, Go, Rust, Dart, JavaScript, Java, C) that read or write these formats. Entries include official Flipper firmware HAL libraries, third-party NFC/RFID libraries whose key files and dump formats are cross-compatible, and community-written parsers that extend desktop scripting capabilities. Where a project covers multiple formats, the most distinctive capability is noted.

## Legend

| Column | Values |
|--------|--------|
| Stars | `~Xk` (approximate GitHub stars) or `N/A` for sub-paths within larger repos |
| Last Commit | `YYYY-MM` |
| Status | `active` = committed to in last 12 months; `stale` = no commit in 12–24 months; `archived` = repo archived |

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| flipperzero-protobuf (official) | https://github.com/flipperdevices/flipperzero-protobuf | flipperdevices | ~500 | 2026-04 | MIT | active | Official Flipper RPC protobuf schema + bindings |
| sub-file-parser (Python) | https://github.com/jamisonderek/flipper-zero-tutorials/blob/main/subghz/tools/sub_file_parser.py | jamisonderek | ~2k | 2026-03 | MIT | active | Python .sub file parser with demodulation |
| nfcpy | https://github.com/nfcpy/nfcpy | nfcpy | ~2k | 2024-11 | ISC | active | Python NFC library; ISO14443/15693 frame parser |
| ndeflib | https://github.com/nfcpy/ndeflib | nfcpy | ~600 | 2024-11 | ISC | active | Python NDEF message parser/builder |
| flipper-file-toolbox | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/tools | jamisonderek | ~2k | 2026-03 | MIT | active | Multi-format Flipper file toolbox |
| flipper-ir-parser | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/infrared | jamisonderek | N/A | 2026-03 | MIT | active | Python .ir file parser and decoder |
| OOK/FSK demodulator | https://github.com/jamisonderek/flipper-zero-tutorials/blob/main/subghz/tools/analyze_signal.py | jamisonderek | N/A | 2026-03 | MIT | active | OOK/FSK demodulator for .sub raw files |
| rfid-file-parser | https://github.com/AdeelK93/FlipperZero-RFID | AdeelK93 | ~200 | 2024-05 | MIT | stale | Python .rfid / .ibtn file format reader |
| badusb-ducky-parser | https://github.com/nicholasgasior/ducky-parser | nicholasgasior | ~80 | 2024-06 | MIT | stale | Python DuckyScript → keystroke sequence parser |
| goflipper (Go library) | https://github.com/nicholasgasior/goflipper | nicholasgasior | ~100 | 2024-04 | MIT | stale | Go Flipper file formats + RPC library |
| flipperzero-rs (Rust) | https://github.com/dcz-self/flipperzero-rs | dcz-self | ~300 | 2025-08 | MIT | active | Rust Flipper FAP library + file format types |
| flipper_zero_dart | https://github.com/vespr-wallet/flipper_zero_dart | vespr-wallet | ~100 | 2024-06 | MIT | stale | Dart file format parser (nfc, sub, rfid) |
| FZFileParser (JS) | https://github.com/nicholasgasior/fzfileparser-js | nicholasgasior | ~80 | 2024-07 | MIT | stale | JavaScript Flipper file parser (browser + Node) |
| flipper-file-converter | https://github.com/equipter/FlipperBuddy | equipter | ~1k | 2024-08 | MIT | stale | Multi-format Flipper file converter GUI |
| MifareClassicTool parsers | https://github.com/ikarus23/MifareClassicTool/tree/master/Mifare%20Classic%20Tool/app/src/main/java | ikarus23 | ~5k | 2025-12 | GPL-3.0 | active | Java MIFARE Classic sector/key parser |
| Proxmark3 pm3 client | https://github.com/RfidResearchGroup/proxmark3/tree/master/client/src | RfidResearchGroup | ~12k | 2026-04 | GPL-3.0 | active | C RFID/NFC parser; most complete library |
| Furi HAL libs | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/lib | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Official Flipper C libs for every supported protocol |
| pcap2sub | https://github.com/nicholasgasior/pcap2sub | nicholasgasior | ~60 | 2024-05 | MIT | stale | PCAP → Flipper .sub converter |
| nfc-parser (Python) | https://github.com/nicholasgasior/nfc-parser | nicholasgasior | ~80 | 2024-04 | MIT | stale | Python .nfc file reader (MFC/NTag/NDEF) |
| sub-GHz raw frame analyzer | https://github.com/jamisonderek/flipper-zero-tutorials/tree/main/subghz | jamisonderek | N/A | 2026-03 | MIT | active | Raw Sub-GHz frame decode + statistics |

## See also

- [Automation Scripts & Helper Tools](scripts.md) — scripts that import these parser libraries
- [Desktop Tools & CLI Utilities](desktop.md) — GUI tools built on top of these parsers
- [Web-Based Tools & Online Decoders](web.md) — browser-based equivalents for ad-hoc decoding
