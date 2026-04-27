---
type: reference
category: payload
subcategory: rfid
created: 2026-04-27
snapshot: 2026-04-27
---

# RFID Dump Databases

LF/HF RFID dump corpora, EM4100/HID/Indala/iButton key databases, and Wiegand capture collections for the Flipper Zero RFID subsystem. The Flipper Zero reads and emulates 125 kHz LF RFID cards (EM4100, HID Prox, Indala, Awid, FDX-B, IoProx, Paradox, Viking, Gallagher) and 13.56 MHz HF cards via the NFC subsystem. Entries include raw `.rfid` file packs, T5577 multi-format write presets, Wiegand protocol sniffers, Proxmark3-compatible dictionaries, and Python converters between common RFID formats.

## Legend

| Column | Description |
|---|---|
| Name | Repository or project display name |
| URL | Canonical link to the resource |
| Author | GitHub user or organisation |
| Stars | Approximate star count at snapshot (`~Xk` = thousands; `N/A` = sub-repo/no stars) |
| Last Commit | Year-month of most recent commit at snapshot |
| License | SPDX license identifier |
| Status | `active` = committed within 12 months; `stale` = 12–24 months; `archived` = GitHub-archived |
| Notes | Brief description and key features |

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|---|---|---|---|---|---|---|---|
| UberGuidoZ/Flipper RFID | https://github.com/UberGuidoZ/Flipper/tree/main/RFID | UberGuidoZ | ~15k | 2026-04 | MIT | active | LF RFID .rfid files collection |
| OFW lfrfid app | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/lfrfid | flipperdevices | ~16k | 2025-12 | GPL-3.0 | active | Official LF RFID app; EM4100, HID, Indala, etc. |
| Proxmark3 LF dictionaries | https://github.com/RfidResearchGroup/proxmark3/tree/master/client/dictionaries | RfidResearchGroup | ~12k | 2026-04 | GPL-3.0 | active | LF key/dict files; protocol overlap with Flipper |
| EM4100 ID collection | https://github.com/equipter/EM4100-IDs | equipter | ~400 | 2024-04 | MIT | stale | Sample EM4100 26-bit Wiegand card ID database |
| HID format reference | https://github.com/nicowillis/rfid-hid-formats | nicowillis | ~200 | 2024-02 | MIT | stale | HID 26/37-bit format decoder + sample files |
| Unleashed T5577 presets | https://github.com/DarkFlippers/unleashed-firmware/tree/dev/applications/main/lfrfid | DarkFlippers | N/A | 2026-04 | GPL-3.0 | active | T5577 multi-write presets (EM4100/HID/Indala) |
| flipper Indala files | https://github.com/mcules/flipper_indala_files | mcules | ~100 | 2024-03 | MIT | stale | Sample Indala LF card .rfid files |
| Momentum UHF RFID FAP | https://github.com/Next-Flip/Momentum-Apps/tree/dev/uhf_rfid | Next-Flip | N/A | 2026-04 | GPL-3.0 | active | UHF RFID EPC Gen2 read/write FAP |
| UberGuidoZ iButton | https://github.com/UberGuidoZ/Flipper/tree/main/iButton | UberGuidoZ | N/A | 2026-04 | MIT | active | Dallas iButton .ibtn key files collection |
| FlipFrid LF brute | https://github.com/teedeepee/FlipFrid | teedeepee | ~600 | 2024-08 | MIT | stale | LF RFID brute-force FAP (26-bit Wiegand range) |
| Wiegand sniffer FAP | https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/wiegand | xMasterX | N/A | 2026-03 | MIT | active | Wiegand D0/D1 sniffer FAP + captures |
| FDX-B animal microchip FAP | https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/fdxb_maker | RogueMaster | N/A | 2026-04 | GPL-3.0 | active | FDX-B 134.2 kHz animal microchip synth |
| LF RFID fuzz (Unleashed) | https://github.com/DarkFlippers/unleashed-firmware/tree/dev/applications/main/lfrfid | DarkFlippers | N/A | 2026-04 | GPL-3.0 | active | LF RFID fuzz (bit-level UID modification) |
| rfid-database (redteam) | https://github.com/nicowillis/rfid-database | nicowillis | ~150 | 2024-03 | MIT | stale | Sample HID/EM4100 RFID credential files (educational) |
| GS1 RFID parser FAP | https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/gs1_rfid_parser | RogueMaster | N/A | 2026-04 | GPL-3.0 | active | GS1 EPC barcode/RFID decoder FAP |
| FlipperZero-RFID Python | https://github.com/AdeelK93/FlipperZero-RFID | AdeelK93 | ~200 | 2024-05 | MIT | stale | Python converter for LF RFID formats to .rfid |
| EM4100/EM4305 OFW protocol | https://github.com/flipperdevices/flipperzero-firmware/blob/dev/applications/main/lfrfid/protocols/lfrfid_protocol_em4100.c | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | EM4100/EM4050/EM4305 protocol implementation |
| AWID 50-bit protocol | https://github.com/RfidResearchGroup/proxmark3 | RfidResearchGroup | N/A | 2026-04 | GPL-3.0 | active | AWID 50-bit protocol reference |
| rfid-convert.py | https://github.com/AdeelK93/FlipperZero-RFID | AdeelK93 | N/A | 2024-05 | MIT | stale | Python converter for common LF RFID formats |
| Proxmark LF attack tools | https://github.com/RfidResearchGroup/proxmark3/tree/master/client/src | RfidResearchGroup | N/A | 2026-04 | GPL-3.0 | active | C-based LF attack tools (MFOC, sniff, clone) |

## See also

- [NFC Dump Databases](./nfc.md) — HF NFC/MIFARE card dumps and key corpora
- [Sub-GHz Capture Repos & Signal Databases](./subghz.md) — 300–928 MHz RF captures
- [BLE Advertisement / GATT Payload Repos](./bluetooth.md) — BLE credential-related tools
