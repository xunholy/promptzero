---
type: reference
category: payload
subcategory: nfc
created: 2026-04-27
snapshot: 2026-04-27
---

# NFC Dump Databases

MIFARE key corpora, NFC dump collections, transit card parsers, and synthetic key generation tools for the Flipper Zero NFC subsystem. The Flipper Zero reads and emulates ISO 14443-A/B (MIFARE Classic, MIFARE Ultralight, DESFire, NTAG21x), ISO 15693, and FeliCa cards. Entries cover raw `.nfc` dump packs, MFCL key dictionaries for nested/darkside attacks, transit card decoders, and host-side tools such as mfoc and mfkey32.

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
| UberGuidoZ/Flipper NFC | https://github.com/UberGuidoZ/Flipper/tree/main/NFC | UberGuidoZ | ~15k | 2026-04 | MIT | active | Large collection of .nfc dump files |
| equipter/NFC-Cards | https://github.com/equipter/NFC-Cards | equipter | ~500 | 2024-06 | MIT | stale | Transit and access card .nfc collection |
| DanSheps nfc-cards | https://github.com/DanSheps/flipperzero-nfc-cards | DanSheps | ~200 | 2024-03 | MIT | stale | Community NFC card dump repository |
| MFCL key dictionaries (MCT) | https://github.com/ikarus23/MifareClassicTool/tree/master/Mifare%20Classic%20Tool/app/src/main/assets/key-files | ikarus23 | ~5k | 2025-12 | GPL-3.0 | active | Default + extended MFCL key dicts; nonces for mfkey32 |
| ndeflib | https://github.com/nfcpy/ndeflib | nfcpy | ~600 | 2024-11 | ISC | active | Python NDEF parsing library |
| Proxmark3 key dictionaries | https://github.com/RfidResearchGroup/proxmark3/tree/master/client/dictionaries | RfidResearchGroup | ~12k | 2026-04 | GPL-3.0 | active | MFC key dicts for Nested/Darkside attacks |
| Metroflip | https://github.com/luu176/Metroflip | luu176 | ~600 | 2026-04 | GPL-3.0 | active | Transit card decoder: Octopus, Suica, Calypso, OPAL |
| FlipperNested | https://github.com/AloneLiberty/FlipperNested | AloneLiberty | ~1k | 2025-08 | GPL-3.0 | active | On-device MFOC nested attack + key database |
| mfoc | https://github.com/nfc-tools/mfoc | nfc-tools | ~2k | 2024-06 | GPL-3.0 | stale | Classic mfoc host-side key recovery |
| FlipperBuddy NFC generator | https://github.com/equipter/FlipperBuddy | equipter | ~1k | 2024-08 | MIT | stale | Flipper-format NFC card database + generator |
| amiibo-database | https://github.com/socram8888/amiibo-database | socram8888 | ~1k | 2024-10 | MIT | stale | Amiibo NTAG215 key database |
| SaFlip (Unsaflok) | https://github.com/aaronjamt/SaFlip | aaronjamt | ~400 | 2025-06 | MIT | active | Saflok MFC key material (hotel lock disclosure) |
| loclass iCLASS keys | https://github.com/holiman/loclass | holiman | ~500 | 2023-08 | GPL-3.0 | stale | iCLASS elite key diversification; used by Seader/Picopass |
| ChameleonUltra keys DB | https://github.com/RfidResearchGroup/ChameleonUltra/tree/main/docs | RfidResearchGroup | ~3k | 2026-04 | GPL-3.0 | active | MIFARE key database; cross-compatible with Flipper |
| OFW NFC app helpers | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/nfc/helpers | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | DESFire/NDEF parsers in official NFC app |
| amiitool_flipper | https://github.com/Gimzie/amiitool_flipper | Gimzie | ~300 | 2024-07 | MIT | stale | Amiibo NTAG215 generator with retail key support |
| nfcpy examples | https://github.com/nfcpy/nfcpy/tree/master/examples | nfcpy | ~2k | 2024-11 | ISC | active | NDEF message examples; reference for NFC Maker FAP |
| netham45 key database | https://github.com/netham45/flipper-nfc-key-database | netham45 | ~200 | 2024-04 | MIT | stale | Community-contributed MFCL key file collection |
| binaryfigments NFC tools | https://github.com/binaryfigments/nfc-tools-php | binaryfigments | ~100 | 2024-01 | MIT | stale | EMV/PayPass TLV decoder reference |
| flipper-magic-gen4 | https://github.com/mgp25/flipper-magic-gen4 | mgp25 | ~300 | 2025-03 | MIT | stale | Gen4 magic card manipulation + .nfc files |

## See also

- [RFID Dump Databases](./rfid.md) — LF/HF RFID captures and EM4100/HID key databases
- [Sub-GHz Capture Repos & Signal Databases](./subghz.md) — RF captures and bruteforcers
- [BLE Advertisement / GATT Payload Repos](./bluetooth.md) — BLE spam and FindMy emulation
