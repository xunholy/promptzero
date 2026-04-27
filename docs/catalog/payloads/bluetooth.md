---
type: reference
category: payload
subcategory: bluetooth
created: 2026-04-27
snapshot: 2026-04-27
---

# BLE Advertisement / GATT Payload Repos

BLE advertisement spam collections, FindMy emulation frameworks, GATT fuzzers, and BLE sniffer tools relevant to the Flipper Zero Bluetooth subsystem. The Flipper Zero ships a Nordic nRF52840 co-processor that handles BLE 5.0 and Classic Bluetooth, enabling BLE peripheral emulation, advertisement broadcasting, HID profiles, and serial passthrough. Entries cover iOS/Android/Windows continuity spam FAPs, Apple AirTag FindMy emulation, GATT-level MITM proxies, CTF challenge frameworks, BLE 5 sniffers, and Nordic SDK tooling.

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
| Xtreme BLE spam (archived) | https://github.com/Flipper-XFW/Xtreme-Firmware/tree/dev/applications/external/ble_spam | Flipper-XFW | ~10k | 2024-11 | GPL-3.0 | archived | Original BLE spam FAP; iOS/Android/Windows spam |
| Momentum BLE spam | https://github.com/Next-Flip/Momentum-Apps/tree/dev/ble_spam | Next-Flip | ~8k | 2026-04 | GPL-3.0 | active | Maintained continuation in Momentum |
| OpenHaystack | https://github.com/seemoo-lab/openhaystack | seemoo-lab | ~8k | 2026-04 | AGPL-3.0 | active | FindMy emulation framework (BLE LE) |
| FindMyFlipper | https://github.com/MatthewKuKanich/FindMyFlipper | MatthewKuKanich | ~2k | 2026-03 | MIT | active | FindMy AirTag emulation on Flipper via BLE |
| AppleJuice (ECTO-1A) | https://github.com/ECTO-1A/AppleJuice | ECTO-1A | ~8k | 2024-06 | MIT | stale | BLE advertising spam targeting Apple continuity pop-ups |
| furiousMAC continuity dissector | https://github.com/furiousMAC/continuity | furiousMAC | ~2k | 2025-08 | MIT | active | Wireshark dissector for Apple BLE Continuity |
| Bluetooth-LE-Spam (Android) | https://github.com/simondankelmann/Bluetooth-LE-Spam | simondankelmann | ~3k | 2025-04 | MIT | stale | Android BLE spam (FastPair, AirDrop, Easy Connect) |
| Stealtooth PoC | https://github.com/seemoo-lab/stealtooth | seemoo-lab | ~500 | 2024-08 | MIT | stale | Stealth Bluetooth pairing exploit PoC |
| BLE_CTF | https://github.com/hackgnar/ble_ctf | hackgnar | ~2k | 2024-07 | MIT | stale | BLE CTF: 20 GATT challenges solvable with Flipper |
| btle-sniffer (nccgroup) | https://github.com/nccgroup/btle-sniffer | nccgroup | ~300 | 2024-03 | MIT | stale | BLE sniffer + GATT enumeration tool |
| Flipper BLE subsystem | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/bluetooth | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Flipper BLE/Bluetooth peripheral emulation |
| apple_bleee | https://github.com/hexway/apple_bleee | hexway | ~4k | 2024-06 | MIT | stale | Apple BLE proximity info exfil PoC |
| GATTacker | https://github.com/securing/gattacker | securing | ~2k | 2024-07 | MIT | stale | GATT-level MITM proxy |
| pc-ble-driver (Nordic) | https://github.com/NordicSemiconductor/pc-ble-driver | NordicSemiconductor | ~1k | 2024-10 | Apache-2.0 | active | Official Nordic BLE sniffer + packet captures |
| Sniffle | https://github.com/nccgroup/sniffle | nccgroup | ~2k | 2025-12 | Apache-2.0 | active | BLE 5 / 4.2 sniffer for CC1352/CC26x2 (CatSniffer) |
| btlejuice | https://github.com/DigitalSecurity/btlejuice | DigitalSecurity | ~2k | 2024-04 | MIT | stale | BLE MITM framework |
| Flipper BLE HID remote | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/desktop | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Flipper BLE HID remote (media/mouse/keyboard) |
| whad-client | https://github.com/whad-team/whad-client | whad-team | ~500 | 2025-12 | GPL-3.0 | active | Python BLE/Zigbee/BLE5 tool framework |
| BLE CTF Infinity | https://github.com/hackgnar/ble_ctf_infinity | hackgnar | ~500 | 2023-12 | MIT | stale | BLE CTF: 20 GATT challenges (advanced version) |
| Android-nRF-Connect | https://github.com/NordicSemiconductor/Android-nRF-Connect | NordicSemiconductor | ~500 | 2026-03 | BSD-3-Clause | active | BLE GATT explorer; Flipper BLE debugging |

## See also

- [BadUSB / DuckyScript Payload Repos](./badusb.md) — USB HID injection payloads
- [NFC Dump Databases](./nfc.md) — contactless card dumps and key databases
- [Sub-GHz Capture Repos & Signal Databases](./subghz.md) — 315/433/868/915 MHz captures
