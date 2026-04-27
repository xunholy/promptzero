---
type: reference
category: payload
subcategory: ir
created: 2026-04-27
snapshot: 2026-04-27
---

# IR Remote Codes & Databases

Infrared remote code databases, IR protocol decoder libraries, and format converters for the Flipper Zero IR subsystem. The Flipper Zero IR transceiver operates at 38 kHz and supports NEC, NECext, NEC42, Samsung32, RC5, RC6, and SIRC protocols alongside raw signal capture. Entries include the official Flipper IRDB, community crowd-sourced `.ir` file packs covering televisions, air conditioners, projectors, AV receivers, cable boxes, and cameras, as well as host-side tools for converting Pronto hex, LIRC lircd.conf, and CSV databases to the Flipper `.ir` format.

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
| OFW IR assets | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/assets/infrared | flipperdevices | ~16k | 2025-12 | GPL-3.0 | active | Official Flipper IR DB: 100+ brands (TV, AC, projectors) |
| Flipper-IRDB (UberGuidoZ) | https://github.com/UberGuidoZ/Flipper-IRDB | UberGuidoZ | ~5k | 2026-03 | MIT | active | Largest community IR database; 1000+ device files |
| flipperdevices/irdb | https://github.com/flipperdevices/irdb | flipperdevices | ~800 | 2025-11 | GPL-3.0 | active | Flipper official IR decoder/encoder repository |
| Arduino-IRremote | https://github.com/Arduino-IRremote/Arduino-IRremote | Arduino-IRremote | ~5k | 2026-03 | MIT | active | IRremote library; massive protocol support |
| LIRC database | https://sourceforge.net/p/lirc/git/ci/master/tree/remotes | LIRC project | N/A | 2024-12 | GPL-2.0 | active | Classic LIRC remote database (lircd.conf; convertible) |
| Flipper-IRDB Samsung TVs | https://github.com/Lucaslhm/Flipper-IRDB/tree/main/TVs/Samsung | Lucaslhm | ~3k | 2025-09 | MIT | active | Samsung TV/soundbar .ir files |
| Flipper-IRDB LG TVs | https://github.com/Lucaslhm/Flipper-IRDB/tree/main/TVs/LG | Lucaslhm | N/A | 2025-09 | MIT | active | LG TV/OLED .ir files |
| IRremoteESP8266 (AC codes) | https://github.com/crankyoldgit/IRremoteESP8266 | crankyoldgit | ~3k | 2026-03 | LGPL-2.1 | active | AC protocol decoding (Daikin, Mitsubishi, Fujitsu) |
| irdb (probonopd) | https://github.com/probonopd/irdb | probonopd | ~3k | 2024-08 | MIT | stale | Large IR codes DB (CSV); convertible to .ir |
| IrScrutinizer | https://github.com/bengtmartensson/IrScrutinizer | bengtmartensson | ~500 | 2024-06 | GPL-3.0 | stale | IR Scrutinizer GUI: import Pronto, export Flipper .ir |
| Flipper-IRDB AC Units | https://github.com/UberGuidoZ/Flipper-IRDB/tree/main/AC_Units | UberGuidoZ | N/A | 2026-03 | MIT | active | Air conditioner remote database (50+ brands) |
| Flipper-IRDB AV Receivers | https://github.com/UberGuidoZ/Flipper-IRDB/tree/main/AV_Receivers | UberGuidoZ | N/A | 2026-03 | MIT | active | AV receiver IR codes |
| Flipper-IRDB Projectors | https://github.com/UberGuidoZ/Flipper-IRDB/tree/main/Projectors | UberGuidoZ | N/A | 2026-03 | MIT | active | Projector remote database |
| LIRC daemon | https://github.com/lirc/lirc | LIRC project | ~800 | 2024-10 | GPL-2.0 | active | LIRC daemon; reference protocol implementation |
| Girr XML format | https://github.com/bengtmartensson/Girr | bengtmartensson | ~200 | 2024-05 | GPL-3.0 | stale | Girr XML IR format with large device library |
| Flipper-IRDB Cable Boxes | https://github.com/UberGuidoZ/Flipper-IRDB/tree/main/Cable_Boxes | UberGuidoZ | N/A | 2026-03 | MIT | active | Cable box / STB remote codes |
| SmartIR HA component | https://github.com/smartHomeHub/SmartIR | smartHomeHub | ~4k | 2025-12 | MIT | active | Large AC/TV/fan code library (JSON → convertible) |
| Tasmota IRremote | https://github.com/arendst/Tasmota | arendst | ~22k | 2026-04 | Apache-2.0 | active | Tasmota IR protocol support |
| irdb.tk online database | https://irdb.tk | irdb.tk | N/A | 2025-12 | MIT | active | Online IR code DB (NEC, RC5, RC6; export to .ir) |
| flipper-zero-camera-trigger | https://github.com/Stargate01/flipper-zero-camera-trigger | Stargate01 | ~200 | 2024-06 | MIT | stale | Camera trigger IR codes (Canon, Nikon, Sony, Olympus) |

## See also

- [Sub-GHz Capture Repos & Signal Databases](./subghz.md) — RF captures for non-IR remotes
- [BadUSB / DuckyScript Payload Repos](./badusb.md) — HID injection payloads
- [NFC Dump Databases](./nfc.md) — NFC card dumps and key corpora
