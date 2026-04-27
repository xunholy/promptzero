---
type: reference
category: payload
subcategory: badusb
created: 2026-04-27
snapshot: 2026-04-27
---

# BadUSB / DuckyScript Payload Repos

DuckyScript payload collections, BadUSB exploit libraries, and format converters for the Flipper Zero BadUSB application. The Flipper Zero enumerates as a USB HID keyboard using the built-in BadUSB app and executes scripts written in a DuckyScript-compatible dialect. Entries cover cross-platform attack scripts (Windows, macOS, Linux), credential harvesters, reverse-shell droppers, educational awareness demos, enterprise phishing simulations, and host-side converters for Hak5 DuckyScript 3.0 and P4wnP1 HID formats.

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
| hak5/usbrubberducky-payloads | https://github.com/hak5/usbrubberducky-payloads | hak5 | ~6k | 2026-02 | MIT | active | Official Hak5 Rubber Ducky payload library; DuckyScript 3.0 |
| UberGuidoZ BadUSB | https://github.com/UberGuidoZ/Flipper/tree/main/BadUSB | UberGuidoZ | ~15k | 2026-04 | MIT | active | BadUSB payload collection in Flipper DuckyScript |
| Flipper-Zero-BadUSB (I-Am-Jakoby) | https://github.com/I-Am-Jakoby/Flipper-Zero-BadUSB | I-Am-Jakoby | ~1k | 2024-08 | MIT | stale | Flipper-specific BadUSB scripts (Win/macOS/Linux) |
| RogueMaster BadUSB pack | https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/assets/badusb | RogueMaster | ~8k | 2026-04 | GPL-3.0 | active | BadUSB payloads bundled in RogueMaster firmware |
| Unleashed BadUSB pack | https://github.com/DarkFlippers/unleashed-firmware/tree/dev/assets/badusb | DarkFlippers | ~22k | 2026-04 | GPL-3.0 | active | Unleashed-bundled BadUSB scripts |
| my-flipper-shits (aleff) | https://github.com/aleff-github/my-flipper-shits | aleff-github | ~2k | 2025-12 | MIT | active | Curated BadUSB payloads (exfil, persistence, phish) |
| simpleAV flipper-zero-badusb | https://github.com/simpleAV/flipper-zero-badusb | simpleAV | ~500 | 2024-07 | MIT | stale | macOS-focused BadUSB payloads |
| nocomp/flipperzero | https://github.com/nocomp/flipperzero | nocomp | ~300 | 2024-04 | MIT | stale | Windows credential harvesting BadUSB scripts |
| shadow-gadgets flipper-badusb | https://github.com/shadow-gadgets/flipper-badusb | shadow-gadgets | ~400 | 2024-09 | MIT | stale | Linux reverse-shell and exfil scripts |
| pico-ducky | https://github.com/dbisu/pico-ducky | dbisu | ~3k | 2025-06 | MIT | active | Raspberry Pi Pico BadUSB; DuckyScript compatible |
| FalsePhilosopher badusb-playground | https://github.com/FalsePhilosopher/badusb-playground | FalsePhilosopher | ~600 | 2025-03 | MIT | stale | Educational BadUSB PoCs with explanations |
| d0cker DuckyScript converter | https://github.com/v1nc/d0cker | v1nc | ~300 | 2024-02 | MIT | stale | DuckyScript 1.0 → Flipper BadUSB dialect converter |
| P4wnP1_aloa HID scripts | https://github.com/RoganDawes/P4wnP1_aloa/tree/master/HIDScripts | RoganDawes | ~4k | 2024-08 | GPL-3.0 | stale | P4wnP1 HID scripts (JS-based; Flipper-adaptable) |
| hak5/keycroc-payloads | https://github.com/hak5/keycroc-payloads | hak5 | ~400 | 2024-08 | MIT | stale | Hak5 KeyCroc payloads; patterns adaptable |
| RedTeamRecipe flipper payloads | https://github.com/RedTeamRecipe/flipper-zero-payloads | RedTeamRecipe | ~800 | 2025-02 | MIT | stale | Windows credential/file exfil BadUSB scripts |
| flipper-zero-linux-payloads | https://github.com/csandker/flipper-zero-linux-payloads | csandker | ~200 | 2024-05 | MIT | stale | Linux-targeting persistence and exfil scripts |
| I-Am-Jakoby hak5-submissions | https://github.com/I-Am-Jakoby/hak5-submissions | I-Am-Jakoby | ~800 | 2025-01 | MIT | stale | Enterprise phishing via BadUSB (fake auth prompts) |
| OFW BadUSB app | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/bad_usb | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Official Flipper BadUSB application |
| hak5 USB RD Script Hub | https://github.com/hak5/usbrubberducky-payloads/tree/master/payloads | hak5 | N/A | 2026-02 | MIT | active | 200+ categorized payload scripts |
| ATtiny85 rubber ducky | https://github.com/MTK911/Attiny85 | MTK911 | ~500 | 2024-06 | MIT | stale | ATtiny85/DigiSpark DuckyScript scripts |
| TheFatRat | https://github.com/screetsec/TheFatRat | screetsec | ~10k | 2025-08 | MIT | active | Metasploit APK payload generator via BadUSB |
| flipper-zero-wifi-pass | https://github.com/gorgsimon/flipperzero-badusb-wifi-pass | gorgsimon | ~300 | 2024-07 | MIT | stale | WiFi password harvester BadUSB (Windows/macOS) |
| djsissom macOS flipper payloads | https://github.com/djsissom/flipper-badusb | djsissom | ~150 | 2024-03 | MIT | stale | macOS keychain dump and shell-drop scripts |
| BADSEC payloads | https://github.com/GoodFellaZ/BADSEC | GoodFellaZ | ~200 | 2024-06 | MIT | stale | Security-awareness demo BadUSB payloads |
| PsychoPy-C CTF BadUSB | https://github.com/PsychoPy-C/flipper-badusb-ctf | PsychoPy-C | ~100 | 2024-04 | MIT | stale | CTF-challenge BadUSB flag exfil scripts |

## See also

- [BLE Advertisement / GATT Payload Repos](./bluetooth.md) — wireless HID and BLE spam
- [Sub-GHz Capture Repos & Signal Databases](./subghz.md) — RF-based remote injection
- [IR Remote Codes & Databases](./ir.md) — infrared-based remote control payloads
