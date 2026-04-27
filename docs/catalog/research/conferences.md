---
type: reference
category: research
subcategory: conferences
created: 2026-04-27
snapshot: 2026-04-27
---

# DEF CON / Black Hat / CCC / USENIX Talks

Selected talks from DEF CON, Black Hat, CCC, USENIX Security, and related venues that directly underpin Flipper Zero capabilities, FAP implementations, or adjacent protocol research.

## Legend

- **Protocol** — primary protocol or attack surface discussed
- **Venue** — conference name and edition
- **Notes** — connection to Flipper Zero tools or firmware features

## Entries

| Title | URL | Speaker | Year | Protocol | Venue | Notes |
|-------|-----|---------|------|----------|-------|-------|
| "Flipper Zero — Swiss Army Knife of Pentesters" | https://defcon.org/html/defcon-30/dc-30-index.html | Pavel Zhovner | 2022 | Multi | DEF CON 30 | Flipper Zero official DEF CON debut |
| "Hacking Rolling Codes" (RollJam) | https://www.defcon.org/html/defcon-23/dc-23-index.html | Samy Kamkar | 2015 | Sub-GHz | DEF CON 23 | Live RollJam demo |
| "AppleJuice: iOS BLE Spam Attack" | https://defcon.org/html/defcon-31/dc-31-index.html | ECTO-1A | 2023 | BLE | DEF CON 31 | iOS BLE spam; Xtreme/Momentum ble_spam FAP |
| "nRootTag: Arbitrary AirTag Emulation" | https://www.usenix.org/conference/usenixsecurity25 | SEEMOO Lab | 2025 | BLE | USENIX Security 25 | ble_findmy_emulate Spec basis |
| "SSID Confusion: Wi-Fi Rogue APs" | https://www.blackhat.com/us-24 | Mathy Vanhoef | 2024 | WiFi | Black Hat USA 24 | CVE-2023-52160; wifi_ssid_confusion |
| "FM11RF08S: MIFARE Classic Backdoor" | https://www.sstic.org/2024/presentation/fm11rf08s_mifare_backdoor | Quarkslab | 2024 | NFC | SSTIC 2024 | Hardware backdoor; mifare_fm11rf08_backdoor |
| "Unsaflok: Millions of Hotel Rooms" | https://defcon.org/html/defcon-32/dc-32-index.html | Wouters et al. | 2024 | NFC | DEF CON 32 | Full Saflok chain; SaFlip FAP |
| "Hacking Hotel Keys: Dormakaba" | https://defcon.org/html/defcon-30/dc-30-speakers.html | Wouters et al. | 2022 | NFC | DEF CON 30 | Dormakaba hotel lock chain |
| "BadUSB: Accessories That Turn Evil" | https://www.blackhat.com/us-14/briefings.html | Karsten Nohl | 2014 | USB | Black Hat USA 14 | Original BadUSB disclosure |
| "KeeLoq FPGA Cracker" | https://www.defcon.org/html/defcon-15/dc-15-speakers.html | community | 2007 | Sub-GHz | DEF CON 15 | First practical KeeLoq full-key recovery |
| "GrandTheftAuto: RF Locks with Flipper" | https://defcon.org/html/defcon-32/dc-32-index.html | Researchers | 2024 | Sub-GHz | DEF CON 32 | Vehicle RKE attacks with Flipper Zero |
| "Drone Remote ID Spoofing" | https://defcon.org/html/defcon-31/dc-31-index.html | Research team | 2023 | Sub-GHz | DEF CON 31 | ASTM F3411 DroneID spoofer |
| "iCLASS SE Downgrade Attacks" | https://www.usenix.org/conference/usenixsecurity22 | Researchers | 2022 | NFC/RFID | USENIX Security 22 | HID iCLASS SE downgrade; Seader FAP basis |
| "MagSpoof: Hacking Hotel Keys" | https://www.defcon.org/html/defcon-23/dc-23-index.html | Samy Kamkar | 2015 | RFID/NFC | DEF CON 23 | MagSpoof device; magspoof_emulate basis |
| "TETRA:BURST" | https://www.blackhat.com/us-23/briefings/schedule | Midnight Blue | 2023 | Sub-GHz | Black Hat USA 23 | TETRA radio protocol vulnerabilities |
| "Hardnested Attack Improvements" | https://media.ccc.de/v/37c3 | Netherlands team | 2023 | NFC | 37C3 | Updated hardnested for MIFARE Classic |
| "Fuzzing Flipper Zero Firmware" | https://media.ccc.de/v/38c3 | Security researchers | 2024 | Flipper | 38C3 | Firmware security analysis |
| "CAN Bus Hacking" | https://defcon.org/html/defcon-30/dc-30-index.html | Car hackers | 2022 | Automotive | DEF CON 30 | CAN bus attacks; Flipper canbus FAP basis |
| "Pwn2Own Automotive 2024" | https://www.zerodayinitiative.com/blog/2024/1/24 | ZDI | 2024 | Automotive | ZDI | EV charger / infotainment exploits |
| "Reversing the Charge: EV Security" | https://defcon.org/html/defcon-32/dc-32-index.html | Researchers | 2024 | Automotive | DEF CON 32 | ISO 15118 EV charging security |
| "UDS-on-DoIP Fuzzing" | https://defcon.org/html/defcon-32/dc-32-index.html | Car hackers | 2024 | Automotive | DEF CON 32 | Automotive UDS protocol fuzzing |
| "BLUFFS: Bluetooth Forward Secrecy" | https://www.usenix.org/conference/usenixsecurity24 | Researchers | 2023 | BLE | USENIX Security 24 | CVE-2023-24023 |
| "Tracking Without Knowing: BLE Cross-Tech" | https://dl.acm.org/doi/10.1145/3576915.3616611 | SEEMOO Lab | 2023 | BLE | ACM CCS 23 | Cross-vendor BLE tracking analysis |
| "Breaking MIFARE DESFire" | https://www.blackhat.com/html/bh-us-11/bh-us-11-briefings.html | Courtois | 2011 | NFC | Black Hat USA 11 | DESFire attack methodology |
| "NFC Practical Attacks" | https://hardwear.io/usa-2023 | Multiple | 2023 | NFC | Hardwear.io 2023 | Collection of practical NFC attack methodology |

## See Also

- [Academic Papers by Protocol Family](papers.md)
- [Relevant CVE Index](cves.md)
- [Vendor Security Advisories](advisories.md)
