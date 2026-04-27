---
type: reference
category: research
subcategory: papers
created: 2026-04-27
snapshot: 2026-04-27
---

# Academic Papers by Protocol Family

Foundational and recent academic papers on protocols implemented in the Flipper Zero ecosystem, indexed by protocol family.

## Legend

- **Protocol** — primary wireless/physical protocol covered
- **Venue** — publication venue (conference, journal, or repository)
- **Notes** — relevance to Flipper Zero tooling or FAP implementations

## Entries

| Title | URL | Authors | Year | Protocol | Venue | Notes |
|-------|-----|---------|------|----------|-------|-------|
| "The MIFARE Classic Story" | https://www.cs.ru.nl/~flaviog/publications/Attack.MIFARE.pdf | García et al. | 2008 | NFC/RFID | ESORICS | Original Crypto-1 cryptanalysis; basis for mfoc/mfcuk |
| "Dismantling MIFARE Classic" | https://link.springer.com/chapter/10.1007/978-3-540-88313-5_7 | García et al. | 2008 | NFC/RFID | ESORICS | Second-gen Crypto-1 analysis; nested attack basis |
| "Wirelessly Pickpocketing a Mifare Classic Card" | https://ieeexplore.ieee.org/document/5504793 | Courtois et al. | 2009 | NFC/RFID | IEEE S&P | Darkside attack; implemented in mfcuk |
| "OpenHaystack: Tracking via Apple Find My" | https://www.usenix.org/conference/usenixsecurity21/presentation/heinrich | Heinrich et al. | 2021 | BLE | USENIX Security | FindMy emulation framework; Flipper FindMy basis |
| "nRootTag: Arbitrary AirTag Emulation" | https://www.usenix.org/conference/usenixsecurity25/presentation/nroottag | SEEMOO Lab | 2025 | BLE | USENIX Security | FindMy arbitrary device; ble_findmy_emulate Spec |
| "FM11RF08S: MIFARE Classic Hardware Backdoors" | https://eprint.iacr.org/2024/1275 | Quarkslab | 2024 | NFC/RFID | IACR ePrint | Hardware backdoor in FM11RF08/FM11RF08S chips |
| "Unsaflok: Millions of Hotel Rooms Unlocked" | https://unsaflok.com | Wouters et al. | 2024 | NFC | Disclosure | Saflok MFC hotel lock; SaFlip FAP basis |
| "SSID Confusion Attack" | https://papers.mathyvanhoef.com/ssidconfusion2024.pdf | Vanhoef | 2024 | WiFi | ACM CCS | CVE-2023-52160; wifi_ssid_confusion Spec |
| "Security of KeeLoq" | https://www.iacr.org/archive/fse2009/54780257/54780257.pdf | Bard et al. | 2009 | Sub-GHz | FSE | KeeLoq algebraic cryptanalysis |
| "Rolling Back: Time-agnostic RKE Replay" | https://ieeexplore.ieee.org/document/9833787 | Boureanu et al. | 2022 | Sub-GHz | IEEE TIFS | RollBack attack; subghz_rollback_detect basis |
| "iCLASS Legacy Contactless Security" | https://www.cs.ru.nl/~rverdult/Ciphertext-Only_Cryptanalysis_on_Hardened_Mifare_Classic_Cards-CCS_2015.pdf | Verdult et al. | 2015 | NFC/RFID | ACM CCS | Loclass algorithm; Flipper Picopass basis |
| "BadUSB: On Accessories That Turn Evil" | https://www.blackhat.com/us-14/briefings.html | Nohl & Lell | 2014 | USB | Black Hat | Original BadUSB paper; Flipper BadUSB foundation |
| "Drone Remote ID Security Analysis" | https://www.usenix.org/conference/usenixsecurity23/presentation/remoteid | Researchers | 2023 | Sub-GHz | USENIX Security | DroneID spoofing; droneid_receive Spec basis |
| "A SoK on RKE System Attacks" | https://ieeexplore.ieee.org/document/10179396 | Püllen et al. | 2023 | Sub-GHz | IEEE TIFS | Systematic RKE attack survey |
| "Stealtooth: Silent BLE Pairing Exploitation" | https://arxiv.org/abs/2408.01234 | SEEMOO Lab | 2024 | BLE | arXiv | BLE automatic pairing abuse |
| "BLUFFS: BLE Session Key Secrecy Bypass" | https://www.usenix.org/conference/usenixsecurity24/presentation/bluffs | Researchers | 2023 | BLE | USENIX Security | CVE-2023-24023; Bluetooth BLUFFS |
| "A Thorough Security Analysis of BLE Location Tracking" | https://arxiv.org/abs/2305.05004 | SEEMOO Lab | 2023 | BLE | arXiv | BLE proximity tracking analysis |
| "Practical Attacks on Proximity ID Systems" | https://link.springer.com/chapter/10.1007/978-3-540-85886-7_11 | Kasper et al. | 2008 | RFID | CHES | HID Prox physical attack analysis |
| "Picopass: Compromising iClass" | https://github.com/holiman/loclass/blob/master/docs | holiman | 2013 | NFC/RFID | GitHub | Loclass open-source key recovery; Flipper Picopass FAP |
| "RollJam: Rolling Code Attack" | https://www.blackhat.com/us-15/briefings/samy-kamkar.html | Samy Kamkar | 2015 | Sub-GHz | Black Hat | Rolling code replay attack; Sub-GHz RKE basis |

## See Also

- [DEF CON / Black Hat / CCC / USENIX Talks](conferences.md)
- [Relevant CVE Index](cves.md)
- [Vendor Security Advisories](advisories.md)
