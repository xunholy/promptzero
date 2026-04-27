---
type: reference
category: payload
subcategory: subghz
created: 2026-04-27
snapshot: 2026-04-27
---

# Sub-GHz Capture Repos & Signal Databases

Community and official Sub-GHz signal databases, capture repositories, bruteforcers, and protocol decoder libraries for the Flipper Zero CC1101 transceiver. The CC1101 supports 300–928 MHz OOK/FSK transmissions and is capable of replaying garage doors, weather sensors, remote controls, and custom RF devices. Entries span raw `.sub` capture packs, firmware-bundled signal libraries, host-side analysis tools, and web-based file generators.

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
| UberGuidoZ/Flipper | https://github.com/UberGuidoZ/Flipper | UberGuidoZ | ~15k | 2026-04 | MIT | active | Largest community payload collection; Sub-GHz captures, IR, NFC |
| unleashed-extra-pack | https://github.com/xMasterX/unleashed-extra-pack | xMasterX | ~3k | 2026-03 | MIT | active | Extra Sub-GHz remotes, NFC, iButton files |
| SubGHz Bruteforce FAP | https://github.com/derskythe/flipperzero-subghz-bruteforcer | derskythe | ~2k | 2025-08 | GPL-3.0 | active | All-in-one Sub-GHz code bruteforcer |
| flipperzero-touchtunes | https://github.com/jimilinuxguy/flipperzero-touchtunes | jimilinuxguy | ~3k | 2024-01 | MIT | stale | TouchTunes jukebox Sub-GHz remote captures (433 MHz OOK) |
| flipper-playlist | https://github.com/darmiel/flipper-playlist | darmiel | ~600 | 2024-06 | MIT | stale | Sub-GHz replay playlist utility + sample captures |
| RogueMaster TouchTunes | https://github.com/RogueMaster/FlipperZero-TouchTunes | RogueMaster | ~400 | 2023-08 | MIT | stale | Additional TouchTunes captures for RM firmware |
| flipperzero_signalfiles | https://github.com/mcules/flipperzero_signalfiles | mcules | ~800 | 2024-02 | MIT | stale | Community Sub-GHz .sub files (garage doors, weather) |
| unitemp-flipperzero | https://github.com/quen0n/unitemp-flipperzero | quen0n | ~500 | 2025-10 | GPL-3.0 | active | 433 MHz weather sensor (thermometers, hygrometers) |
| flipperzero-geigercounter | https://github.com/nmrr/flipperzero-geigercounter | nmrr | ~300 | 2024-08 | GPL-3.0 | stale | Geiger counter Sub-GHz pulse reader |
| OFW Sub-GHz app | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/subghz | flipperdevices | ~16k | 2025-12 | GPL-3.0 | active | Official Sub-GHz app; built-in remote library |
| Unleashed Sub-GHz | https://github.com/DarkFlippers/unleashed-firmware | DarkFlippers | ~22k | 2026-04 | GPL-3.0 | active | Extended frequency ranges + extra decoders |
| mRF-labs RKE captures | https://github.com/mRF-labs/flipper-zero-subghz | mRF-labs | ~200 | 2024-07 | MIT | stale | Automotive RKE captures (433/315 MHz) |
| fzeetools subghz | https://github.com/fzeetools/subghz-signals | fzeetools | ~150 | 2024-05 | MIT | stale | Residential gate/garage captures |
| portapack-mayhem captures | https://github.com/portapack-mayhem/mayhem-firmware/tree/next/sdcard/CAPTURES | portapack-mayhem | ~4k | 2026-04 | GPL-2.0 | active | HackRF PortaPack capture library |
| CARS RHKS SNAP | https://github.com/ai-carpro/flipper-rhks-snap | ai-carpro | ~100 | 2024-11 | MIT | stale | Honda/Nissan key-fob .sub captures |
| weatherstation-signals | https://github.com/klaufer/flipper-weatherstation | klaufer | ~80 | 2024-03 | MIT | stale | Acurite/Oregon weather station Sub-GHz frames |
| flipper-maker subghz pack | https://github.com/flipper-maker/subghz-pack | flipper-maker | ~400 | 2025-02 | MIT | stale | Mixed Sub-GHz household device captures |
| Momentum POCSAG | https://github.com/Next-Flip/Momentum-Apps/tree/dev/pocsag | Next-Flip | N/A | 2026-04 | GPL-3.0 | active | POCSAG pager decode FAP + sample captures |
| SubGHz chat | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/subghz | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Point-to-point text chat over Sub-GHz |
| KeeLoq/StarLine support | https://github.com/DarkFlippers/unleashed-firmware/tree/dev/applications/main/subghz | DarkFlippers | N/A | 2026-04 | GPL-3.0 | active | KeeLoq/StarLine rolling-code protocol + captures |
| Frequency Analyzer FAP | https://github.com/flipperdevices/flipperzero-firmware/tree/dev/applications/main/frequency_analyzer | flipperdevices | N/A | 2025-12 | GPL-3.0 | active | Live Sub-GHz spectrum analyzer |
| wetox-team firmware | https://github.com/wetox-team/flipperzero-firmware | wetox-team | ~800 | 2022-04 | GPL-3.0 | stale | First custom firmware; ships early Sub-GHz captures |
| sub-analyzer.py | https://github.com/jamisonderek/flipper-zero-tutorials/blob/main/subghz | jamisonderek | ~2k | 2026-03 | MIT | active | Python .sub file parser + visualization |
| pcap2sub | https://github.com/nicholasgasior/pcap2sub | nicholasgasior | ~60 | 2024-05 | MIT | stale | PCAP Sub-GHz frame → Flipper .sub converter |
| flipper-maker SubGHz builder | https://flippermaker.github.io | flipper-maker | N/A | 2025-12 | MIT | active | Web-based Sub-GHz .sub file generator |

## See also

- [NFC Dump Databases](./nfc.md) — MIFARE key corpora and NFC dump collections
- [RFID Dump Databases](./rfid.md) — LF/HF RFID captures and Wiegand key databases
- [BLE Advertisement / GATT Payload Repos](./bluetooth.md) — BLE spam and FindMy emulation
