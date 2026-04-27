---
type: reference
category: tool
subcategory: mobile
created: 2026-04-27
snapshot: 2026-04-27
---

# Mobile Companion Apps (Android / iOS)

Mobile companion apps extend Flipper Zero functionality to smartphones, enabling wireless firmware updates, file management over BLE, NFC/RFID tag generation, and real-time serial consoles without a desktop PC. This catalog covers the official Android and iOS apps from `flipperdevices`, third-party community apps, related NFC/BLE utilities that produce Flipper-compatible files, and progressive web apps (PWAs) that work on mobile browsers. Entries note whether each app is open-source and whether it is still actively maintained as of the snapshot date.

## Legend

| Column | Values |
|--------|--------|
| Stars | `~Xk` (approximate GitHub stars) or `N/A` for closed-source/store apps |
| Last Commit | `YYYY-MM` (GitHub) or store last-updated month |
| Status | `active` = maintained; `stale` = no update in 12–24 months; `archived` = abandoned |

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| Flipper Android App (official) | https://github.com/flipperdevices/Flipper-Android-App | flipperdevices | ~2k | 2026-04 | GPL-3.0 | active | Official Android app: update, archive, BLE remote |
| Flipper iOS App (official) | https://github.com/flipperdevices/Flipper-iOS-App | flipperdevices | ~1k | 2026-04 | GPL-3.0 | active | Official iOS companion app |
| Flipper Maker (PWA) | https://flippermaker.github.io | flipper-maker | N/A | 2025-12 | MIT | active | Browser PWA for NFC/Sub-GHz/RFID file generation |
| NFC Tools (Android) | https://play.google.com/store/apps/details?id=com.wakdev.wdnfc | Wak Dev | N/A | 2026-03 | proprietary | active | NFC tag reader/writer; Flipper .nfc-compatible export |
| MifareClassicTool (Android) | https://github.com/ikarus23/MifareClassicTool | ikarus23 | ~5k | 2025-12 | GPL-3.0 | active | Android MIFARE reader; key files cross-compatible |
| TagInfo by NXP | https://play.google.com/store/apps/details?id=com.nxp.taginfolite | NXP | N/A | 2026-03 | proprietary | active | NFC tag analysis; cross-reference for Flipper dumps |
| nRF Connect (Android) | https://github.com/NordicSemiconductor/Android-nRF-Connect | NordicSemiconductor | ~500 | 2026-03 | BSD-3-Clause | active | BLE GATT explorer; Flipper BLE debugging |
| WiFi Analyzer (Android) | https://github.com/VREMSoftwareDevelopment/WiFiAnalyzer | VREM | ~3k | 2025-12 | GPL-3.0 | active | 802.11 analysis; complements Flipper WiFi DevBoard |
| Serial USB Terminal (Android) | https://play.google.com/store/apps/details?id=de.kai_morich.serial_usb_terminal | kai_morich | N/A | 2026-04 | proprietary | active | USB serial terminal for Android Flipper CLI |
| USB Serial Console | https://play.google.com/store/apps/details?id=jp.sugnakys.usbserialconsole | sugnakys | N/A | 2025-10 | Apache-2.0 | active | Android USB serial console for Flipper |
| Authenticator Pro (2FA) | https://github.com/jamie-mh/AuthenticatorPro | jamie-mh | ~5k | 2026-03 | GPL-3.0 | active | 2FA app; TOTP compatible with Flipper TOTP FAP |
| Aerlink BLE remote (iOS) | https://github.com/ECTO-1A/Aerlink-for-Flipper | ECTO-1A | ~200 | 2024-07 | MIT | stale | BLE remote control iOS app for Flipper |
| FlipperZero-BLE-keyboard | https://github.com/jplexer/FlipperBLE | jplexer | ~300 | 2024-09 | MIT | stale | iOS/macOS BLE keyboard emulator companion |
| flipper-gpt (ChatGPT) | https://github.com/0xJustin/flipper-gpt | 0xJustin | ~300 | 2024-06 | MIT | stale | ChatGPT wrapper for Flipper payload generation |
| Proxmark3 Android client | https://github.com/RfidResearchGroup/proxmark3/tree/master/client/android | RfidResearchGroup | N/A | 2025-08 | GPL-3.0 | stale | Proxmark3 Android; NFC keys exportable to Flipper |
| RFID Tools companion | https://github.com/AdeelK93/FlipperZero-RFID | AdeelK93 | ~200 | 2024-05 | MIT | stale | Android RFID companion for Flipper file generation |
| BLE Scanner (Android) | https://play.google.com/store/apps/details?id=com.macdom.ble.blescanner | Bluepixel | N/A | 2026-02 | proprietary | active | BLE advertisement scanner; FindMy/spam analysis |
| ClemensElflein community Android | https://github.com/ClemensElflein/flipperzero-android | ClemensElflein | ~200 | 2024-05 | MIT | stale | Community Android app with archive management |
| Flipper Zero Hub (Android) | https://play.google.com/store/apps/details?id=io.flipperhub | FlipperHub | N/A | 2025-10 | proprietary | stale | Third-party file manager + firmware downloader |
| iOS Shortcut file transfer | https://www.icloud.com/shortcuts/flipper | community | N/A | 2024-08 | MIT | stale | iOS Shortcut to transfer files via BLE |

## See also

- [Desktop Tools & CLI Utilities](desktop.md) — desktop GUI and CLI tools for USB-connected workflows
- [Web-Based Tools & Online Decoders](web.md) — browser tools usable on mobile as PWAs
- [Forums, Discord Servers & Subreddits](../community/forums.md) — community support channels for mobile app issues
