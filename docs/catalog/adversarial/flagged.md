---
type: reference
category: adversarial
subcategory: flagged
created: 2026-04-27
snapshot: 2026-04-27
---

# Adversarial / Flagged Projects

> **⚠️ WARNING: This file is for defensive awareness only.**
> URLs are withheld for projects with mass-harm potential, active malware distribution, or per vendor request.
> This catalog exists to help defenders, incident responders, and community moderators identify malicious tooling.
> See [README.md](README.md) for the full ethics and URL-withholding policy.
> **Do not attempt to locate or use withheld tools. Possession or use without authorization may be illegal.**

## Legend

- **Name** — project name or alias as it circulates in the community
- **Category** — harm category code(s) from [README.md](README.md)
- **URL / Status** — safe URL if disclosed; otherwise withheld with reason
- **Why Flagged** — description of the harm vector and evidence basis

## Entries

| Name | Category | URL / Status | Why Flagged |
|------|----------|-------------|-------------|
| Private-Unleashed 2.0 | A1, A12 | URL withheld — mass-harm (vehicle theft) | Paywalled dark-web firmware with rolling-code removal; sold for vehicle theft |
| "PremiumFlipper Pro" | A1 | URL withheld — active scam | Telegram brand selling repackaged official firmware as premium CFW |
| Backdoored "all-plugins v2" | A2 | URL withheld — active malware | Fake all-the-plugins release with persistent reverse shell via BadUSB FAP |
| Flipper Cracked Tools | A9 | URL withheld — piracy | Cracked Proxmark3 Iceman commercial add-on as free Flipper pack |
| "Underground Signal Pack 2024" | A3 | URL withheld — fraud | Telegram pack sold ~$50; contains only free UberGuidoZ signals repackaged |
| "Flipper Dark Pack" | A3 | URL withheld — fraud | Dark-web brand selling free community files as premium |
| Credential-harvesting BadUSB pack | A4 | URL withheld — active malware | Corporate-targeting BadUSB payloads not disclosed to defenders |
| Evil Portal mass-deployment phish kit | A5 | URL withheld — phishing | Flipper WiFi DevBoard Evil Portal impersonating banks/ISPs at scale |
| "Flipper.net" phishing site | A5 | URL withheld — fraud | Domain impersonating official Flipper Zero store |
| BLE crash spam (infrastructure) | A6 | URL withheld — mass-harm | BLE spam tuned to crash emergency-service BLE radios |
| WiFi Deauth-as-a-service build | A7 | URL withheld — harassment | Marauder fork as permanent WiFi jammer marketed for residential harassment |
| FindMy stalker beacon | A8 | URL withheld — stalking | FindMy FAP modified to suppress on-device display for covert tracking |
| "Stalkerware Zero" | A8 | URL withheld — stalking | Firmware fork with FindMy emulation + BLE RSSI triangulation marketed as stalkerware |
| EMV-Replay-Zero | A11 | URL withheld — fraud | Flipper FAP for contactless EMV payment replay |
| NFC PayPass cloner | A11 | URL withheld — fraud | App to clone contactless payment cards for fraudulent transactions |
| IMSI-catcher FAP | A10 | URL withheld — illegal interception | Flipper + ESP32 cellular IMSI catcher |
| Vehicle keyfob emulator (VKE-Tool) | A12 | URL withheld — mass-harm | Tool specifically framed for high-value vehicle key cloning |

## Research-Safe References

The following projects are publicly disclosed, patched or mitigated in target platforms, or represent responsible academic disclosures. URLs are provided for defensive research purposes.

| Name | Category | URL | Notes |
|------|----------|-----|-------|
| Xtreme BLE spam (archived) | A6 | https://github.com/Flipper-XFW/Xtreme-Firmware/tree/dev/applications/external/ble_spam | iOS crash patched in 17.2; archived PoC reference |
| AppleJuice (ECTO-1A) | A6 | https://github.com/ECTO-1A/AppleJuice | Public PoC; iOS 17.2 patched; research disclosure |
| Stealtooth PoC | A8 | https://github.com/seemoo-lab/stealtooth | Academic PoC by SEEMOO Lab; responsible disclosure |
| RollJam research | A12 | https://github.com/samyk/rolljam | Samy Kamkar academic PoC; widely cited |
| MagSpoof | A12 | https://github.com/samyk/magspoof | Samy Kamkar magnetic stripe PoC; academic |

## See Also

- [Ethics & Policy](README.md)
- [Academic Papers by Protocol Family](../research/papers.md)
- [DEF CON / Black Hat / CCC / USENIX Talks](../research/conferences.md)
