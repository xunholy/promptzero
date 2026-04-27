---
name: Awesome Flipper Zero — ecosystem project index
description: Flat, diffable index of every Flipper-Zero-adjacent project on GitHub and the open web — one row per repo. Snapshot 2026-04-27 (fourth-pass discovery — long-tail FAPs, jammers, ESL/UHF/LoRa/Modbus/CAN extensions, defensive auditors, RollJam single-chip PoC, ESP32-port firmware, AIAgent siblings).
type: reference
created: 2026-04-26T00:00
updated: 2026-04-27T00:00
tags: [catalog, flipper, ecosystem, market-analysis, threat-intel]
related: [[catalog/README]] [[catalog/firmware]] [[catalog/apps]] [[catalog/attacks]] [[catalog/hardware]] [[catalog/gap-analysis]]
---

# Awesome Flipper Zero — ecosystem project index

A **flat, sortable index** of every Flipper-Zero-adjacent project (firmwares, bundles, host tools, libraries, mobile apps, attack PoCs, adjacent hardware, awesome lists, wikis, AI agents, defensive tools, academic research) discovered as of **2026-04-27**. A second discovery pass added long-tail legitimate entries (rows 171–268) plus an **Adversarial / ethically-flagged appendix** (separate table, URLs withheld for malware/scam/cracked categories per the catalog policy on `Private-Unleashed 2.0`). A third pass deepened offensive-capability coverage (rows 269–344). A fourth pass on 2026-04-27 swept GitHub topic surfaces, the prolific-author user pages, and the SubGHz/NFC capability searches — adding rows 393–451 (long-tail FAPs, jammers, ESL/UHF/LoRa/Modbus/CAN extensions, defensive auditors, the RollJam single-chip PoC, ESP32-port and Moon firmwares, and three new AIAgent siblings).

Companion to — not a replacement for — the deep capability catalog under [`docs/catalog/`](./catalog/). The catalog answers *"what does this ecosystem do, by protocol and primitive?"*; this index answers *"what repos exist, what's new, and which ones are hostile?"*.

## How to use

- **Discover gaps:** filter by `In PZ?` column — anything `Gap` is a candidate Spec or transport.
- **Detect new entrants:** re-run the discovery procedure (§"Refresh procedure" below) and `diff` the row set; any new repo not present here is fresh ecosystem activity worth investigating.
- **License check before porting:** PromptZero is **AGPL-3.0-or-later**. GPL-3.0, GPL-2.0, MIT, BSD, Apache-2.0 are inbound-compatible (with attribution). `(none)` / `NOASSERTION` / unspecified means *do not vendor without contacting the author* — only study the design.
- **Threat-intel use:** the appendix below is an explicit "do not federate / do not vendor" list. Drives the firmware-allowlist and payload-blocklist Specs in PromptZero.

## Legend

- **Category** — `CFW` Custom Firmware · `Bundle` App/plugin/asset bundle · `AwesomeList` Curated index · `Wiki` Knowledge base · `Official` flipperdevices first-party · `CLI` Host CLI/REPL · `WebSerial` Browser tool · `SDK` Build/dev tooling · `Library` Host parser/decoder/lib · `Mobile` Phone app · `AttackPoC` External attack/research repo · `AdjacentHW` Non-Flipper hardware tool often paired · `AIAgent` LLM-driven Flipper driver · `Defensive` Detection/protection against FZ misuse · `Research` Academic / paper / conference companion
- **Lang** — primary language. `(mix)` for repos that are mostly assets/payloads/scripts.
- **~Stars** — best-effort, snapshot date. `~Nk` for ≥1000.
- **Last** — last commit OR latest release, whichever is more recent.
- **Status** — `Active` (≤6 mo) · `Stale` (6–24 mo) · `Archived` (≥2 yr or repo-archived) · `Adversarial` (flagged untrustworthy).
- **In PZ?** — coverage in PromptZero's `internal/tools/` registry: `Yes` covered today · `Partial` partial/variant exists · `Gap` candidate for new Spec · `N/A` not a capability target (asset pack, wiki, etc.) · `Compete` direct competitor surface · `Refuse` should be explicitly refused / blocklisted.

## Master index

| # | Project | Repo | Author | Category | Lang | ~Stars | Last | License | Status | Capability | In PZ? |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Unleashed | https://github.com/DarkFlippers/unleashed-firmware | DarkFlippers | CFW | C | ~22k | 2026-04-25 | GPL-3.0 | Active | Sub-GHz unlock; expanded NFC/iButton/BadUSB; dynamic KeeLoq/StarLine/Faac SLH | N/A |
| 2 | Official | https://github.com/flipperdevices/flipperzero-firmware | flipperdevices | CFW | C | ~16k | 2025-12-05 | GPL-3.0 | Active | Stock firmware; region-locked Sub-GHz; lab.flipper.net catalog | N/A |
| 3 | Xtreme | https://github.com/Flipper-XFW/Xtreme-Firmware | Flipper-XFW | CFW | C | ~10k | 2024-11-19 | GPL-3.0 | Archived | Custom UI/asset packs; **BLE Spam origin** (incl. iOS-17 crash variant — see appendix); broad protocol unlock | N/A |
| 4 | Momentum | https://github.com/Next-Flip/Momentum-Firmware | Next-Flip | CFW | C | ~8k | 2026-04-19 | GPL-3.0 | Active | Successor to Xtreme; ~Unleashed parity + UI extras | N/A |
| 5 | RogueMaster | https://github.com/RogueMaster/flipperzero-firmware-wPlugins | RogueMaster | CFW | C | ~6k | 2026-04-26 | GPL-3.0 | Active | Unleashed base + bleeding-edge plugins, experimental games | N/A |
| 6 | Xtreme (clean fork) | https://github.com/ClaraCrazy/Flipper-Xtreme | ClaraCrazy | CFW | C | ~200 | 2024 | GPL-3.0 | Stale | Cleaned Xtreme codebase; mirror | N/A |
| 7 | Xvirus | https://github.com/Xvirus-Team/xvirus-firmware | Xvirus-Team | CFW | C | <100 | 2025 | GPL-3.0 | Stale | Unleashed fork; custom theme + extended freq | N/A |
| 8 | SquachWare | https://github.com/skizzophrenic/SquachWare-CFW | skizzophrenic | CFW | C | <500 | 2023 | GPL-3.0 | Archived | OFW-derived; built-in name changer + community apps | N/A |
| 9 | Wetox | https://github.com/wetox-team/flipperzero-firmware | wetox-team | CFW | C | <200 | 2023 | GPL-3.0 | Stale | Near-OFW; T5577 RFID password cracking PoC | N/A |
| 10 | MuddledBox | https://github.com/MuddledBox/flipperzero-firmware | MuddledBox | CFW | C | <500 | 2023 | GPL-3.0 | Archived | First popular CFW; Mouse Jiggler; early NFC tweaks | N/A |
| 11 | v1nc | https://github.com/v1nc/flipperzero-firmware | v1nc | CFW | C | <300 | 2024 | GPL-3.0 | Stale | Unleashed fork; multi-keyboard-layout DuckyScript | N/A |
| 12 | AlexStrNik (AirTag PoC) | https://github.com/AlexStrNik/flipperzero-firmware | AlexStrNik | CFW | C | <100 | 2022 | GPL-3.0 | Archived | Early Apple AirTag broadcast PoC | N/A |
| 13 | DXVVAY | https://github.com/DXVVAY/Dexvmaster0 | DXVVAY | CFW | C | <100 | 2024 | GPL-3.0 | Stale | Xtreme fork; experimental mods | N/A |
| 14 | Kiisu firmware | https://github.com/kiisu-io/kiisu-firmware | kiisu-io | CFW | C | ~100 | 2026-04-09 | GPL-3.0 | Active | OFW fork for Kiisu (FZ-compatible Lab401 board) | N/A |
| 15 | enhanced-kiisu4-fw | https://github.com/twoelw/enhanced-kiisu4-fw | twoelw | CFW | C | <50 | 2026 | GPL-3.0 | Active | Kiisu V4 community enhancements | N/A |
| 16 | FlipperZero-CN | https://github.com/ZhaiRenGaiZaoJia/FlipperZero-CN-Firmware | ZhaiRenGaiZaoJia | CFW | C | ~150 | 2024-08-06 | GPL-3.0 | Stale | Chinese-language firmware | N/A |
| 17 | RedFlipper | https://github.com/Red-Flipper/RedFlipper | Red-Flipper | CFW | C | <10 | 2024-02-18 | GPL-3.0 | Stale | Red-team-focused build | N/A |
| 18 | Haisenteck-Flipper-MOD | https://github.com/haisenteck/Haisenteck-Flipper-MOD | haisenteck | CFW | C | <20 | 2023-11 | GPL-3.0 | Stale | Custom firmware tweaks | N/A |
| 19 | FlipperEugene | https://github.com/FlipperEugene/Flipper-Zero-Eugene-Firmware | FlipperEugene | CFW | C | <10 | 2023-02-22 | GPL-3.0 | Archived | Customised Unleashed variant; vanity build | N/A |
| 20 | no-region-lock | https://github.com/xSevithx/flipperzero-firmware-no-region-lock | xSevithx | CFW | C | <50 | 2023 | GPL-3.0 | Stale | Single-purpose patch removing region lock | N/A |
| 21 | RGB backlight mod | https://github.com/quen0n/flipperzero-firmware-rgb | quen0n | CFW | C | ~70 | 2025-12-06 | GPL-3.0 | Stale | FW patches for RGB backlight HW mod | N/A |
| 22 | Code-Grabber fork | https://github.com/theY4Kman/flipperzero-firmware | theY4Kman | CFW | C | <100 | 2023 | GPL-3.0 | Stale | Sub-GHz code-grabber experimental fork | N/A |
| 23 | WiFi-Marauder companion FW | https://github.com/tcpassos/flipperzero-firmware-with-wifi-marauder-companion | tcpassos | CFW | C | ~30 | 2025-07-16 | GPL-3.0 | Stale | OFW + Marauder companion app baked in | N/A |
| 24 | GMMan personal fork | https://github.com/GMMan/flipperzero-firmware | GMMan | CFW | C | ~35 | 2025-03-31 | GPL-3.0 | Stale | NFC research; frequently-cited dev fork | N/A |
| 25 | Private-Unleashed 2.0 | *URL withheld — see appendix* | KommerZDealer | CFW | C | low | 2026 | unclear | Adversarial | Scam impersonator, publicly disavowed by Unleashed/Flipper teams; rebadged 10-yr-old vulns sold $600–$2000 | Refuse |
| 26 | flipperzero-good-faps | https://github.com/flipperdevices/flipperzero-good-faps | flipperdevices | Bundle | C | ~600 | 2026 | MIT | Active | Official curated FAP source set (NFC magic, Sub-GHz analyser, etc.) | Partial |
| 27 | Momentum-Apps | https://github.com/Next-Flip/Momentum-Apps | Next-Flip | Bundle | C | ~600 | 2026 | varies | Active | ~245 external apps tweaked for Momentum (NFC, GPIO, weather, Telegram, WiFi, hex editor) | Partial |
| 28 | Asset-Packs | https://github.com/Next-Flip/Asset-Packs | Next-Flip | Bundle | (mix) | small | 2026 | varies | Active | UI/animation companion to Momentum-Apps | N/A |
| 29 | all-the-plugins | https://github.com/xMasterX/all-the-plugins | xMasterX | Bundle | C | ~1.5k | 2026-04-25 | GPL-3.0 | Active | De-facto Unleashed plugin pack (`apps_source_code`, `base_pack`, `non_catalog_apps`) | Partial |
| 30 | UberGuidoZ/Flipper | https://github.com/UberGuidoZ/Flipper | UberGuidoZ | Bundle | (mix) | ~17k | 2026 | GPL-3.0 | Active | Mega "playground" of dumps, IR, NFC, RFID, Sub-GHz, GPIO, music, graphics + docs | N/A |
| 31 | Flipper-IRDB | https://github.com/logickworkshop/Flipper-IRDB | logickworkshop | Bundle | (mix) | ~2k | 2026 | unspecified | Active | Canonical IR remote dump database | Yes (`ir_*`) consumes |
| 32 | flipperzero-bruteforce | https://github.com/tobiabocchi/flipperzero-bruteforce | tobiabocchi | Bundle | Python | ~2.4k | 2024-07-12 | MIT | Stale | Sub-GHz fixed-code bruteforce `.sub` generator + presets | Gap (`subghz_fixed_brute_gen`) |
| 33 | FlipperAmiibo | https://github.com/Gioman101/FlipperAmiibo | Gioman101 | Bundle | (mix) | ~1k | 2026 | unspecified | Active | Amiibo NFC dumps converted for FZ | N/A — IP-disputed |
| 34 | FroggMaster/FlipperZero | https://github.com/FroggMaster/FlipperZero | FroggMaster | Bundle | (mix) | ~700 | 2026 | unspecified | Active | Mixed scripts/apps/dumps collection | N/A |
| 35 | I-Am-Jakoby/Flipper-Zero-BadUSB | https://github.com/I-Am-Jakoby/Flipper-Zero-BadUSB | I-Am-Jakoby | Bundle | PowerShell | ~6.8k | 2024-06-15 | unspecified | Stale | Most-starred Flipper-tuned BadUSB pack | N/A — payloads (training data) |
| 36 | flipper-zero-bad-usb (SeenKid) | https://github.com/SeenKid/flipper-zero-bad-usb | SeenKid | Bundle | PowerShell | ~600 | 2025-04-15 | MIT | Stale | BadUSB script collection | N/A |
| 37 | my-flipper-shits | https://github.com/aleff-github/my-flipper-shits | aleff-github | Bundle | HTML | ~1.7k | 2026-03-17 | GPL-3.0 | Active | Free/libre BadUSB payloads (Win/Linux/iOS); GPL-clean | N/A — payloads |
| 38 | FalsePhilosopher/badusb | https://github.com/FalsePhilosopher/badusb | FalsePhilosopher | Bundle | PowerShell | ~1.9k | 2026-04-01 | NOASSERTION | Active | Active community BadUSB corpus | N/A |
| 39 | bst04/payloads_flipperZero | https://github.com/bst04/payloads_flipperZero | bst04 | Bundle | (mix) | ~375 | 2026-03-16 | GPL-3.0 | Active | DuckyScript 1.0 payload set | N/A |
| 40 | narstybits/MacOS-DuckyScripts | https://github.com/narstybits/MacOS-DuckyScripts | narstybits | Bundle | (mix) | ~486 | 2024-06-22 | unspecified | Stale | macOS-targeted DuckyScript set | N/A |
| 41 | SHUR1K-N/Flipper-Zero-BadKB-Files | https://github.com/SHUR1K-N/Flipper-Zero-BadKB-Files | SHUR1K-N | Bundle | (mix) | ~635 | 2024-08-30 | unspecified | Stale | BadKB (BLE keyboard) payloads | Gap (BadKB Spec class) |
| 42 | MarkCyber/BadUSB | https://github.com/MarkCyber/BadUSB | MarkCyber | Bundle | PowerShell | small | 2026 | unspecified | Active | Ethical-hacking BadUSB pack incl. vuln scanner | N/A |
| 43 | flipper-zero-tonies | https://github.com/nortakales/flipper-zero-tonies | nortakales | Bundle | (mix) | small | 2026 | unspecified | Active | Toniebox NFC database | N/A |
| 44 | flipperzero-touchtunes | https://github.com/jimilinuxguy/flipperzero-touchtunes | jimilinuxguy | Bundle | (mix) | small | 2026 | unspecified | Active | TouchTunes Sub-GHz captures | N/A — dumps |
| 45 | FlipperHub | https://github.com/salscodess/FlipperHub | salscodess | Bundle | (mix) | ~16 | 2025-03-31 | unspecified | Stale | 200+ curated link aggregator (presets, firmware, animations) | N/A |
| 46 | Mrmatiiii/FlipperZero | https://github.com/Mrmatiiii/FlipperZero | Mrmatiiii | Bundle | (mix) | small | 2026 | unspecified | Stale | "Maybe complete" FZ file database | N/A |
| 47 | ADolbyB/flipper-zero-files | https://github.com/ADolbyB/flipper-zero-files | ADolbyB | Bundle | (mix) | small | 2026 | unspecified | Active | Misc files collection | N/A |
| 48 | Flipper-Zero-Camera-Suite | https://github.com/CodyTolene/Flipper-Zero-Camera-Suite | CodyTolene | Bundle | C | ~150 | 2025-05-16 | MIT | Stale | Firmware + apps for ESP32-CAM module | Gap (camera Spec) |
| 49 | awesome-flipperzero | https://github.com/djsime1/awesome-flipperzero | djsime1 | AwesomeList | (mix) | ~23k | 2024-09-27 | CC0/unspecified | Stale | Canonical FZ awesome list | N/A — discovery source |
| 50 | awesome-flipperzero-withModules | https://github.com/RogueMaster/awesome-flipperzero-withModules | RogueMaster | AwesomeList | (mix) | ~1.9k | 2026-04-22 | unspecified | Active | djsime1 shape + modules + RogueMaster-specific; **most up-to-date awesome list** | N/A — discovery source |
| 51 | awesome-flipperzero-collection | https://github.com/FlipperZX/awesome-flipperzero-collection | FlipperZX | AwesomeList | (mix) | small | 2025 | unspecified | Stale | Mirror of djsime1 | N/A |
| 52 | flipper-zero-awesome (123fzero) | https://github.com/123fzero/flipper-zero-awesome | 123fzero | AwesomeList | (mix) | ~10 | 2025 | unspecified | Active | Curated FZ app catalog | N/A |
| 53 | merlinepedra/awesome-flipperzero | https://github.com/merlinepedra/awesome-flipperzero | merlinepedra | AwesomeList | (mix) | small | unknown | unspecified | Stale | Mirror of djsime1 | N/A |
| 54 | Flipper-Zero-Off-The-Deep_End | https://github.com/Lo-Z/Flipper-Zero-Off-The-Deep_End | Lo-Z | AwesomeList | (mix) | small | 2025-11-16 | unspecified | Active | Resource compilation on FZ tech | N/A |
| 55 | jamisonderek tutorials | https://github.com/jamisonderek/flipper-zero-tutorials | jamisonderek | Wiki | (mix) | ~2k | 2026 | unspecified | Active | Wiki + tutorial repo (apps, dev guide, NFC magic, **VGE engine docs**) | N/A |
| 56 | flipper-community-wiki | https://github.com/Flipper-Community/flipper-community-wiki | Flipper-Community | Wiki | (mix) | small | 2026 | likely CC-BY-SA | Active | Source for flipper.wiki — community KB | N/A |
| 57 | Momentum Wiki | https://github.com/Next-Flip/Momentum-Firmware/wiki | Next-Flip | Wiki | (mix) | n/a | 2026 | n/a | Active | Authoritative Momentum docs | N/A |
| 58 | flipper.wiki (rendered) | https://flipper.wiki/ | Flipper-Community | Wiki | n/a | n/a | 2026 | n/a | Active | Rendered community wiki | N/A |
| 59 | momentum-fw.dev/wiki | https://momentum-fw.dev/wiki | Next-Flip | Wiki | n/a | n/a | 2026 | n/a | Active | Rendered Momentum wiki | N/A |
| 60 | awesome-flipper.com | https://awesome-flipper.com/ | community | Wiki | n/a | n/a | 2026 | n/a | Active | Web aggregator inspired by djsime1 | N/A |
| 61 | djsime1 firmware-diff gist | https://gist.github.com/djsime1/edb8f3a0ab77e563898d1c55f489bf96 | djsime1 | Wiki | (mix) | n/a | 2024 | n/a | Stale | Side-by-side CFW feature matrices | N/A |
| 62 | qFlipper | https://github.com/flipperdevices/qFlipper | flipperdevices | Official | C++/Qt | ~1.6k | 2024-06-11 | GPL-3.0 | Stale | Cross-platform desktop: FW updater + file mgr + screen streamer over USB | N/A — RPC reference |
| 63 | Flipper-Android-App | https://github.com/flipperdevices/Flipper-Android-App | flipperdevices | Official | Kotlin | ~2.1k | 2026-04-25 | MIT | Active | Official Android: BLE control, key/file mgmt, alarm, hub | N/A — BLE reference (note issue #877 file-write bug) |
| 64 | Flipper-iOS-App | https://github.com/flipperdevices/Flipper-iOS-App | flipperdevices | Official | Swift | ~917 | 2025-03-04 | MIT | Stale | Official iOS companion (BLE) | N/A — BLE reference |
| 65 | flipperzero-protobuf | https://github.com/flipperdevices/flipperzero-protobuf | flipperdevices | Official | Proto | ~100 | 2025-01-15 | unspecified | Active | Canonical .proto for Flipper RPC | Partial — codegen source |
| 66 | flipperzero_protobuf_py | https://github.com/flipperdevices/flipperzero_protobuf_py | flipperdevices | Official | Python | ~74 | 2024-12-17 | unspecified | Stale | Python protobuf bindings + RPC examples | N/A — reference |
| 67 | flipperzero-protobuf-jvm | https://github.com/flipperdevices/flipperzero-protobuf-jvm | flipperdevices | Official | JVM | ~12 | 2023-11-06 | unspecified | Stale | JVM protobuf bindings | N/A |
| 68 | flipperzero-protobuf-metric | https://github.com/flipperdevices/flipperzero-protobuf-metric | flipperdevices | Official | Proto | ~8 | 2025-01-15 | unspecified | Stale | Telemetry/metric proto schemas | N/A |
| 69 | flipperzero-ufbt | https://github.com/flipperdevices/flipperzero-ufbt | flipperdevices | Official | Python | ~1k | 2026-01-29 | GPL-3.0 | Active | Micro Flipper Build Tool — host-side FAP build/upload | Gap (FAP build orchestration) |
| 70 | flipperzero-ufbt-action | https://github.com/flipperdevices/flipperzero-ufbt-action | flipperdevices | Official | YAML | ~152 | 2024-03-06 | unspecified | Stale | GitHub Action wrapper around ufbt | N/A |
| 71 | flipperzero-toolchain | https://github.com/flipperdevices/flipperzero-toolchain | flipperdevices | Official | Shell | ~134 | 2025-05-27 | GPL-3.0 | Active | Pinned ARM toolchain for FW builds | N/A |
| 72 | flipperzero-nfc-tools | https://github.com/flipperdevices/flipperzero-nfc-tools | flipperdevices | Official | C | ~142 | 2025-01-15 | GPL-3.0 | Active | Host-side NFC dump/format converters | Gap — port to Go |
| 73 | flipper-application-catalog | https://github.com/flipperdevices/flipper-application-catalog | flipperdevices | Official | Python | ~1k | 2026-04-24 | unspecified | Active | Source of lab.flipper.net app catalog | Gap — validation hook |
| 74 | blackmagic-esp32-s2 | https://github.com/flipperdevices/blackmagic-esp32-s2 | flipperdevices | Official | C | ~658 | 2025-09-11 | GPL-3.0 | Stale | ESP32-S2 → Black Magic Probe (JTAG/SWD) | Gap (`swd_dump` workflow) |
| 75 | fztea | https://github.com/jon4hz/fztea | jon4hz | CLI | Go | ~391 | 2026-02-23 | MIT | Active | TUI Flipper remote-control over USB serial / SSH (Bubble Tea) | Compete — strong port target |
| 76 | pyFlipper | https://github.com/wh00hw/pyFlipper | wh00hw | CLI | Python | ~434 | 2025-06-18 | MIT | Active | Wraps every Flipper CLI verb | Compete — exhaustive checklist |
| 77 | flipperzero-cli-tools | https://github.com/lomalkin/flipperzero-cli-tools | lomalkin | CLI | Python | ~96 | 2024-08-19 | unspecified | Stale | Storage push/pull/diff CLI wrappers | N/A |
| 78 | flipper-rpc | https://github.com/elijah629/flipper-rpc | elijah629 | CLI | Rust | ~2 | 2026-03-28 | MIT | Active | Rust async RPC library on official protobufs | N/A — design reference |
| 79 | flipperbridge | https://github.com/perillamint/flipperbridge | perillamint | CLI | Rust | ~6 | 2022-08-25 | unspecified | Archived | Rust transport-layer RPC | N/A |
| 80 | flipperzero_protobuf_rs | https://github.com/GGORG0/flipperzero_protobuf_rs | GGORG0 | CLI | Rust | 0 | 2025-06-21 | unspecified | Stale | Rust protobuf bindings | N/A |
| 81 | flipper-rpc-bridge | https://github.com/FourteenBrush/flipper-rpc-bridge | FourteenBrush | CLI | Odin | 0 | 2026-02-18 | unspecified | Active | Odin-language CLI wrapper | N/A |
| 82 | flipperzero-cli (nledez) | https://github.com/nledez/flipperzero-cli | nledez | CLI | Python | ~9 | 2022-08-09 | GPL-3.0 | Archived | Early Python CLI wrapper | N/A |
| 83 | fzcli | https://github.com/gmelodie/fzcli | gmelodie | CLI | Python | ~2 | 2023-05-24 | MIT | Archived | Lightweight Python CLI | N/A |
| 84 | FlipperCLI | https://github.com/StevenFAU/FlipperCLI | StevenFAU | CLI | Python | ~2 | 2026-03-21 | unspecified | Active | Small Python CLI; active maintenance | N/A |
| 85 | pi-flipper-hid | https://github.com/ivanvza/pi-flipper-hid | ivanvza | CLI | TypeScript | ~3 | 2026-04-18 | unspecified | Active | Pi extension: drives Flipper as USB HID over serial | Gap (`act_keystroke_via_flipper`) |
| 86 | pyQFlipper | https://github.com/Crsarmv7l/pyQFlipper | Crsarmv7l | CLI | Python | ~1 | 2025-09-10 | unspecified | Archived | Serial Python impl of qFlipper file ops | N/A |
| 87 | flipper-CLI-script-gen-eng | https://github.com/Kingdamienjl/flipper-CLI-script-gen-eng | Kingdamienjl | CLI | JS | 0 | 2026-04-03 | GPL-3.0 | Active | LLM-assisted BadUSB script generator | Compete — review prompts |
| 88 | FZ PC-Monitor USB Backend | https://github.com/DonJulve/Flipper-Zero-PC-Monitor-USB-Backend | DonJulve | CLI | Rust | ~17 | 2025-12-16 | MIT | Active | Streams CPU/RAM/GPU stats to Flipper screen via CDC | N/A — pattern |
| 89 | pineflip | https://github.com/bad-antics/pineflip | bad-antics | CLI | Rust | ~4 | 2026-03-05 | unspecified | Active | GTK4/libadwaita Linux companion | Compete — UI inspiration |
| 90 | Qflip-Mods | https://github.com/bad-antics/Qflip-Mods | bad-antics | CLI | C++ | ~1 | 2025-12-29 | GPL-3.0 | Active | Forked qFlipper with extras | N/A |
| 91 | Flipper-WebSerial | https://github.com/jaylikesbunda/Flipper-WebSerial | jaylikesbunda | WebSerial | JS | ~5 | 2025-02-02 | GPL-3.0 | Stale | Browser WebSerial JS lib for Flipper CLI | Gap |
| 92 | F0-WebSerial-File-Transfer | https://github.com/jaylikesbunda/F0-WebSerial-File-Transfer | jaylikesbunda | WebSerial | JS | ~5 | 2024-11-14 | unspecified | Stale | Browser file pull/push via WebSerial | N/A |
| 93 | flipper-zero-interface | https://github.com/bruno-civongroup/flipper-zero-interface | bruno-civongroup | WebSerial | JS | ~4 | 2026-04-03 | MIT | Active | Web UI: terminal + file browser + WiFi/SubGHz/NFC/IR/screen mirror | Compete |
| 94 | zero-cmd | https://github.com/archrampart/zero-cmd | archrampart | WebSerial | JS | ~1 | 2026-02-06 | MIT | Active | Web command center (Marauder + Deauther + NRF24 + iButton bridges) | Compete |
| 95 | FlipperZero-Web-Cli-Terminal | https://github.com/crownytrex/FlipperZero-Web-Cli-Terminal | crownytrex | WebSerial | HTML | 0 | 2025-12-02 | MIT | Active | Browser web CLI terminal | N/A |
| 96 | flipperzero-rs | https://github.com/flipperzero-rs/flipperzero-rs | flipperzero-rs | SDK | Rust | ~677 | 2026-04-14 | MIT | Active | Rust no_std SDK for **on-device** apps | N/A — pipeline reference |
| 97 | flipperzero-template | https://github.com/flipperzero-rs/flipperzero-template | flipperzero-rs | SDK | Rust | ~106 | 2025-12-22 | unspecified | Active | Cookie-cutter for Rust FAPs | N/A |
| 98 | flipperzero-rust-template (kWAYTV) | https://github.com/kWAYTV/flipperzero-rust-template | kWAYTV | SDK | Rust | ~1 | 2025-02-16 | unspecified | Stale | Hot-reload Rust template | N/A |
| 99 | flipper0 | https://github.com/boozook/flipper0 | boozook | SDK | Rust | ~35 | 2023-02-02 | MIT | Archived | Predecessor to flipperzero-rs | N/A |
| 100 | mp-flipper | https://github.com/ofabel/mp-flipper | ofabel | SDK | C | ~182 | 2025-04-19 | MIT | Active | MicroPython runtime ported to Flipper Zero | Gap — LLM payloads on-device |
| 101 | Flipper-Zero-Development-Toolkit | https://github.com/CodyTolene/Flipper-Zero-Development-Toolkit | CodyTolene | SDK | C | ~130 | 2025-02-02 | MIT | Stale | Dev bundle for kickstarting FZ projects | N/A |
| 102 | Flipper-Studio | https://github.com/cosmixcom/Flipper-Studio | cosmixcom | SDK | JS | ~21 | 2024-10-11 | MIT | Stale | Electron IDE for Ducky + FAPs | N/A — UX precedent |
| 103 | Flipper-Plugin-Tutorial | https://github.com/DroomOne/Flipper-Plugin-Tutorial | DroomOne | SDK | C | ~747 | 2024-03-25 | unspecified | Stale | Most-cited beginner FAP tutorial | N/A |
| 104 | FZBuilder | https://github.com/gianniocchipinti/FZBuilder | gianniocchipinti | SDK | (mix) | ~57 | 2023-02-25 | unspecified | Archived | CFW + Marauder + CLI integrated builder | N/A |
| 105 | NiA-FBT26 | https://github.com/NaTo1000/NiA-FBT26 | NaTo1000 | SDK | Shell | ~1 | 2026-03-29 | unspecified | Active | "Advanced qFlipper alt" w/ FAP/FW builder + integrated terminal | Compete |
| 106 | quartz | https://github.com/kdairatchi/quartz | kdairatchi | SDK | Crystal | 0 | 2026-04-18 | MIT | Active | Crystal-language Flipper dev framework | N/A |
| 107 | proxmark3-to-flipper | https://github.com/dimchansky/proxmark3-to-flipper | dimchansky | Library | Go | ~61 | 2022-10-07 | Apache-2.0 | Archived | Convert PM3 dumps to Flipper .nfc | Gap — direct Go port candidate |
| 108 | ClassicConverter | https://github.com/equipter/ClassicConverter | equipter | Library | Python | ~121 | 2024-09-20 | GPL-3.0 | Stale | Mifare bin ↔ Flipper .nfc converter | Gap — port to Go |
| 109 | AmiiboConverter | https://github.com/Lanjelin/AmiiboConverter | Lanjelin | Library | Python | ~154 | 2026-03-19 | GPL-3.0 | Active | Amiibo bin format converter | Gap (`nfc_amiibo_*`) |
| 110 | SerialHex2FlipperZeroInfrared | https://github.com/maehw/SerialHex2FlipperZeroInfrared | maehw | Library | Python | ~107 | 2024-05-21 | GPL-3.0 | Stale | Hex IR dump → .ir converter | Gap — IR decoder port |
| 111 | flipperzero-subghz-bruteforce (Lisp) | https://github.com/alecigne/flipperzero-subghz-bruteforce | alecigne | Library | Common Lisp | ~19 | 2024-07-13 | unspecified | Stale | Same idea as tobiabocchi, in Lisp | N/A |
| 112 | flipperzero-gate-bruteforce | https://github.com/Hong5489/flipperzero-gate-bruteforce | Hong5489 | Library | Python | ~653 | 2022-10-22 | unspecified | Archived | Gate remote bruteforce generator | N/A |
| 113 | mfkey32v2 | https://github.com/equipter/mfkey32v2 | equipter | Library | C | ~846 | 2024-09-20 | GPL-3.0 | Stale | Mifare Classic key recovery from nonces | Yes (`mfkey32_recover`) |
| 114 | FlipperNested | https://github.com/AloneLiberty/FlipperNested | AloneLiberty | Library | C | ~374 | 2023-07-10 | GPL-3.0 | Stale | Nested-attack on-device + host helpers | Partial (`mfoc_attack`) |
| 115 | mfoc | https://github.com/nfc-tools/mfoc | nfc-tools | Library | C | ~1.4k | 2024-07-17 | GPL-2.0 | Stale | Mifare Classic Offline Cracker | Partial — Spec exists, library port candidate |
| 116 | mfcuk | https://github.com/nfc-tools/mfcuk | nfc-tools | Library | C | ~1.1k | 2024-07-10 | GPL-2.0 | Stale | Mifare Classic Universal toolKit (darkside) | Gap |
| 117 | miLazyCracker | https://github.com/nfc-tools/miLazyCracker | nfc-tools | Library | Shell | ~363 | 2022-12-20 | unspecified | Archived | Hardnested attack runner | Gap |
| 118 | mfterm | https://github.com/4ZM/mfterm | 4ZM | Library | C | ~153 | 2024-01-14 | GPL-3.0 | Stale | Interactive Mifare terminal | N/A — UX precedent |
| 119 | rtl_433 | https://github.com/merbanan/rtl_433 | merbanan | Library | C | ~7.4k | 2026-04-25 | GPL-2.0 | Active | ISM-band protocol decoder (TPMS, weather, KeeLoq) | Partial — federate via MCP |
| 120 | Universal Radio Hacker | https://github.com/jopohl/urh | jopohl | Library | Python | ~12k | 2025-12-19 | GPL-3.0 | Active | GUI for analysing/fuzzing arbitrary RF protocols | Gap — MCP bridge candidate |
| 121 | inspectrum | https://github.com/miek/inspectrum | miek | Library | C++ | ~2.4k | 2025-12-06 | GPL-3.0 | Active | Visual SDR signal analyser | N/A — adjunct |
| 122 | FlipperDroid | https://github.com/Jeremiznoo/FlipperDroid | Jeremiznoo | Mobile | Kotlin | ~438 | 2025-08-27 | MIT | Active | Android app emulating Flipper features | N/A |
| 123 | iredroid | https://github.com/0x1c1101/iredroid | 0x1c1101 | Mobile | Dart | ~10 | 2025-09-05 | GPL-3.0 | Stale | Android IR remote w/ Flipper .ir import | N/A |
| 124 | FlipIR | https://github.com/QWavey/FlipIR | QWavey | Mobile | Dart | ~1 | 2026-03-13 | unspecified | Active | Flutter app to TX Flipper IR | N/A |
| 125 | android-ir-blaster | https://github.com/iodn/android-ir-blaster | iodn | Mobile | Dart | ~328 | 2026-04-25 | GPL-3.0 | Active | Custom IR remote builder; imports Flipper/LIRC/IRPLUS | N/A |
| 126 | FlipperFinderApp | https://github.com/e5ky0/FlipperFinderApp | e5ky0 | Mobile | Java | ~1 | 2018-11-02 | unspecified | Archived | Lost-Flipper finder | N/A |
| 127 | BLE-Hound | https://github.com/GH0ST3CH/BLE-Hound | GH0ST3CH | Mobile | Kotlin | ~19 | 2026-04-17 | MIT | Active | Android BLE scanner (detects Flippers, AirTags) + offensive spam | Gap — defensive Spec |
| 128 | MifareClassicTool | https://github.com/ikarus23/MifareClassicTool | ikarus23 | AttackPoC | Java | ~5.9k | 2026-01-25 | GPL-3.0 | Active | Android Mifare Classic R/W/analysis | Partial — default-key dictionaries reference |
| 129 | MifareOneTool | https://github.com/xcicode/MifareOneTool | xcicode | AttackPoC | C# | ~1k | 2019-05-17 | GPL-3.0 | Archived | Windows GUI for Mifare ops | N/A |
| 130 | seader | https://github.com/bettse/seader | bettse | AttackPoC | C | ~149 | 2026-03-28 | GPL-3.0 | Active | iCLASS SE / DESFire EV1/EV2 / Seos credential reader (FAP + host parsers) | Partial; Gap (`nfc_seader_credential_read`) |
| 131 | passy | https://github.com/bettse/passy | bettse | AttackPoC | C | ~97 | 2026-04-24 | GPL-3.0 | Active | ePassport reader for Flipper (BAC/PACE) | Gap |
| 132 | ChameleonUltra | https://github.com/RfidResearchGroup/ChameleonUltra | RfidResearchGroup | AttackPoC | C | ~2.5k | 2026-04-25 | GPL-3.0 | Active | Companion device firmware + host protocol | Partial — federation via shared dump fmt |
| 133 | proxmark3 (Iceman) | https://github.com/RfidResearchGroup/proxmark3 | RfidResearchGroup | AttackPoC | C | ~5.6k | 2026-04-26 | GPL-3.0 | Active | Definitive PM3 client (`pm3` REPL) | Gap — wrap as MCP/containerbridge |
| 134 | Proxmark3 (mainline) | https://github.com/Proxmark/proxmark3 | Proxmark | AttackPoC | C | ~3.5k | 2026-01-02 | GPL-2.0 | Active | Original PM3 codebase | N/A — compat reference |
| 135 | ESP32Marauder | https://github.com/justcallmekoko/ESP32Marauder | justcallmekoko | AttackPoC | C++ | ~11k | 2026-04-25 | unspecified | Active | Reference Marauder firmware | Yes — `internal/marauder` consumes |
| 136 | FZEasyMarauderFlash | https://github.com/SkeletonMan03/FZEasyMarauderFlash | SkeletonMan03 | AttackPoC | Python | ~1.4k | 2024-11-12 | GPL-3.0 | Stale | Host flasher for Marauder | Gap (`task setup:marauder`) |
| 137 | marauder-ui | https://github.com/michelangelomo/marauder-ui | michelangelomo | AttackPoC | Vue | ~55 | 2024-11-13 | unspecified | Stale | Web UI over Marauder serial | N/A |
| 138 | projectZero | https://github.com/C5Lab/projectZero | C5Lab | AttackPoC | C | ~146 | 2026-04-25 | MIT | Active | Evil-twin + deauther + **WPA3-SAE overflow** on ESP32C5 + Flipper | Gap — WPA3-SAE not in attacks.md |
| 139 | bettercap | https://github.com/bettercap/bettercap | bettercap | AttackPoC | Go | ~19k | 2026-04-18 | GPL-3.0 | Active | Swiss-army for 802.11/BLE/HID/CAN/IP MITM | Gap — Go reference for primitives |
| 140 | pwnagotchi | https://github.com/evilsocket/pwnagotchi | evilsocket | AttackPoC | Python | ~9k | 2025-08-23 | unspecified | Stale | RL-driven WPA handshake harvester | N/A — federation candidate |
| 141 | esp8266_deauther | https://github.com/SpacehuhnTech/esp8266_deauther | SpacehuhnTech | AttackPoC | C | ~15k | 2024-08-14 | unspecified | Stale | Cheap 802.11 deauther | Partial — covered by Marauder |
| 142 | openhaystack | https://github.com/seemoo-lab/openhaystack | seemoo-lab | AttackPoC | Swift | ~13k | 2024-07-09 | AGPL-3.0 | Stale | FindMy network beacon framework | Gap — port key derivation to Go |
| 143 | AirGuard | https://github.com/seemoo-lab/AirGuard | seemoo-lab | AttackPoC | Kotlin | ~2.3k | 2026-04-22 | Apache-2.0 | Active | Anti-tracking AirTag detector | Gap — defensive Spec |
| 144 | FindMyFlipper | https://github.com/MatthewKuKanich/FindMyFlipper | MatthewKuKanich | AttackPoC | Python | ~2.1k | 2025-04-01 | unspecified | Stale | OpenHaystack key pairs → Flipper AirTag/Tile/SmartTag broadcast | Gap (`findmy_emit`) — anti-stalking-bypass concern noted in appendix |
| 145 | jackit | https://github.com/insecurityofthings/jackit | insecurityofthings | AttackPoC | Python | ~892 | 2020-10-01 | unspecified | Archived | Original MouseJack exploit | Partial (`mousejack_inject`) |
| 146 | jackit-python3 | https://github.com/D0ublesec/jackit-python3 | D0ublesec | AttackPoC | Python | ~2 | 2024-10-02 | CC0-1.0 | Stale | Python 3 port of jackit | Partial |
| 147 | JackItNG | https://github.com/curiousmaster/JackItNG | curiousmaster | AttackPoC | Python | ~1 | 2026-04-15 | unspecified | Active | jackit + SQLite scan history | Partial |
| 148 | cc1101-tool | https://github.com/mcore1976/cc1101-tool | mcore1976 | AttackPoC | C++ | ~457 | 2025-12-23 | unspecified | Active | Arduino CC1101 host CLI | N/A |
| 149 | flipperzero-subbrute | https://github.com/DarkFlippers/flipperzero-subbrute | DarkFlippers | AttackPoC | C | ~868 | 2026-01-05 | MIT | Active | SubGHz key checker | Partial |
| 150 | usbrubberducky-payloads | https://github.com/hak5/usbrubberducky-payloads | hak5 | AttackPoC | PowerShell | ~5.7k | 2026-04-10 | unspecified | Active | Official Hak5 Ducky payload corpus | N/A — fine-tuning input |
| 151 | bashbunny-payloads | https://github.com/hak5/bashbunny-payloads | hak5 | AttackPoC | PowerShell | ~2.9k | 2026-02-02 | unspecified | Active | Bash Bunny payload corpus | N/A |
| 152 | BadUSB-Payloads (Mr-Proxy) | https://github.com/Mr-Proxy-source/BadUSB-Payloads | Mr-Proxy-source | AttackPoC | PowerShell | ~332 | 2026-02-28 | unspecified | Active | Active payload corpus | N/A |
| 153 | flipperzero_badusb_kl | https://github.com/dummy-decoy/flipperzero_badusb_kl | dummy-decoy | AttackPoC | C | ~102 | 2023-07-18 | MIT | Stale | Keyboard-layout (.kl) generator | Gap — non-US-layout payload correctness |
| 154 | REPG | https://github.com/InfoSecREDD/REPG | InfoSecREDD | AttackPoC | PowerShell | ~211 | 2023-12-16 | MIT | Archived | Encrypted Ducky payload generator | N/A — obfuscation, requires elevated audit reason |
| 155 | roostercoopllc/flipper-mcp | https://github.com/roostercoopllc/flipper-mcp | roostercoopllc | AIAgent | Rust | ~10 | 2026-03-08 | MIT | Active | **MCP server for Flipper over WiFi** | Compete — direct sibling |
| 156 | Str1ck9/flipper-mcp | https://github.com/Str1ck9/flipper-mcp | Str1ck9 | AIAgent | Python | 0 | 2026-04-19 | MIT | Active | MCP server over USB-CDC serial | Compete |
| 157 | AgentFlipper | https://github.com/mattyspangler/AgentFlipper | mattyspangler | AIAgent | Python | ~33 | 2025-08-29 | unspecified | Stale | LLM agent (Ollama + LightLLM + RAG + pyFlipper) | Compete |
| 158 | ESP32-Bus-Pirate | https://github.com/geo-tp/ESP32-Bus-Pirate | geo-tp | AdjacentHW | C++ | ~3.1k | 2026-04-23 | MIT | Active | Web-CLI hardware-hacking tool | Gap — federation via MCP |
| 159 | Bruce firmware | https://github.com/BruceDevices/firmware | BruceDevices | AdjacentHW | C++ | ~5.4k | 2026-04-16 | AGPL-3.0 | Active | Multi-tool FW on M5Cardputer / ESP boards | N/A |
| 160 | qBruce | https://github.com/Laith-Al/qBruce | Laith-Al | AdjacentHW | VB.NET | ~2 | 2026-04-17 | MIT | Active | qFlipper-style Windows app for Bruce | Compete |
| 161 | Launcher (Bruce/M5/CYD) | https://github.com/bmorcelli/Launcher | bmorcelli | AdjacentHW | C++ | ~1.5k | 2026-04-26 | MIT | Active | Multi-firmware launcher for ESP32 boards | N/A |
| 162 | Ghost ESP (original) | https://github.com/Spooks4576/Ghost_ESP | Spooks4576 | AdjacentHW | C | ~1.1k | 2025-04-22 | MIT | Archived | ESP32 pen-test FW; superseded by GhostESP-Revival (row 254) | N/A — historical |
| 163 | ESP32-Marauder-CYD | https://github.com/Fr4nkFletcher/ESP32-Marauder-Cheap-Yellow-Display | Fr4nkFletcher | AdjacentHW | C | ~1.6k | 2025-11-15 | MIT | Active | Marauder for Cheap Yellow Display board | N/A |
| 164 | Ultimate-Remote (M5) | https://github.com/geo-tp/Ultimate-Remote | geo-tp | AdjacentHW | C++ | ~169 | 2025-09-11 | unspecified | Stale | Reads Flipper-IRDB files | N/A |
| 165 | FlipperAnimationManager | https://github.com/Ooggle/FlipperAnimationManager | Ooggle | AdjacentHW | C++ | ~494 | 2023-11-16 | MIT | Archived | Desktop tool to manage Flipper animations | N/A |
| 166 | FlipperSetup | https://github.com/FlipperSetup/FlipperSetup | FlipperSetup | AdjacentHW | PowerShell | ~138 | 2023-09-24 | unspecified | Archived | Drag-drop Windows setup tool | N/A |
| 167 | flipper-zero authenticator companion | https://github.com/akopachov/flipper-zero_authenticator-companion | akopachov | AdjacentHW | Svelte | ~114 | 2024-11-29 | GPL-3.0 | Stale | Web companion for Flipper Authenticator (TOTP/HOTP key import) | N/A |
| 168 | flipperzero-mayhem | https://github.com/eried/flipperzero-mayhem | eried | AdjacentHW | C++ | ~701 | 2026-01-26 | MIT | Active | Multi-board ESP32 + CC1101 + NRF24 expansion | N/A |
| 169 | flipper-zero-backpacks | https://github.com/Chrismettal/flipper-zero-backpacks | Chrismettal | AdjacentHW | C++ | ~423 | 2026-04-25 | NOASSERTION | Active | Add-on board ecosystem | N/A |
| 170 | pwnhyve | https://github.com/whatotter/pwnhyve | whatotter | AdjacentHW | Python | ~448 | 2026-02-26 | GPL-3.0 | Active | RPi Zero "Flipper-like" multitool | Compete |
| 171 | Kali-Zero-Firmware | https://github.com/Flipper76/Kali-Zero-Firmware | Flipper76 | CFW | C | ~200 | 2026 | GPL-3.0 | Active | French-localized firmware ("le firmware leader français"); heavy UI/menu translation; Unleashed-derived | N/A |
| 172 | FlipperFrenchCommunity | https://github.com/FlipperFrenchCommunity | community | CFW | (mix) | small | 2026 | varies | Active | French community org: translated docs, animations, tutorials, awesome list | N/A — discovery node |
| 173 | Eng1n33r/flipperzero-firmware | https://github.com/Eng1n33r/flipperzero-firmware | Eng1n33r | CFW | C | ~436 followers | 2024 | GPL-3.0 | Stale | Russian-author Quantum-FW lineage; **first encoder/sender for several SubGHz protocols Q2 2022** — historically load-bearing on Unleashed lineage tree | N/A |
| 174 | slootsky/Eng1n33r mirror | https://github.com/slootsky/Eng1n33r-flipperzero-firmware | slootsky | CFW | C | <50 | 2024 | GPL-3.0 | Stale | Maintained mirror of Eng1n33r code-grabber lineage | N/A |
| 175 | derskythe rolling-code | https://github.com/derskythe/flipperzero-firmware-derskythe | derskythe | CFW | C | ~300 | 2025 | GPL-3.0 | Stale | Code-grabber rolling-code (Doorhan, Nice FlorS, BFT Mitto, Somfy Telis); experimental rolling-counter desync evasion | N/A |
| 176 | an4tur0r/flipperzero-unleashed | https://github.com/an4tur0r/flipperzero-unleashed | an4tur0r | CFW | C | <50 | 2024 | GPL-3.0 | Stale | Code-grabber Unleashed variant | N/A |
| 177 | Flipper-ARF | https://github.com/D4C1-Labs/Flipper-ARF | D4C1-Labs | CFW | C | ~50 | 2026 | GPL-3.0 | Active | **Automotive Research Firmware** — Unleashed-derived but *removes* general-purpose features; KeeLoq/keyless/alarm-fob focus; academic positioning. Site arf.d4c1.com | Gap — focused-CFW pattern |
| 178 | WerWolv/flipperzero-firmware | https://github.com/WerWolv/flipperzero-firmware | WerWolv | CFW | C | small | 2023 | GPL-3.0 | Stale | Personal fork by ImHex author — historic cross-pollination | N/A |
| 179 | yocvito/Flipper-Xtreme | https://github.com/yocvito/Flipper-Xtreme | yocvito | CFW | C | small | 2024 | GPL-3.0 | Stale | Independent Xtreme mirror | N/A |
| 180 | FlipperZeroHondaFirmware | https://github.com/nonamecoder/FlipperZeroHondaFirmware | nonamecoder | CFW | C | <100 | 2024 | GPL-3.0 | Stale | Single-vendor PoC firmware: Honda key fobs (FCC ID KR5V2X) | N/A |
| 181 | flipperzero-firmware-walkietalkie | https://github.com/jamisonderek/flipperzero-firmware-walkietalkie | jamisonderek | CFW | C | ~50 | 2024 | GPL-3.0 | Stale | Walkie-talkie firmware variant — niche audio-over-SubGHz CFW | Gap — voice-over-SubGHz |
| 182 | FZ_graphics | https://github.com/Kuronons/FZ_graphics | Kuronons | Bundle | (mix) | ~600 | 2026 | unspecified | Active | Custom animations + profile + passport pictures | N/A |
| 183 | flipper-zero-animations | https://github.com/mnenkov/flipper-zero-animations | mnenkov | Bundle | (mix) | ~200 | 2025 | unspecified | Stale | Animation dump + creation tooling | N/A |
| 184 | Graphics4FZ | https://github.com/ablaran/Graphics4FZ | ablaran | Bundle | (mix) | ~150 | 2026 | unspecified | Active | Momentum-optimized graphic/icon packs | N/A |
| 185 | flip0anims | https://github.com/wrenchathome/flip0anims | wrenchathome | Bundle | (mix) | <50 | 2025 | unspecified | Stale | Custom animations | N/A |
| 186 | FZ_Animations (Haseosama) | https://github.com/Haseosama/FZ_Animations | Haseosama | Bundle | (mix) | <100 | 2025 | unspecified | Stale | French-author animation pack | N/A |
| 187 | Flipper-Zero-Anime-Wallpapers | https://github.com/IoriKesso/Flipper-Zero-Anime-Wallpapers | IoriKesso | Bundle | (mix) | ~150 | 2025 | unspecified | Stale | Anime wallpapers + install instructions | N/A |
| 188 | flipper-pirates-asset-pack | https://github.com/cyberartemio/flipper-pirates-asset-pack | cyberartemio | Bundle | (mix) | ~50 | 2025 | unspecified | Stale | PotC-themed pack (15 anim/3 passports/6 icons/3 fonts) | N/A |
| 189 | awesome-flipperzero-pack | https://github.com/iakat/awesome-flipperzero-pack | iakat | Bundle | (mix) | small | 2025 | unspecified | Stale | Curated asset bundle releases | N/A |
| 190 | Flipper-Zero-NFC-Trolls | https://github.com/w0lfzk1n/Flipper-Zero-NFC-Trolls | w0lfzk1n | Bundle | (mix) | ~100 | 2025 | unspecified | Stale | NFC link payload corpus (NDEF URI tags) | N/A |
| 191 | BADUSB (CharlesTheGreat77) | https://github.com/CharlesTheGreat77/BADUSB | CharlesTheGreat77 | Bundle | PowerShell | small | 2025 | unspecified | Active | Lesser-known BadUSB script collection | N/A |
| 192 | Flipper-zero-on-dwgx | https://github.com/dwgx/Flipper-zero-on-dwgx | dwgx | Bundle | (mix) | small | 2025 | unspecified | Stale | Full SD pack incl. BitLocker dump payloads | N/A — flag BitLocker payloads |
| 193 | Correia-jpv mirror | https://github.com/Correia-jpv/fucking-awesome-flipperzero | Correia-jpv | AwesomeList | (mix) | small | 2026 | unspecified | Active | djsime1 mirror with star/fork counts auto-injected per row | N/A |
| 194 | hackliberty Forgejo mirror | https://git.hackliberty.org/Awesome-Mirrors/awesome-flipperzero | hackliberty | AwesomeList | (mix) | n/a | 2025 | unspecified | Stale | Off-GitHub mirror — censorship-resilience pattern | N/A |
| 195 | firefox-webserial | https://github.com/kuba2k2/firefox-webserial | kuba2k2 | CLI | TypeScript | ~250 | 2026 | MIT | Active | **WebSerial polyfill for Firefox** via native helper — unblocks all WebSerial Flipper tools on FF | Gap — strategic dep for browser client |
| 196 | nfc2bin | https://github.com/D0ublesec/nfc2bin | D0ublesec | CLI | Python | ~30 | 2024 | unspecified | Stale | Convert Flipper `.nfc` → mfdread-compatible `.bin` | Gap — port to Go |
| 197 | nfc_dumpconvert | https://github.com/kulverstukas1/nfc_dumpconvert | kulverstukas1 | CLI | Python | ~10 | 2024 | unspecified | Stale | NFC file converter (Flipper ↔ MCT/PM3 emulator/ChameleonUltra) | Gap — port to Go |
| 198 | flipper_toolbox | https://github.com/evilpete/flipper_toolbox | evilpete | CLI | Python | ~150 | 2025 | unspecified | Stale | Random scripts for generating Flipper data files | N/A |
| 199 | flipperzero-rawsub_decoder | https://github.com/nocomp/flipperzero-rawsub_decoder | nocomp | CLI | Python | ~80 | 2024 | unspecified | Stale | Decode raw `.sub` (OOK/Manchester) — direct port candidate | Gap — port to Go |
| 200 | flipper_kdf | https://github.com/Esonhugh/flipper_kdf | Esonhugh | CLI | Python | ~20 | 2024 | unspecified | Stale | Mifare KDF helper | Gap |
| 201 | AmiiboFlipperConverter | https://github.com/Lucaslhm/AmiiboFlipperConverter | Lucaslhm | Library | Python | ~250 | 2024 | unspecified | Stale | Amiibo `.bin` → Flipper format; predates AmiiboConverter | N/A |
| 202 | F0_EM4100_generator | https://github.com/evillero/F0_EM4100_generator | evillero | Library | Python | ~30 | 2024 | unspecified | Stale | RFID ID generator for fuzzer (EM4100 dictionary) | Gap |
| 203 | vin_decoder (FAP) | https://github.com/evillero/vin_decoder | evillero | Library | C | ~10 | 2024 | unspecified | Stale | VIN decoder FAP — only Flipper-side VIN parser | N/A |
| 204 | PicoGen | https://github.com/00Waz/PicoGen | 00Waz | Library | Python | ~80 | 2025 | unspecified | Stale | **PicoPass emulation file generator** — PACS string + parity bits + iCLASS legacy transport-key encryption | Gap — picopass downgrade chain |
| 205 | weebo (bettse) | https://github.com/bettse/weebo | bettse | Library | C | ~50 | 2026-04 | GPL-3.0 | Active | NTAG215 parser/emulator/duplicator | Gap |
| 206 | seos_compatible (bettse) | https://github.com/bettse/seos_compatible | bettse | Library | C | ~30 | 2026-04 | GPL-3.0 | Active | HID Seos reader research | Gap (`nfc_seos_*`) |
| 207 | d11f_catalog (bettse) | https://github.com/bettse/d11f_catalog | bettse | Library | C | ~20 | 2026-01 | GPL-3.0 | Active | Mifare Classic Mini token parser | Gap |
| 208 | Metroflip | https://github.com/luu176/Metroflip | luu176 | AttackPoC | C | ~400 | 2026 | GPL-3.0 | Active | **Multi-protocol metro card reader FAP** (Bip!, Charliecard, Clipper, Intertic, ITSO, Metromoney, myki, Navigo, Opal, Opus, Rav-Kav, RENFE, Suica, Troika) — Metrodroid spiritual successor on-device | Gap — top transit-research target |
| 209 | Flipper-ARTM-NFC-card-scans | https://github.com/JohnELester/Flipper-ARTM-NFC-card-scans | JohnELester | AttackPoC | (mix) | ~10 | 2024 | unspecified | Stale | Quebec ARTM transit card scans | N/A |
| 210 | FlipperApp-TuLlave | https://github.com/zqu4rtz/FlipperApp-TuLlave | zqu4rtz | AttackPoC | C | ~5 | 2024 | unspecified | Stale | Bogotá TransMi "TuLlave" balance reader | N/A |
| 211 | ami-tool | https://github.com/Firefox2100/ami-tool | Firefox2100 | AttackPoC | C | ~150 | 2025 | unspecified | Stale | Amiibo toolkit FAP (NTAG215 emulate, write game data, generate characters) | Gap |
| 212 | flipper-amiibo-toolkit | https://github.com/Firefox2100/flipper-amiibo-toolkit | Firefox2100 | AttackPoC | C | ~100 | 2025 | unspecified | Stale | Predecessor to ami-tool | N/A |
| 213 | HHB-Flipper-App | https://github.com/Anomalous68/HHB-Flipper-App | Anomalous68 | AttackPoC | C | <20 | 2025 | unspecified | Stale | DEF CON 33 hardhat companion FAP (IR signaling to convention badge) | N/A |
| 214 | moycat/secplus | https://github.com/moycat/secplus | moycat | AttackPoC | C | ~100 | 2024 | unspecified | Stale | **Security+ garage-opener standalone FAP** (Chamberlain/LiftMaster Sec+) | Gap |
| 215 | Offensive-Wireless/Flipper-Zero | https://github.com/Offensive-Wireless/Flipper-Zero | Offensive-Wireless | AttackPoC | (mix) | small | 2025 | unspecified | Stale | Garage-door opener research notes + dumps (BFT, CAME, Beninca, Avidsen) | N/A |
| 216 | flipperzero-pin-bypass | https://github.com/heeeyflo/flipperzero-pin-bypass | heeeyflo | AttackPoC | C | ~50 | 2024 | unspecified | Stale | **Lock-screen bypass on Flipper itself** (defensive interest) | Gap — defensive Spec |
| 217 | flipper-tesla-fsd | https://github.com/hypery11/flipper-tesla-fsd | hypery11 | AttackPoC | C | ~100 | 2025 | unspecified | Active | Tesla mod via OBD-II/X179: nag killer, FSD region unlock, BMS dashboard, blind-spot, speed display | N/A — single-vendor automotive |
| 218 | Flipper-Gravity | https://github.com/chris-bc/Flipper-Gravity | chris-bc | AttackPoC | C | ~80 | 2025 | unspecified | Stale | Companion FAP for ESP32-Gravity (offensive/defensive WiFi/BT) | N/A |
| 219 | FlipperPasswordExtractor | https://github.com/RiadZX/FlipperPasswordExtractor | RiadZX | AttackPoC | (mix) | ~50 | 2024 | unspecified | Stale | BadUSB Chrome/Edge browser-password extraction payload — dual-use, requires authorized scope | N/A — payload (audit gate) |
| 220 | bigbrodude6119/flipper-zero-evil-portal | https://github.com/bigbrodude6119/flipper-zero-evil-portal | bigbrodude6119 | AttackPoC | C | ~600 | 2025 | MIT | Active | Generic evil-portal credential harvester (FZ + WiFi devboard) — dual-use, requires engagement scope | Gap — engagement-scope Spec |
| 221 | fl-BLE_SPAM | https://github.com/John4E656F/fl-BLE_SPAM | John4E656F | AttackPoC | C | ~50 | 2025 | unspecified | Stale | Custom-message BLE spam — bystander-safety concern | N/A — bystander-protection Spec required |
| 222 | HEX0DAYS/FlipperZero-PWNDTOOLS | https://github.com/HEX0DAYS/FlipperZero-PWNDTOOLS | HEX0DAYS | AttackPoC | (mix) | small | 2025 | unspecified | Stale | Multi-attack pack incl. deauth — dual-use | N/A — deauth-target Spec required |
| 223 | FlipperHTTP | https://github.com/jblanked/FlipperHTTP | jblanked | Library | C | ~600 | 2026 | unspecified | Active | **HTTP library for WiFi devboard / BW16 / Pi / ESP32-S3/C3/C5/C6** — foundational for jblanked sub-ecosystem | Gap |
| 224 | FlipWiFi | https://github.com/jblanked/FlipWiFi | jblanked | AttackPoC | C | ~250 | 2026 | unspecified | Active | Companion to FlipperHTTP: scan, save WiFi, captive portal, deauth | N/A — deauth-target Spec required |
| 225 | FlipDownloader | https://github.com/jblanked/FlipDownloader | jblanked | Bundle | C | ~150 | 2026 | unspecified | Active | Download apps/assets via WiFi | N/A |
| 226 | FlipWeather | https://github.com/jblanked/FlipWeather | jblanked | Bundle | C | ~100 | 2026 | unspecified | Active | GPS + weather over WiFi | N/A |
| 227 | FlipLibrary | https://github.com/jblanked/FlipLibrary | jblanked | Bundle | C | ~80 | 2024 | unspecified | Stale | Dictionary + random facts | N/A |
| 228 | FlipSocial | https://github.com/jblanked/FlipSocial | jblanked | Bundle | C | ~150 | 2024 | unspecified | Stale | Social media platform on Flipper | N/A |
| 229 | FlipWorld | https://github.com/jblanked/FlipWorld | jblanked | Bundle | C | ~100 | 2025 | unspecified | Stale | Open-world multiplayer game (best with VGM) | N/A |
| 230 | WebCrawler-FlipperZero | https://github.com/jblanked/WebCrawler-FlipperZero | jblanked | Bundle | C | ~80 | 2025 | unspecified | Stale | Browse web + fetch APIs on Flipper | N/A |
| 231 | Norge99/flipperhttp | https://github.com/Norge99/flipperhttp | Norge99 | Library | C | small | 2025 | unspecified | Stale | Independent fork of FlipperHTTP | N/A |
| 232 | magiquest-wand | https://github.com/jamisonderek/magiquest-wand | jamisonderek | AttackPoC | C | ~50 | 2026 | unspecified | Active | Clone/replay MagiQuest IR wand | Gap |
| 233 | FZBambuFilamentReader | https://github.com/jamisonderek/FZBambuFilamentReader | jamisonderek | AttackPoC | C | ~50 | 2026 | unspecified | Active | Bambu Lab 3D printer NFC filament-spool reader | N/A — single-vendor PoC |
| 234 | fzDigiLab (jamisonderek) | https://github.com/jamisonderek/fzDigiLab | jamisonderek | Bundle | C | ~40 | 2025 | unspecified | Stale | Lab401 DigiLab companion FAP | N/A |
| 235 | lab-401/fzDigiLab | https://github.com/lab-401/fzDigiLab | lab-401 | AdjacentHW | C | ~50 | 2025 | unspecified | Stale | **Official Lab401 DigiLab companion FAP** (logic analyzer / GPIO debug) | N/A |
| 236 | Flipper-RGB | https://github.com/jamisonderek/Flipper-RGB | jamisonderek | Bundle | C | ~30 | 2025 | unspecified | Stale | RGB LED driver companion | N/A |
| 237 | Flipper-SCD4x-CO2-Sensor | https://github.com/jamisonderek/Flipper-SCD4x-CO2-Sensor | jamisonderek | Bundle | C | ~30 | 2025 | unspecified | Stale | I2C CO2 sensor read/log | N/A |
| 238 | fzLightMessenger | https://github.com/jamisonderek/fzLightMessenger | jamisonderek | Bundle | C | ~40 | 2025 | unspecified | Stale | Visible-light messaging FAP | N/A |
| 239 | FlipBoard | https://github.com/jamisonderek/flipboard | jamisonderek | Bundle | C | ~80 | 2024 | unspecified | Stale | Macro-pad GPIO companion | N/A |
| 240 | Gemini-Flipper | https://github.com/jamisonderek/Gemini-Flipper | jamisonderek | AIAgent | C | ~60 | 2024 | unspecified | Stale | **ESP32 + Gemini API on-Flipper interaction** — sibling to PromptZero AIAgent class | Compete |
| 241 | Flipper-Zero-Radio-Scanner | https://github.com/jamisonderek/Flipper-Zero-Radio-Scanner | jamisonderek | Bundle | C | ~80 | 2024 | unspecified | Stale | SubGHz scanner output to internal speaker | N/A |
| 242 | Flipper-Zero-Laser-Tag | https://github.com/jamisonderek/Flipper-Zero-Laser-Tag | jamisonderek | Bundle | C | ~50 | 2024 | unspecified | Stale | IR laser tag game | N/A |
| 243 | flipper-zero-input | https://github.com/jamisonderek/flipper-zero-input | jamisonderek | Bundle | C | ~30 | 2024 | unspecified | Stale | Alternative input method | N/A |
| 244 | flipper-zero-sao | https://github.com/jamisonderek/flipper-zero-sao | jamisonderek | Bundle | JS | ~30 | 2024 | unspecified | Stale | Shitty Add-On (DC33 SAO badge) JS payloads | N/A |
| 245 | unitemp-flipperzero | https://github.com/jamisonderek/unitemp-flipperzero | jamisonderek | Bundle | C | ~80 | 2024 | unspecified | Stale | Universal temp/humidity/pressure sensor reader | N/A |
| 246 | flipperzero-changed-faps | https://github.com/jamisonderek/flipperzero-changed-faps | jamisonderek | Bundle | C | ~30 | 2024 | unspecified | Stale | Modded forks of official good-faps | N/A |
| 247 | Flipper-Zero-Video-Game-Module-DIY | https://github.com/EstebanFuentealba/Flipper-Zero-Video-Game-Module-DIY | EstebanFuentealba | SDK | C | ~200 | 2025 | unspecified | Stale | DIY VGM clone hardware + firmware | N/A |
| 248 | FZ Game Engine wiki | https://github.com/jamisonderek/flipper-zero-tutorials/wiki/FlipperZero-Game-Engine-(Video-Game-Engine) | jamisonderek | Wiki | (wiki) | n/a | 2026 | unspecified | Active | Only authoritative VGM dev guide outside official docs | N/A |
| 249 | playmean/fap-list | https://github.com/playmean/fap-list | playmean | SDK | (mix) | ~150 | 2025 | unspecified | Stale | Auto-built `.fap` index with fap-factory | N/A |
| 250 | flipperzero-espwroom32 | https://github.com/snsational/flipperzero-espwroom32 | snsational | AdjacentHW | C | ~150 | 2025 | unspecified | Stale | ESP-WROOM-32 alt to official WiFi devboard | N/A |
| 251 | 0xchocolate/flipperzero-wifi-marauder | https://github.com/0xchocolate/flipperzero-wifi-marauder | 0xchocolate | AdjacentHW | C | ~600 | 2025 | unspecified | Stale | **Original Marauder companion FAP** (`esp32_wifi_marauder.fap`) — predates many forks | N/A |
| 252 | dangerousvasil Marauder companion FW | https://github.com/dangerousvasil/flipperzero-firmware-with-wifi-marauder-companion | dangerousvasil | CFW | C | ~40 | 2024 | GPL-3.0 | Stale | Firmware + Marauder integrated build (sibling to row 23) | N/A |
| 253 | jaylikesbunda/Ghost_ESP (Revival) | https://github.com/jaylikesbunda/Ghost_ESP | jaylikesbunda | AdjacentHW | C | ~1.2k | 2026 | MIT | Active | **Active maintained successor to Spooks4576/Ghost_ESP** — supersedes archived row 162 | N/A |
| 254 | ghost_esp_app | https://github.com/jaylikesbunda/ghost_esp_app | jaylikesbunda | AdjacentHW | C | ~600 | 2026 | MIT | Active | Flipper companion FAP for GhostESP Revival; menu-driven WiFi/BLE/GPS/wardrive | N/A |
| 255 | Spooks4576/GhostESP_Legacy | https://github.com/Spooks4576/GhostESP_Legacy | Spooks4576 | AdjacentHW | C | ~200 | 2024 | MIT | Stale | Legacy ESP32-targeted Ghost firmware — historical reference | N/A |
| 256 | Spooks4576/ghost_esp_app | https://github.com/Spooks4576/ghost_esp_app | Spooks4576 | AdjacentHW | C | ~300 | 2024 | MIT | Stale | Original (pre-revival) companion app | N/A |
| 257 | busse/flipperzero-mcp | https://github.com/busse/flipperzero-mcp | busse | AIAgent | Python | ~50 | 2026 | unspecified | Active | **Modular MCP server** (USB + WiFi transports, protobuf RPC, custom ESP32 FW bundled); Claude Desktop / Cursor compatible. **Most complete sibling.** | Compete — top diff target |
| 258 | flippercloud/flipper-mcp | https://github.com/flippercloud/flipper-mcp | flippercloud | AIAgent | (unknown) | <10 | 2026 | unspecified | Active | **Naming collision** — actually MCP for Flipper Cloud SaaS feature flags, NOT the device | N/A — flag for confusion |
| 259 | dudebot/flipper-mcp-bridge | https://glama.ai/mcp/servers/dudebot/flipper-mcp-bridge | dudebot | AIAgent | (unknown) | <5 | 2026 | unspecified | Active | USB-attached Flipper-as-tool MCP; v0 IR-only (list/parse `.ir`, replay, capture) | Compete — narrow scope |
| 260 | Wall of Flippers | https://github.com/k3yomi/Wall-of-Flippers | k3yomi | Defensive | (mix) | ~500 | 2025 | unspecified | Stale | **MAC-prefix-based FZ + BLE-spam detector** (referenced by BleepingComputer post-FurFest 2023) | Gap — defensive Spec target |
| 261 | FlipperZero-MetroCard-Security | https://github.com/ZafkoGR/FlipperZero-MetroCard-Security | ZafkoGR | Research | (mix) | <30 | 2025 | unspecified | Stale | Academic paper repo: RFID clone, NFC relay, transit cryptanalysis | N/A — citation source |
| 262 | MDPI: Real Capabilities of FZ | https://www.mdpi.com/2673-4591/123/1/6 | (academic) | Research | n/a | n/a | 2026 | n/a | Active | Empirical analysis: IR/RFID/NFC/SubGHz/USB/BLE attack vectors; AI-Cyber Summer School 2025 proceedings | N/A — citation source |
| 263 | IJCRT: Ethical-hacking framework | https://www.ijcrt.org/papers/IJCRT2504103.pdf | (academic) | Research | n/a | n/a | 2025 | n/a | Active | IJCRT 2025-04 — ethical-hacking framework paper | N/A |
| 264 | HID iCLASS downgrade gist | https://gist.github.com/kitsunehunter/c75294bdbd0533eca298d122c39fb1bd | kitsunehunter | Research | (md) | n/a | 2025 | n/a | Stale | iCLASS SR/SE/SEOS → legacy iCLASS downgrade attack notes (PM3 + Flipper) | Gap — picopass downgrade workflow |
| 265 | flipperzero-firmware PR #1888 | https://github.com/flipperdevices/flipperzero-firmware/pull/1888 | pcunning | Research | C | n/a | 2024 | GPL-3.0 | merged | iCLASS Elite key reading w/ CSN display | N/A — historical PR |
| 266 | flipperzero-firmware PR #2201 | https://github.com/flipperdevices/flipperzero-firmware/pull/2201 | nvx | Research | C | n/a | 2024 | GPL-3.0 | merged | nvx PicoPass fixes — key-recovery side reference | N/A |
| 267 | LRQA: FZ Sub-GHz Experiments | https://www.lrqa.com/en/cyber-labs/flipper-zero-experiments-sub-ghz/ | LRQA | Research | n/a | n/a | 2025 | n/a | Active | Industry lab write-up — SubGHz risk assessment | N/A — citation source |
| 268 | ProtoView | https://github.com/antirez/protoview | antirez | Library | C | ~1.7k | 2024 | BSD-3 | Active | OOK/FSK signal capture/decode/edit/replay; built-in TPMS (Renault/Toyota/Schrader/Citroën/Ford), HCS200/300, Keeloq, Oregon, PT2262 | Partial — bundled in Momentum/RogueMaster |
| 269 | ProtoPirate | https://github.com/RocketGod-git/ProtoPirate | RocketGod | Library | C | ~50 | 2024 | unspecified | Active | Multi-vendor key-fob decoder + replay (TPMS, gate fobs); WIP | Gap |
| 270 | RogueMaster/ProtoPirate (fork) | https://github.com/RogueMaster/ProtoPirate | RogueMaster | Library | C | small | 2024 | unspecified | Active | RogueMaster fork of ProtoPirate | Gap |
| 271 | flipper-pager (POCSAG) | https://github.com/xMasterX/flipper-pager | xMasterX & Shmuma | Library | C | ~150 | 2024 | unspecified | Active | POCSAG 512/1200/2400 receive/decode on CC1101 — pager intercept (wiretap-risk in many jurisdictions) | Gap — `subghz_pocsag_decode` Spec listed in v0.8 audit |
| 272 | FlipperMfkey | https://github.com/noproto/FlipperMfkey | noproto | AttackPoC | C | ~700 | 2025 | GPL | Active | **On-device** MIFARE Classic 1K/4K nested-key cracker (no PC needed) | Partial (`mfkey32_recover` host-side); Gap on-device |
| 273 | Pacs-Pwn | https://github.com/noproto/Pacs-Pwn | noproto | AttackPoC | C | ~150 | 2025 | GPL | Active | iCLASS / Picopass / SE / SR PACS extraction + downgrade workflow; pairs with seader (row 130) and PicoGen (row 204) | Gap — picopass downgrade chain |
| 274 | magspoof_flipper (zacharyweiss) | https://github.com/zacharyweiss/magspoof_flipper | Zachary Weiss | AttackPoC | C | ~700 | 2024 | MIT | Active | Magnetic-stripe (Track 1/2/3) emulation over GPIO H-bridge; experimental internal-coil TX | Gap (`magspoof_emulate` Spec); **Refuse-on-payment-card-target** |
| 275 | magspoof_flipper (ElectronicCats fork) | https://github.com/ElectronicCats/magspoof_flipper | ElectronicCats | AttackPoC | C | ~150 | 2024 | MIT | Active | Same upstream + addon-board hardware support | Gap |
| 276 | flipperzero-firmware-magspoof | https://github.com/deft01/flipperzero-firmware-magspoof | deft01 | CFW | C | ~5 | 2023 | GPL | Stale | Whole-firmware bundle of magspoof — provenance only | N/A |
| 277 | nfc_relay | https://github.com/leommxj/nfc_relay | leommxj | AttackPoC | C | ~250 | 2024 | unspecified | Active | **Two-Flipper NFCA APDU relay** over Sub-GHz/RF24 link; passes ISO14443-4 commands. Highest-leverage offensive FAP gap | Gap — `nfc_relay_run` Spec; **Refuse-on-payment/access-target** without engagement scope |
| 278 | flipperzero-firmware_nfc_relay | https://github.com/SpenserCai/flipperzero-firmware_nfc_relay | SpenserCai | CFW | C | ~50 | 2023 | GPL | Stale | Whole-firmware fork bundling NFC relay; predecessor to standalone `nfc_relay` | N/A — provenance |
| 279 | nfc_apdu_runner | https://github.com/SpenserCai/nfc_apdu_runner | SpenserCai | AttackPoC | C/Python | ~120 | 2025 | unspecified | Active | Multi-frame APDU script runner for ISO14443-4A/B; ships NARD response decoder | Gap — `nfc_apdu_script_run` Spec |
| 280 | uid_brute_smarter | https://github.com/fbettag/uid_brute_smarter | fbettag | AttackPoC | C | ~30 | 2024 | unspecified | Active | NFC UID brute-forcer for access-control readers (incremented + dictionary modes) | Gap; **Refuse-on-unauth-target** |
| 281 | Chameleon_Flipper | https://github.com/muylder/Chameleon_Flipper | muylder | AttackPoC | C | ~150 | 2024 | unspecified | Active | FAP that drives a Chameleon Ultra (NFC emulator/sniffer) over USB/BLE — bridges Flipper to MIFARE/HID/iCLASS attacks the Flipper alone can't run | Gap — federation pattern; cross-ref row 132 |
| 282 | flipperzero-sentry-safe-plugin | https://github.com/H4ckd4ddy/flipperzero-sentry-safe-plugin | H4ckd4ddy | AttackPoC | C | ~1.5k | 2023 | unspecified | Stale | Opens any Sentry Safe / Master Lock electronic safe via factory-reset wire pulse — electromechanical, not RF | Gap; **Refuse-on-unauth-target** |
| 283 | wendigo (chris-bc) | https://github.com/chris-bc/wendigo | chris-bc | AttackPoC | C | ~100 | 2025 | GPL | Active | WiFi + BT-Classic + BLE scanner with native UI; collects probes, AP/station list, deauth target picker; ESP32 backend | Gap — most modern BT/BLE recon FAP |
| 284 | BluetoothScannerAndAttacker | https://github.com/MarkCyber/BluetoothScannerAndAttacker | MarkCyber | AttackPoC | C | ~30 | 2024 | unspecified | Active | BlueBorne-vulnerability scanner + exploit attempt FAP — author states "complete control of the device" | **Refuse** without authorized scope |
| 285 | Bluetooth-LE-Spam (Android) | https://github.com/simondankelmann/Bluetooth-LE-Spam | simondankelmann | Mobile | Kotlin | ~3.5k | 2024 | Apache-2.0 | Active | Multi-protocol BLE spam (Apple, Google Fast Pair, Samsung EasySetup, Microsoft SwiftPair) — vendor-corpus reference for FZ ports | Gap — bystander-protection Spec required |
| 286 | ble-spam-android (tutozz) | https://github.com/tutozz/ble-spam-android | tutozz | Mobile | Kotlin | ~700 | 2024 | unspecified | Active | Extends BLE spam with Galaxy/Pixel/Bose buds vendor IDs; corpus portable to Flipper | N/A — corpus reference |
| 287 | Flipper-Zero-BLE-Spam (EvanDebruyne) | https://github.com/EvanDebruyne/Flipper-Zero-BLE-Spam | EvanDebruyne | AttackPoC | C | ~50 | 2023 | unspecified | Stale | Apple-centric BLE spam with MAC rotation every 2s — predecessor to current bundled BLE Spam | N/A — historical |
| 288 | apple_ble_spam_ofw | https://github.com/noproto/apple_ble_spam_ofw | noproto | AttackPoC | C | ~250 | 2024 | unspecified | Active | Apple-only BLE spam port to OFW (vs Xtreme/Momentum) | Gap — bystander-protection Spec required |
| 289 | ble_spam_ofw | https://github.com/noproto/ble_spam_ofw | noproto | AttackPoC | C | ~200 | 2023-12 | unspecified | Stale | Multi-protocol (Apple+Android+Windows) BLE spam OFW port | Gap |
| 290 | SWGE-Flipper-Zero-Beacons | https://github.com/TitaNets/SWGE-Flipper-Zero-Beacons | TitaNets | AttackPoC | JS | ~30 | 2024 | unspecified | Active | Star Wars: Galaxy's Edge BLE beacon spoofer; useful as iBeacon/Eddystone reference impl | N/A — low-harm novelty |
| 291 | flipperzero-CLI-wifi-cracker | https://github.com/grugnoymeme/flipperzero-CLI-wifi-cracker | grugnoymeme | CLI | Python | ~60 | 2024 | unspecified | Active | Off-device cracker for Marauder `.pcap` → hashcat | Gap — pipeline tool |
| 292 | flipper-zero-wifi-hacking (kickcodeandlift) | https://github.com/kickcodeandlift/flipper-zero-wifi-hacking | kickcodeandlift | Wiki | (mix) | ~80 | 2024 | unspecified | Active | End-to-end WPA/WPA2 capture + crack tutorial repo with reusable scripts | N/A — workflow corpus |
| 293 | flipper-zero-wifi-hacking (tm-security) | https://github.com/tm-security/flipper-zero-wifi-hacking | tm-security | Wiki | (mix) | ~30 | 2024 | unspecified | Active | Sister/clone of the kickcodeandlift workflow | N/A |
| 294 | delfyRTL | https://github.com/gorebrau/delfyRTL | gorebrau | AttackPoC | C | ~80 | 2024 | unspecified | Active | **5GHz** WiFi capability via RTL8720DN devboard — deauth, beacon spam — only credible 5GHz attack FAP | Gap — high-leverage 5GHz capability extender |
| 295 | FlipperZero-WiFi-Attacks (GrantPierce94) | https://github.com/GrantPierce94/FlipperZero-WiFi-Attacks | GrantPierce94 | AttackPoC | C | ~10 | 2024 | unspecified | Stale | Educational evil-twin + sniff WIP | N/A — low-maturity |
| 296 | flipper-MCP2515-CANBUS | https://github.com/ElectronicCats/flipper-MCP2515-CANBUS | ElectronicCats | AttackPoC | C | ~250 | 2025 | MIT | Active | **Full CAN bus FAP**: sniff/log/save/modify/inject/error-detect — requires EC CAN add-on | Gap — fills CAN gap entirely; **Refuse-on-unauth-vehicle** |
| 297 | flipper-canutils | https://github.com/iomonad/flipper-canutils | iomonad | AttackPoC | C | ~30 | 2024 | unspecified | Active | "Linux canutils-style" CAN FAP via SPI to MCPxxxx — sniff/inject/filter | Gap — `Refuse-on-unauth-vehicle` |
| 298 | Flipper-Zero-CAN-FD-HS-SW | https://github.com/serma-safety-security/Flipper-Zero-CAN-FD-HS-SW | SERMA Safety & Security | AttackPoC | C | ~30 | 2024 | unspecified | Active | USB-to-CAN bridge FAP: makes Flipper a slcan-compatible adapter on Linux. Requires SERMA CAN-FD board | Gap |
| 299 | flipper-swd_probe | https://github.com/g3gg0/flipper-swd_probe | g3gg0 | AttackPoC | C | ~250 | 2024 | unspecified | Active | **Auto-detects SWD pinout, reads ID register, runs scripts against SWD without OpenOCD/PC** — direct chipdump primitive | Gap — `swd_dump` Spec |
| 300 | flipper-app-dap-link | https://github.com/sfjuocekr/flipper-app-dap-link | sfjuocekr | AttackPoC | C | ~100 | 2024 | unspecified | Active | Free-DAP / CMSIS-DAP debugger FAP — Flipper as full SWD/JTAG probe under PyOCD/OpenOCD | Gap — pairs with row 299 |
| 301 | flipperzero-gps (ezod) | https://github.com/ezod/flipperzero-gps | ezod | AttackPoC | C | ~250 | 2024 | MIT | Active | NMEA 0183 serial GPS module reader FAP — feeds wardriving/wendigo | Gap — wardriving pipeline |
| 302 | flipperzero-gps-lpuart | https://github.com/Sil333033/flipperzero-gps-lpuart | Sil333033 | AttackPoC | C | ~30 | 2024 | unspecified | Active | LPUART variant of GPS reader — better wardrive battery life | N/A |
| 303 | flipperzero-wardriver | https://github.com/Sil333033/flipperzero-wardriver | Sil333033 | AttackPoC | C | ~150 | 2024 | unspecified | Active | Wardriving FAP — logs WiFi+GPS to SD for WiGLE upload | Gap — `wifi_wardrive` Spec; legality varies |
| 304 | Flock-You-Android | https://github.com/MaxwellDPS/Flock-You-Android | MaxwellDPS | Defensive | Kotlin/C | ~200 | 2025 | unspecified | Active | **Counter-surveillance** — detects ALPRs, IMSI catchers, trackers across 7 protocols / 75+ device sigs; ships an FZ FAP companion | Gap — defensive Spec target |
| 305 | Multi_Fuzzer (DarkFlippers) | https://github.com/DarkFlippers/Multi_Fuzzer | DarkFlippers | AttackPoC | C | ~80 | 2024 | GPL | Active | Combined RFID 125kHz + iButton fuzzer (DS1990, Metakom, Cyfral); custom dictionary loader | Gap |
| 306 | iButton Fuzzer | https://github.com/xMasterX/ibutton-fuzzer | xMasterX | AttackPoC | C | ~150 | 2024 | GPL | Active | DS1990/Metakom/Cyfral dictionary attack against 1-Wire readers | Gap |
| 307 | flipper_fuzzgen | https://github.com/Clawzman/flipper_fuzzgen | Clawzman | Library | Python | ~10 | 2024 | unspecified | Active | Off-device generator producing iButton/RFID/NFC fuzz lists | Gap |
| 308 | Flipper_ListEM | https://github.com/Clawzman/Flipper_ListEM | Clawzman | AttackPoC | C | ~15 | 2024 | unspecified | Active | On-device UID dictionary generator for EM4100/iButton | Gap |
| 309 | Flipper-Fuzzer-Lists | https://github.com/Morzan6/Flipper-Fuzzer-Lists | Morzan6 | Bundle | (mix) | ~10 | 2024 | unspecified | Active | Pre-baked dictionaries for iButton + RFID fuzzers | N/A — corpus |
| 310 | flipperzero-goodies | https://github.com/wetox-team/flipperzero-goodies | wetox-team | Bundle | (mix) | ~200 | 2023 | unspecified | Stale | Pre-extracted Moscow-region intercom (DS1990/MSK) iButton master keys + RFID dumps | N/A — corpus, geographic targeting |
| 311 | flipper-hotel-keys | https://github.com/runasand/flipper-hotel-keys | runasand | Bundle | (mix) | ~60 | 2023 | unspecified | Stale | Personal hotel-key collection — provenance reference | N/A — corpus, see appendix A3 |
| 312 | Flipper-Zero RollJam PoC | https://github.com/d4rks1d33/Flipper-Zero---RollJam-PoC | d4rks1d33 | Research | C | ~40 | 2024 | unspecified | Active | WIP RollJam state-machine PoC — research framing, no live-attack jam-and-replay | N/A — research; see appendix A12 |
| 313 | KeeLoq Exploitation Toolkit | https://github.com/Ghost6220/keeloq-exploit-toolkit | Ghost6220 | AttackPoC | C | ~30 | 2025 | unspecified | Active | Production-ready KeeLoq attack PoC: rolling-code recovery + replay primitives — explicit "exploitation" framing | **Refuse** without authorized vehicle/gate target |
| 314 | hackrf | https://github.com/greatscottgadgets/hackrf | greatscottgadgets | AdjacentHW | C | ~7.8k | 2026-04-24 | GPL-2.0 | Active | 1 MHz–6 GHz half-duplex SDR; complements FZ at 868–928 MHz and 2.4 GHz BLE channels | N/A — federation candidate |
| 315 | mayhem-firmware (PortaPack) | https://github.com/portapack-mayhem/mayhem-firmware | portapack-mayhem | AdjacentHW | C++ | ~3.5k | 2026-04 | GPL-2.0 | Active | PortaPack standalone UI for HackRF; ships **`FlipperTX` app that imports FZ `.sub` recordings** to H1/H2/H4M | N/A — Flipper-pipeline downstream |
| 316 | dtmrc/portapack-mayhem | https://github.com/dtmrc/portapack-mayhem | dtmrc | AdjacentHW | C++ | ~200 | 2025 | GPL-2.0 | Active | Alt Mayhem fork with extra apps | N/A |
| 317 | rfcat | https://github.com/atlas0fd00m/rfcat | atlas0fd00m | Adjacent | C/Python | ~620 | 2024-07 | BSD-3 | Stale | YARD Stick One automation; same TI CC1111 family as FZ; classic OOK/2-FSK pen-test interface | N/A — federation candidate |
| 318 | rtl_433-decoders | https://github.com/triq-org/rtl_433-decoders | triq-org | Adjacent | Python | ~80 | 2025 | GPL-3.0 | Active | Community-maintained extra decoders, pulls new TPMS protocols faster than upstream rtl_433 | N/A — pipeline upstream |
| 319 | LimeSuite | https://github.com/myriadrf/LimeSuite | myriadrf | AdjacentHW | C++ | ~860 | 2025 | Apache-2.0 | Active | LimeSDR host (50 MHz BW) — off-band signals FZ cannot reach | N/A |
| 320 | bladeRF | https://github.com/Nuand/bladeRF | Nuand | AdjacentHW | C | ~1k | 2025 | LGPL-2.1 | Active | 47 MHz–6 GHz, 56 MHz BW; rolling-code crack research papers beyond FZ reach | N/A |
| 321 | libiio (PlutoSDR) | https://github.com/analogdevicesinc/libiio | ADI | AdjacentHW | C | ~700 | 2026 | LGPL-2.1 | Active | 70 MHz–6 GHz dev kit; common cellular-band reference companion | N/A |
| 322 | srsRAN_4G | https://github.com/srsRAN/srsRAN_4G | srsRAN | Adjacent | C++ | ~3.9k | 2026-01-26 | AGPL-3.0 | Active | LTE eNB/EPC/UE software stack — research-framing only (lab/shielded testbed) | N/A — research only |
| 323 | srsRAN_Project (5G) | https://github.com/srsran/srsRAN_Project | srsran | Adjacent | C++ | ~1k | 2026-02-16 | AGPL-3.0 | Archived | 5G NR gNB; **archived 2026-02** — flag for monitoring | N/A — research only |
| 324 | OpenAirInterface5G | https://gitlab.eurecom.fr/oai/openairinterface5g | EURECOM | Adjacent | C | n/a | 2026-04 | OAI Public | Active | Full LTE/5G NR academic stack | N/A — research only |
| 325 | YateBTS | https://github.com/yatevoip/yatebts | yatevoip | Adjacent | C++ | ~270 | 2024 | AGPL-3.0 | Stale | GSM BTS controller; "rogue BTS" lab tool framing | N/A — research only |
| 326 | OpenBTS | https://github.com/RangeNetworks/OpenBTS | RangeNetworks | Adjacent | C++ | ~480 | 2018 | AGPL-3.0 | Archived | Original GSM BTS-on-USRP project — historical | N/A |
| 327 | AIMSICD | https://github.com/CellularPrivacy/Android-IMSI-Catcher-Detector | CellularPrivacy | Defensive | Java | ~5.2k | 2026-02-27 | GPL-3.0 | Active | **Defensive** — detects rogue cells; pairs with FZ BLE recon for combined RF threat picture | Gap — defensive Spec |
| 328 | snoopsnitch | https://github.com/srlabs/snoopsnitch | srlabs | Defensive | Java | ~3.7k | 2025 | GPL-3.0 | Active | SRLabs IMSI-catcher / SS7 detector; firmware-analysis | Gap — defensive Spec |
| 329 | hashcat | https://github.com/hashcat/hashcat | hashcat | Adjacent | C | ~26k | 2026-02-20 | MIT | Active | Mode 22000 = WPA*-PMKID/EAPOL — primary cracker for Marauder→FZ→hcxpcapngtool flow | Gap — pipeline downstream |
| 330 | hcxdumptool | https://github.com/ZerBea/hcxdumptool | ZerBea | Adjacent | C | ~2.1k | 2026-04-06 | MIT | Active | PMKID/EAPOL capture from monitor-mode adapters; pipeline upstream of hashcat 22000 | Gap |
| 331 | hcxtools | https://github.com/ZerBea/hcxtools | ZerBea | Adjacent | C | ~2.4k | 2026-04-22 | MIT | Active | `hcxpcapngtool` / `hcxhashtool` — converters Marauder pcap → hc22000 | Gap |
| 332 | john (jumbo) | https://github.com/openwall/john | openwall | Adjacent | C | ~13k | 2026-04-25 | GPL-2.0 | Active | Plugins for non-standard formats incl. several NFC/RFID hash formats | N/A |
| 333 | crapto1 | https://github.com/nfc-tools/crapto1 | nfc-tools | Adjacent | C | ~120 | 2024 | LGPL-2.1 | Stale | Mifare Classic crypto1 attack lib used by mfoc/mfcuk | Partial — bare lib |
| 334 | mfkey64 | https://github.com/CrapsJeroen/mfkey64 | CrapsJeroen | Adjacent | C | ~60 | 2024 | GPL-2.0 | Stale | Mifare Classic key64 derivation from sniffed traffic | Gap |
| 335 | Pyrit | https://github.com/JPaulMora/Pyrit | JPaulMora | Adjacent | Python/C | ~2.3k | 2023 | GPL-3.0 | Stale | Legacy GPU WPA precompute (mostly superseded by hashcat 22000) | N/A — historical |
| 336 | Hob0Rules | https://github.com/praetorian-inc/Hob0Rules | praetorian-inc | Adjacent | (mix) | ~3k | 2024 | Apache-2.0 | Stale | Rule packs targeting WPA/RKE/PIN dictionaries | N/A — pipeline data |
| 337 | OneRuleToRuleThemAll | https://github.com/stealthsploit/OneRuleToRuleThemAll | stealthsploit | Adjacent | (mix) | ~1.1k | 2025 | MIT | Active | Heavyweight hashcat rule | N/A |
| 338 | caringcaribou | https://github.com/CaringCaribou/caringcaribou | CaringCaribou | Adjacent | Python | ~860 | 2025 | GPL-3.0 | Active | UDS/ISO-TP fuzzer; reads logs from any SocketCAN source incl. FZ-CAN bridges | Gap — federation candidate |
| 339 | SavvyCAN | https://github.com/collin80/SavvyCAN | collin80 | Adjacent | C++ | ~1.7k | 2025 | MIT | Active | Host GUI for CAN bus reverse engineering; consumes pcap/log from FZ-CAN | N/A |
| 340 | python-can | https://github.com/hardbyte/python-can | hardbyte | Adjacent | Python | ~1.3k | 2026 | LGPL-3.0 | Active | Generic CAN abstraction; required for caringcaribou | N/A — dependency |
| 341 | awesome-canbus | https://github.com/iDoka/awesome-canbus | iDoka | AwesomeList | (mix) | ~1.7k | 2025 | CC0 | Active | Catalog of CAN tools incl. FZ-relevant adapters | N/A — discovery source |
| 342 | TPMS-Flipper | https://github.com/Crsarmv7l/TPMS-Flipper | Crsarmv7l | AttackPoC | Python | ~120 | 2025 | MIT | Active | Generates valid FZ `.sub` TPMS "low pressure" payloads with chosen ID | Gap — TPMS spoof, ethically gray |
| 343 | flipperzero-tpms (wosk) | https://github.com/wosk/flipperzero-tpms | wosk | AttackPoC | C | ~470 | 2025 | GPL-3.0 | Active | Receive-side TPMS decoder FAP; complements rtl_433 | Gap — defensive-leaning |
| 344 | cantact-app | https://github.com/linklayer/cantact-app | linklayer | Adjacent | Rust/JS | ~200 | 2024 | MIT | Stale | Cross-platform CAN host UI for CANtact dongle | N/A |
| 345 | CAN-Fuzzer (Frostielocks) | https://github.com/Frostielocks/CAN-Fuzzer | Frostielocks | Adjacent | Python | ~50 | 2024 | MIT | Stale | Lightweight CAN fuzzer | N/A |
| 346 | python-OBD | https://github.com/brendan-w/python-OBD | brendan-w | Adjacent | Python | ~1.7k | 2024 | GPL-2.0 | Stale | High-level OBD-II PID library; consumes FZ-relayed ELM327 streams | N/A |
| 347 | ChipWhisperer | https://github.com/newaetech/chipwhisperer | newaetech | AdjacentHW | C/Python | ~1.5k | 2026-04-23 | GPL-3.0 | Active | Side-channel + voltage glitch platform; FZ commonly used as low-cost trigger source | N/A — already in catalog/hardware.md |
| 348 | chipshouter-picoemp | https://github.com/newaetech/chipshouter-picoemp | newaetech | AdjacentHW | C/MicroPython | ~700 | 2025 | CC-BY-SA-4.0 | Active | Low-cost EMFI probe | N/A — already in catalog/hardware.md |
| 349 | Glasgow Interface Explorer | https://github.com/GlasgowEmbedded/glasgow | GlasgowEmbedded | AdjacentHW | Python | ~2.1k | 2026-04-26 | 0BSD/Apache-2.0 | Active | iCE40 protocol explorer; FZ swap-in for SWD/JTAG/UART/I²C/SPI | N/A — already in catalog/hardware.md |
| 350 | faultier (hextreeio) | https://github.com/hextreeio/faultier | hextreeio | AdjacentHW | Python | ~280 | 2025 | MIT | Active | RP2040-based fault injection framework (Stacksmashing/Thomas Roth) | Gap — `workflow_glitch_chip_dump` upstream |
| 351 | glitchlib | https://github.com/stacksmashing/glitchlib | stacksmashing | Adjacent | Python | ~120 | 2025 | MIT | Active | Generic glitcher comms lib for Pico-based platforms | N/A |
| 352 | fault-injection-library (findus) | https://github.com/MKesenheimer/fault-injection-library | MKesenheimer | Adjacent | Python | ~210 | 2026 | MIT | Active | Fork-evolution of raelize/TAoFI; PicoGlitcher v2 native | Gap |
| 353 | TAoFI-FaultLib | https://github.com/raelize/TAoFI-FaultLib | raelize | Adjacent | Python | ~290 | 2024 | MIT | Stale | "The Art of Fault Injection" companion library | N/A |
| 354 | faultycat | https://github.com/ElectronicCats/faultycat | ElectronicCats | AdjacentHW | C/Python | ~340 | 2025 | MIT | Active | Low-cost EMFI alternative to PicoEMP | Gap |
| 355 | picoglitcher-lpc1343 | https://github.com/SySS-Research/picoglitcher-lpc1343 | SySS-Research | Adjacent | Python | ~40 | 2025 | MIT | Active | Reference exploit recipe (LPC1343 voltage glitch) using PicoGlitcher + findus | N/A — research demo |
| 356 | Black Magic Probe (upstream) | https://github.com/blackmagic-debug/blackmagic | blackmagic-debug | AdjacentHW | C | ~3.4k | 2026 | GPL-3.0 | Active | SWD/JTAG host upstream of `flipperdevices/blackmagic-esp32-s2` (row 74) | N/A — upstream reference |
| 357 | libnfc | https://github.com/nfc-tools/libnfc | nfc-tools | Adjacent | C | ~2k | 2025-03-05 | LGPL-3.0 | Active | Host-side NFC/PN53x library; underlies mfoc/mfcuk/miLazyCracker (rows 115–117) | Partial — implicit dep |
| 358 | iceman1001 (user) | https://github.com/iceman1001 | iceman1001 | AwesomeList | (various) | n/a | 2026 | various | Active | The RfidResearchGroup PM3 lead's scratch space — PM3 batch scripts, dictionaries, conversion utilities | N/A — discovery source |
| 359 | RFIDIOt | https://github.com/AdamLaurie/RFIDIOt | AdamLaurie | Adjacent | Python | ~270 | 2024 | GPL-2.0 | Stale | Pre-libnfc Python toolkit; ePassport BAC/PACE pioneer | N/A — complements row 131 |
| 360 | pymrtd | https://github.com/andrea-cuneo/pymrtd | andrea-cuneo | Adjacent | Python | ~80 | 2024 | LGPL | Stale | ePassport / eMRTD parser — beyond `passy` for full DG decoding | Gap |
| 361 | emrtd-tools | https://github.com/MartijnBraam/emrtd | MartijnBraam | Adjacent | Python | ~110 | 2025 | MIT | Active | Modern eMRTD reader; pairs with FZ NFC dump | Gap |
| 362 | cardpeek | https://github.com/L1L1/cardpeek | L1L1 | Adjacent | C/Lua | ~430 | 2024 | GPL-3.0 | Stale | EMV/transit-card script-driven reader — upstream of FZ Metroflip RE | Gap — upstream of row 208 |
| 363 | Sniffle (NCC Group) | https://github.com/nccgroup/Sniffle | nccgroup | AdjacentHW | Python | ~1.1k | 2025-09-25 | BSD-3 | Stale | BLE 5/4.x sniffer firmware for TI CC1352/CC26x2 | N/A — already in catalog/hardware.md |
| 364 | Sniffle (ElectronicCats) | https://github.com/ElectronicCats/Sniffle | ElectronicCats | AdjacentHW | Python | ~230 | 2026-02-12 | BSD-3 | Active | CatSniffer-tuned Sniffle build (`sniffle_cc1352p7_1M.hex` for V3) | Gap |
| 365 | CatSniffer V3 | https://github.com/ElectronicCats/CatSniffer | ElectronicCats | AdjacentHW | Python/HW | ~830 | 2026-02-12 | MIT/CERN | Active | Multi-band Zigbee/Thread/BLE5/LoRa/wMBus dongle | N/A — already in catalog/hardware.md |
| 366 | CatSniffer-Firmware | https://github.com/ElectronicCats/CatSniffer-Firmware | ElectronicCats | AdjacentHW | C | ~130 | 2026 | MIT | Active | Firmware hub for CatSniffer | Gap |
| 367 | CatSniffer-Tools | https://github.com/ElectronicCats/CatSniffer-Tools | ElectronicCats | Adjacent | Python | ~110 | 2026 | MIT | Active | Host-side capture/decoder utilities | Gap |
| 368 | btlejack | https://github.com/virtualabs/btlejack | virtualabs | Adjacent | Python | ~2.1k | 2024-08 | MIT | Stale | BLE 4.x connection hijack via BBC microbit | Gap; **Refuse-on-unauth-target** |
| 369 | crackle | https://github.com/mikeryan/crackle | mikeryan | Adjacent | C | ~770 | 2024 | BSD-3 | Stale | BLE LE Legacy Pairing TK cracker | Gap |
| 370 | nrf-research-firmware | https://github.com/BastilleResearch/nrf-research-firmware | BastilleResearch | AdjacentHW | C/Python | ~810 | 2024 | BSD-2 | Stale | nRF24LU1+ research firmware (mousejack family) | Partial — pairs with rows 145–147 |
| 371 | mousejack (BastilleResearch) | https://github.com/BastilleResearch/mousejack | BastilleResearch | Adjacent | C | ~360 | 2023 | BSD-2 | Stale | Original mousejack PoC | N/A — historical |
| 372 | nRF Sniffer for 802.15.4 | https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4 | NordicSemiconductor | AdjacentHW | C | ~110 | 2025 | proprietary-OK | Active | Zigbee/Thread sniffer firmware for nRF52840 dongle | Gap — alt to CatSniffer |
| 373 | eaphammer | https://github.com/s0lst1c3/eaphammer | s0lst1c3 | Adjacent | C/Python | ~2.5k | 2024-09 | GPL-3.0 | Stale | Enterprise WPA2/3 evil-twin (EAP relay, PEAP creds capture) | Gap — `wifi_peap_downgrade_audit` Spec |
| 374 | wifite2 (kimocoder) | https://github.com/kimocoder/wifite2 | kimocoder | Adjacent | Python | ~1.5k | 2026-04-24 | GPL-2.0 | Active | Automated WiFi audit wrapper around aircrack-ng/hcxdumptool — canonical fork | Gap |
| 375 | wifite2 (derv82, original) | https://github.com/derv82/wifite2 | derv82 | Adjacent | Python | ~7.8k | 2024-08 | GPL-2.0 | Stale | Original — superseded by kimocoder fork | N/A — historical |
| 376 | krackattacks-scripts | https://github.com/vanhoefm/krackattacks-scripts | vanhoefm | Adjacent | C | ~3.5k | 2024-12 | GPL-2.0 | Stale | KRACK PoC scripts; pairs with FZ as adjacent deauth source | N/A — Vanhoef reference impl |
| 377 | wifiphisher | https://github.com/wifiphisher/wifiphisher | wifiphisher | Adjacent | Python | ~14.6k | 2025-02 | GPL-3.0 | Stale | Rogue-AP phishing framework; **borderline** — primary purpose is credential phishing | **Refuse** without engagement scope; cross-ref appendix A5 |
| 378 | Kismet | https://github.com/kismetwireless/kismet | kismetwireless | Adjacent | C++ | ~2.1k | 2026-04-22 | GPL-2.0 | Active | Multi-radio wireless detection/IDS; ingests Marauder/FZ pcaps | Gap — defensive |
| 379 | dwpa (WPA-sec) | https://github.com/RealEnder/dwpa | RealEnder | Adjacent | Python/PHP | ~470 | 2025 | MIT | Active | Distributed WPA cracking back-end (wpa-sec.stanev.org) | N/A |
| 380 | SecLists | https://github.com/danielmiessler/SecLists | danielmiessler | Bundle | (mix) | ~60k | 2026 | MIT | Active | Wordlist corpus consumed by hashcat post-Marauder capture | N/A — pipeline data |
| 381 | Probable-Wordlists | https://github.com/berzerk0/Probable-Wordlists | berzerk0 | Bundle | (mix) | ~10k | 2026 | MIT | Active | Wordlist corpus | N/A — pipeline data |
| 382 | opensesame | https://github.com/samyk/opensesame | samyk | Adjacent | C | ~870 | 2024 | unspecified | Stale | De Bruijn-sequence wireless garage attack (TI CC11xx — same chip family as FZ); FZ port lives in xMasterX/all-the-plugins | Partial — Samy Kamkar classic |
| 383 | magspoof (samyk) | https://github.com/samyk/magspoof | samyk | Adjacent | C/Eagle | ~4.1k | 2022-07 | unspecified | Stale | Magstripe spoof reference; FZ port = row 274/275 | N/A — upstream |
| 384 | keysweeper | https://github.com/samyk/keysweeper | samyk | Adjacent | C/Eagle | ~1.1k | 2017 | unspecified | Archived | Wireless keyboard sniffer (MS proprietary 2.4 GHz); superseded by mousejack | N/A — historical |
| 385 | poisontap | https://github.com/samyk/poisontap | samyk | Adjacent | JS | ~6.5k | 2018 | unspecified | Archived | USB-impl HID exfil via DHCP race; same conceptual family as FZ BadUSB | N/A — historical |
| 386 | awesome-dc32-badge | https://github.com/raulnor516/awesome-dc32-badge | raulnor516 | AwesomeList | (mix) | ~250 | 2025 | MIT | Active | Catalog of DC32 (2024) badge resources — useful for FZ↔badge SAO interop | N/A — discovery source |
| 387 | DEFCON-32-BadgeFirmware (jaku) | https://github.com/jaku/DEFCON-32-BadgeFirmware | jaku | AdjacentHW | C | ~120 | 2024 | MIT | Stale | DC32 alt firmware; FZ-relayable IR/RF over SAO | N/A |
| 388 | defcon-32-badge-flashy-rom | https://github.com/Calvin-LL/defcon-32-badge-flashy-rom | Calvin-LL | AdjacentHW | C | ~30 | 2024 | MIT | Stale | DC32 ROM mod | N/A |
| 389 | RFID-Gooseneck | https://github.com/sh0ckSec/RFID-Gooseneck | sh0ckSec | AdjacentHW | (mix) | ~290 | 2024 | MIT | Stale | DEF CON-popularized **long-range HID reader**; FZ stores captured badges | Gap; **Refuse-on-unauth-physical-pentest** |
| 390 | CircuitPython | https://github.com/adafruit/circuitpython | Adafruit | Adjacent | C/Python | ~4.3k | 2026 | MIT | Active | Run CircuitPython on ESP32-S2 WiFi devboard for custom companion code | N/A — alternate devboard route |
| 391 | ESP-IDF | https://github.com/espressif/esp-idf | espressif | Adjacent | C | ~14k | 2026 | Apache-2.0 | Active | Required base SDK for any custom WiFi-devboard firmware | N/A — dependency |
| 392 | Termux | https://github.com/termux/termux-app | termux | Mobile | Java | ~38k | 2026 | GPL-3.0 | Active | Android terminal — host for `qFlipper`-style scripting against FZ over USB-OTG | N/A — Android-side scripting harness |
| 393 | TagTinker | https://github.com/i12bp8/TagTinker | i12bp8 | AttackPoC | C | ~1.2k | 2026-04-26 | unspecified | Active | **Electronic Shelf Label (ESL) research FAP via IR** — Furrtek ESL protocol family. New attack-surface class not previously catalogued | Gap (`ir_esl_*` Spec) |
| 394 | flipperzero-esp-flasher | https://github.com/0xchocolate/flipperzero-esp-flasher | 0xchocolate | Bundle | C | ~609 | 2026-04-26 | unspecified | Active | **Flash ESP chips from the Flipper itself** — no PC needed; foundational for Marauder/devboard onboarding | Gap (`task setup:marauder` on-device variant) |
| 395 | flipper-zero-rf-jammer | https://github.com/RocketGod-git/flipper-zero-rf-jammer | RocketGod-git | AttackPoC | C | ~679 | 2026-04-26 | unspecified | Active | Frequency- and preset-adjustable Sub-GHz RF jammer FAP | Gap; **Refuse-on-unauth-RF-jamming** (FCC §15.5; jurisdictional illegality) |
| 396 | FlipperZeroNRFJammer | https://github.com/huuck/FlipperZeroNRFJammer | huuck | AttackPoC | C | ~526 | 2026-04-21 | unspecified | Active | **2.4 GHz nRF24-based jammer** spanning the BLE/WiFi spectrum | Gap; **Refuse-on-unauth-RF-jamming** |
| 397 | FZ_nRF24_jammer | https://github.com/W0rthlessS0ul/FZ_nRF24_jammer | W0rthlessS0ul | AttackPoC | C | ~166 | 2026-04-26 | unspecified | Active | Alt nRF24 jammer impl — sibling to row 396 | Gap; **Refuse-on-unauth-RF-jamming** |
| 398 | FlipperzeroNRFJammer (d1mov) | https://github.com/d1mov/FlipperzeroNRFJammer | d1mov | AttackPoC | C | ~29 | 2026-04-17 | unspecified | Active | Third independent nRF24 jammer impl | Gap; **Refuse-on-unauth-RF-jamming** |
| 399 | NRF24ChannelScanner | https://github.com/htotoo/NRF24ChannelScanner | htotoo | AttackPoC | C | ~70 | 2026-03-27 | unspecified | Active | nRF24 all-channel scanner — passive recon companion to the jammers above | Gap (defensive sister Spec) |
| 400 | flipper-zero-rf-jammer family — defensive note | *(see rows 395–398)* | (multiple) | Defensive | n/a | n/a | 2026 | n/a | n/a | RF jamming is illegal in most jurisdictions (FCC §15.5; UK Wireless Telegraphy Act 2006) — even for "research" framing | Refusal-policy: bake jurisdiction-specific block into `subghz_jam_*` Specs; mandate operator authorization+RegDomain check |
| 401 | uhf_rfid (frux-c) | https://github.com/frux-c/uhf_rfid | frux-c | AttackPoC | C | ~313 | 2026-04-11 | unspecified | Active | **UHF RFID via YRM100 module** — extends Flipper to the 860–960 MHz EPC Gen2 band (warehouse/asset-tag class) not natively supported | Gap — new band class entirely |
| 402 | flipperzero-geigercounter | https://github.com/nmrr/flipperzero-geigercounter | nmrr | Bundle | C | ~253 | 2026-04-23 | unspecified | Active | ☢ Geiger counter FAP — radiation tube/probe module reader | Gap — sensor class |
| 403 | flipperzero-flippenheimer | https://github.com/eried/flipperzero-flippenheimer | eried | AdjacentHW | (mix) | ~51 | 2026-03-29 | unspecified | Active | DIY geiger-counter add-on hardware design | N/A — sister of row 402 |
| 404 | flipper-xremote | https://github.com/kala13x/flipper-xremote | kala13x | Bundle | C | ~233 | 2026-04-24 | unspecified | Active | Advanced IR universal-remote FAP with stored-button presets | N/A — UX precedent |
| 405 | flipper-xbox-controller | https://github.com/gebeto/flipper-xbox-controller | gebeto | Bundle | C | ~163 | 2026-04-23 | unspecified | Active | Drives Xbox via IR (controller-class) | N/A |
| 406 | flipperzero-qrcode | https://github.com/bmatcuk/flipperzero-qrcode | bmatcuk | Library | C | ~155 | 2026-03-04 | unspecified | Active | On-device QR-code rendering library — reusable display primitive | Gap (display lib) |
| 407 | quac | https://github.com/rdefeo/quac | rdefeo | Bundle | C | ~68 | 2026-03-27 | unspecified | Active | **Q**uick **AC**tion remote — multi-protocol (IR/SubGHz/etc.) macro-remote shell | Gap — workflow pattern |
| 408 | flipperzero-i2ctools | https://github.com/NaejEL/flipperzero-i2ctools | NaejEL | AttackPoC | C | ~109 | 2026-04-18 | unspecified | Active | I²C scan / read / sniff tools — bus-pirate-class primitive on Flipper | Gap (`i2c_*` Spec) |
| 409 | flipper-rs485modbus | https://github.com/ElectronicCats/flipper-rs485modbus | ElectronicCats | AttackPoC | C | ~26 | 2026-01-12 | MIT | Active | **Modbus RTU over RS-485** — industrial-protocol FAP (PLC/SCADA testing) | Gap (`modbus_*` Spec); **Refuse-on-unauth-ICS** |
| 410 | flipper-SX1262-LoRa | https://github.com/ElectronicCats/flipper-SX1262-LoRa | ElectronicCats | AttackPoC | C | ~87 | 2026-04-03 | MIT | Active | **LoRa SX1262** add-on — LoRaWAN class, beyond CC1101's OOK/2-FSK reach | Gap (`lora_*` Spec) |
| 411 | flipper-zero-aprs-tx | https://github.com/yo3gnd/flipper-zero-aprs-tx | yo3gnd | AttackPoC | C | ~26 | 2026-04-25 | unspecified | Active | **APRS transmit** over CC1101 — ham-radio class; ITAR/FCC licensed-band caveat | Gap (`aprs_tx` Spec); jurisdictional warning |
| 412 | FlipRSDR | https://github.com/jsammarco/FlipRSDR | jsammarco | CLI | C | ~19 | 2026-04-18 | unspecified | Active | SDR TX/RX visualizer + recorder for SubGHz over USB or Bluetooth | Gap — host-side SDR pipeline |
| 413 | Flipper-SubGHz-Viewer-Trimmer | https://github.com/SiroxCW/Flipper-SubGHz-Viewer-Trimmer | SiroxCW | WebSerial | JS | ~19 | 2026-04-21 | unspecified | Active | Browser tool: visualize, zoom, trim FZ `.sub` files (RSSI charts) | Gap — port to internal/web |
| 414 | flipper-subghz-scheduler | https://github.com/shalebridge/flipper-subghz-scheduler | shalebridge | Bundle | C | ~21 | 2026-04-11 | unspecified | Active | Send `.sub` files / playlists at preset intervals (cron-on-Flipper) | Gap (`subghz_schedule` Spec) |
| 415 | RocketGods-SubGHz-Toolkit | https://github.com/RocketGod-git/RocketGods-SubGHz-Toolkit | RocketGod | Library | C | ~239 | 2026-04-24 | unspecified | Active | Reverse-engineer FZ SubGHz protocols + KeeLoq manufacturer codes | Gap |
| 416 | Flipper-Zero-SubGHz-Signal-Generator | https://github.com/RocketGod-git/Flipper-Zero-SubGHz-Signal-Generator | RocketGod | Library | C | ~35 | 2026-04-03 | unspecified | Active | Generate arbitrary SubGHz `.sub` waveforms | Gap |
| 417 | Flipper_Zero-sub_converter | https://github.com/RocketGod-git/Flipper_Zero-sub_converter | RocketGod | CLI | Python | ~40 | 2026-03-14 | unspecified | Active | Convert `.sub` → other SubGHz file formats | Gap — port to Go |
| 418 | Flipper-Zero-RollJam-Single-Chip-PoC | https://github.com/c0d3r-SubGHz/Flipper-Zero-RollJam-Single-Chip-PoC | c0d3r-SubGHz | Research | (mix) | ~21 | 2026-04-24 | unspecified | Active | **Atomic Replay attacks via TDM on a single CC1101** — first credible single-chip RollJam PoC for FZ; supersedes row 312 | Research; **Refuse-on-unauth-RKE-target**; cross-ref appendix A12 |
| 419 | EvilCrowRF_Custom_Firmware_CC1101_FlipperZero | https://github.com/h-RAT/EvilCrowRF_Custom_Firmware_CC1101_FlipperZero | h-RAT | AdjacentHW | HTML/C | ~565 | 2026-04-24 | unspecified | Active | EvilCrowRF dual-CC1101 dongle FW that reads/writes FZ-compatible files | Gap — federation pattern |
| 420 | flipper_serprog | https://github.com/Psychotropos/flipper_serprog | Psychotropos | CLI | Rust | ~43 | 2026-04-06 | unspecified | Active | **Serprog SPI programmer** — FZ as `flashrom` SPI host (chip dump/reflash) | Gap (`spi_flashrom` Spec) |
| 421 | usb_hid_autofire | https://github.com/pbek/usb_hid_autofire | pbek | Bundle | C | ~126 | 2026-04-16 | unspecified | Active | USB HID left-click auto-fire (clicker) — minimal HID example | N/A — pattern |
| 422 | flipp_pomodoro | https://github.com/Th3Un1q3/flipp_pomodoro | Th3Un1q3 | Bundle | C | ~208 | 2026-04-12 | unspecified | Active | Pomodoro productivity timer FAP | N/A |
| 423 | unitemp-flipperzero (quen0n) | https://github.com/quen0n/unitemp-flipperzero | quen0n | Bundle | C | ~347 | 2026-04-12 | GPL | Active | **Upstream** of jamisonderek/unitemp (row 245) — DHT11/22, DS18B20, BMP280, HTU21 etc. | Gap (sensor read Spec) |
| 424 | FlipperMusicRTTTL | https://github.com/neverfa11ing/FlipperMusicRTTTL | neverfa11ing | Bundle | (mix) | ~369 | 2026-04-12 | unspecified | Active | RTTTL `.txt` corpus for FZ Music Player | N/A — corpus |
| 425 | flipper-zero-fap-boilerplate | https://github.com/leedave/flipper-zero-fap-boilerplate | leedave | SDK | C | ~181 | 2026-02-28 | unspecified | Active | FAP boilerplate / starter — sibling to DroomOne tutorial (row 103) | N/A |
| 426 | flipper-zero-cross-remote | https://github.com/leedave/flipper-zero-cross-remote | leedave | Bundle | C | ~53 | 2026-03-14 | unspecified | Active | Combined IR + SubGHz universal remote | N/A — UX precedent |
| 427 | Flipper-Zero-Game-Boy-Pokemon-Trading | https://github.com/kbembedded/Flipper-Zero-Game-Boy-Pokemon-Trading | kbembedded | Bundle | C | ~373 | 2026-04-24 | unspecified | Active | Trade Pokemon Gen I/II between FZ and Game Boy via game-link cable | N/A — novel hardware-bridge |
| 428 | flipper-gblink | https://github.com/kbembedded/flipper-gblink | kbembedded | Library | C | ~19 | 2026-03-10 | unspecified | Active | **Game Boy Link Cable interface library** for FZ — used by row 427 | Gap — reusable serial-cable lib |
| 429 | flipperzero-waveshare-nfc | https://github.com/mogenson/flipperzero-waveshare-nfc | mogenson | Library | Rust | ~25 | 2026-03-14 | unspecified | Active | Write to Waveshare e-Paper NFC tags from FZ — example Rust FAP | N/A — Rust SDK example |
| 430 | flipperzero-letterbeacon | https://github.com/nmrr/flipperzero-letterbeacon | nmrr | AttackPoC | C | ~43 | 2026-03-14 | unspecified | Active | **Morse beacon over RFID/NFC** interfaces — covert-channel research | Gap |
| 431 | acegoal07/FlipperZero_NFC_Playlist | https://github.com/acegoal07/FlipperZero_NFC_Playlist | acegoal07 | Bundle | C | ~103 | 2026-04-03 | unspecified | Active | Run through a list of NFC cards (sequential emulator) | Gap |
| 432 | acegoal07/FlipperZero_NFC_Comparator | https://github.com/acegoal07/FlipperZero_NFC_Comparator | acegoal07 | Bundle | C | ~23 | 2026-04-12 | unspecified | Active | Compare two NFC cards by UID/protocol/data — verification utility | Gap (defensive) |
| 433 | flipper-bambu (uzyn) | https://github.com/uzyn/flipper-bambu | uzyn | AttackPoC | C | ~52 | 2026-04-21 | unspecified | Active | Bambu Lab filament NFC parser — sibling to jamisonderek's FZBambuFilamentReader (row 233) | N/A |
| 434 | lishi (evillero) | https://github.com/evillero/lishi | evillero | Bundle | C | ~46 | 2026-04-18 | unspecified | Active | Save values from **LISHI lockpick tool** — physical-pentest companion | Gap |
| 435 | flipper-access-audit | https://github.com/matthewkayne/flipper-access-audit | matthewkayne | Defensive | C | ~29 | 2026-04-24 | unspecified | Active | **Defensive auditing of access-control credentials/tags** — first explicit defensive-framing FAP for HID/iCLASS/EM4100 audit | Gap — defensive Spec target |
| 436 | Flipper-Zero-Ghost-Camera-Detector | https://github.com/sacriphanius/Flipper-Zero-Ghost-Camera-Detector | sacriphanius | Defensive | C | ~32 | 2026-04-09 | unspecified | Active | **IR camera detector** — turns FZ into hidden-camera spotter via IR LEDs | Gap — defensive Spec |
| 437 | Flipper-Zero-LD-Toypad-Emulator | https://github.com/SegerEnd/Flipper-Zero-LD-Toypad-Emulator | SegerEnd | Bundle | C | ~33 | 2026-01-10 | unspecified | Active | Lego Dimensions ToyPad USB emulator | N/A |
| 438 | Animations-for-Flipper-Zero (Kf637) | https://github.com/Kf637/Animations-for-Flipper-Zero | Kf637 | Bundle | (mix) | ~239 | 2026-04-26 | unspecified | Active | 300+ public animations from many creators | N/A |
| 439 | flipperzero-animation-tool | https://github.com/nfowlie/flipperzero-animation-tool | nfowlie | CLI | Svelte | ~29 | 2026-03-20 | unspecified | Active | Browser tool for creating custom FZ animations | N/A |
| 440 | bad-antics/nullsec-flipper-suite | https://github.com/bad-antics/nullsec-flipper-suite | bad-antics | Bundle | Python | ~32 | 2026-04-19 | unspecified | Active | 430+ files: 80 BadUSB / 40 SubGHz / 16 IR / NFC / RFID / animations | N/A — corpus |
| 441 | T-Union_Master | https://github.com/SocialSisterYi/T-Union_Master | SocialSisterYi | AttackPoC | C | ~87 | 2026-03-27 | unspecified | Active | **China Transit-Union (交通联合) card info FAP** — adds CN-region transit to Metroflip-class coverage (row 208) | Gap (transit) |
| 442 | tap-ducky | https://github.com/iodn/tap-ducky | iodn | Mobile | Dart | ~78 | 2026-04-25 | unspecified | Active | Rooted-Android USB Rubber Ducky — FZ BadUSB sibling for phones | N/A — adjacent payload class |
| 443 | DucklingScript | https://github.com/DragonOfShuu/DucklingScript | DragonOfShuu | Library | Python | ~53 | 2026-03-14 | unspecified | Active | Trans-compiler from extended DucklingScript → DuckyScript 1.0 | Gap — host-side payload toolchain |
| 444 | DuckyScriptCookbook | https://github.com/aleff-github/DuckyScriptCookbook | aleff-github | SDK | CSS/JS | ~26 | 2026-04-14 | unspecified | Active | VSCode-ium extension: snippets + icons for DuckyScript dev | N/A — UX precedent |
| 445 | FlipperZero-BadUSB-Wireshark | https://github.com/agentzex/FlipperZero-BadUSB-Wireshark | agentzex | Defensive | Lua | ~51 | 2026-04-07 | unspecified | Active | **Wireshark dissector** for BadUSB devices (FZ, Rubber Ducky, etc.) + ducky-script reconstructor | Gap — defensive forensics |
| 446 | flipperzero-shapshup | https://github.com/derskythe/flipperzero-shapshup | derskythe | Bundle | C | ~26 | 2026-03-22 | unspecified | Active | Standalone FAP from the derskythe lineage (cross-ref row 175) | N/A |
| 447 | flipper0-wifi-map (carvilsi) | https://github.com/carvilsi/flipper0-wifi-map | carvilsi | AttackPoC | C | ~111 | 2026-04-18 | unspecified | Active | WiFi map FAP for FZ + ESP32 — wardrive visualisation | Gap — pairs with rows 301–303 |
| 448 | esp32-wifi-map (carvilsi) | https://github.com/carvilsi/esp32-wifi-map | carvilsi | AttackPoC | C | ~31 | 2026-03-27 | unspecified | Active | ESP32 host of row 447 | N/A |
| 449 | flipper-map (Stichoza) | https://github.com/Stichoza/flipper-map | Stichoza | WebSerial | Vue | ~34 | 2026-04-09 | unspecified | Active | Browser visualisation of FZ recordings on an interactive map | Gap — host UX |
| 450 | flipper-nearby-files | https://github.com/Stichoza/flipper-nearby-files | Stichoza | Bundle | C | ~22 | 2026-03-25 | unspecified | Active | View nearby files sorted by GPS distance from current location | N/A |
| 451 | rubber-dolphy (carvilsi) | https://github.com/carvilsi/rubber-dolphy | carvilsi | AttackPoC | C | ~20 | 2026-04-18 | unspecified | Active | BadUSB with **on-device mass-storage exfiltration** | Gap; **Refuse-on-unauth-target** — payload-validator must flag exfil |
| 452 | BadBT (AGO061) | https://github.com/AGO061/BadBT | AGO061 | AttackPoC | C | ~141 | 2026-04-18 | unspecified | Active | **Run BadUSB scripts over Bluetooth** — BLE-keyboard variant of BadKB | Gap (BadKB Spec class — extends row 41) |
| 453 | Chameleon-Ultra-Flipper-Zero-key-dictionary | https://github.com/nbox/Chameleon-Ultra-Flipper-Zero-key-dictionary | nbox | Library | Shell | ~44 | 2026-04-17 | unspecified | Active | Unified key dictionary for ChameleonUltra + FZ | Gap — federation data |
| 454 | NFC-Login (Play2BReal) | https://github.com/Play2BReal/NFC-Login | Play2BReal | Bundle | C | ~20 | 2026-04-12 | unspecified | Active | NFC-tag-as-login-credential FAP | N/A |
| 455 | flipper-rc (ClusterM) | https://github.com/ClusterM/flipper_rc | ClusterM | CLI | Python | ~28 | 2026-04-11 | unspecified | Active | **Home Assistant integration** to emulate IR remotes via FZ | Gap (`homeassistant_bridge` Spec) |
| 456 | fz-yuricable-pro-max | https://github.com/arag0re/fz-yuricable-pro-max | arag0re | AttackPoC | C | ~37 | 2026-02-23 | unspecified | Active | YuriCable Pro Max — **SWD/DCSD-cable** FAP (Apple silicon debug) | Gap — pairs with rows 299–300 |
| 457 | ZeroMesh | https://github.com/SAMS0N1TE/ZeroMesh | SAMS0N1TE | Bundle | C | ~23 | 2026-04-26 | unspecified | Active | **Meshtastic** app for FZ over LoRa add-on | Gap — pairs with row 410 |
| 458 | Moon-Firmware | https://github.com/KaraZajac/Moon-Firmware | KaraZajac | CFW | C | ~22 | 2026-04-25 | unspecified | Active | Custom FW with **XIP flash execution**, full BLE stack, expanded SubGHz automotive protocols | N/A — emerging firmware base |
| 459 | flippy (elijah629) | https://github.com/elijah629/flippy | elijah629 | CLI | Rust | ~22 | 2026-03-28 | unspecified | Active | Rust FW + remote archive management — pairs with row 78 (`flipper-rpc`) | N/A — Rust ecosystem |
| 460 | Sor3nt/Flipper-Zero-ESP32-Port | https://github.com/Sor3nt/Flipper-Zero-ESP32-Port | Sor3nt | CFW | C | ~42 | 2026-04-26 | unspecified | Active | **Flipper firmware ported to ESP32** — alternative-hardware FZ-compatible target | N/A — emerging hardware base; pairs with row 458 |
| 461 | stacksmashing/flipperzero-firmware | https://github.com/stacksmashing/flipperzero-firmware | stacksmashing | CFW | C | ~61 | 2023-10 | GPL-3.0 | Stale | OFW fork with **MIFARE Classic dictionary-attack improvements** — Stacksmashing/Thomas Roth lineage | N/A — research provenance |
| 462 | flipperzero-firmware-unirfremix | https://github.com/ESurge/flipperzero-firmware-unirfremix | ESurge | CFW | C | ~227 | 2026-04 | GPL-3.0 | Archived | Universal-RF Remix CFW — historical reference (now in mainline plugins) | N/A — historical |
| 463 | EJRicketts/flipperzero-firmware-Unleashed | https://github.com/EJRicketts/flipperzero-firmware-Unleashed | EJRicketts | CFW | C | ~47 | 2026-01 | GPL-3.0 | Stale | Code-grabber Unleashed variant in the Eng1n33r lineage (row 173) | N/A |
| 464 | UberGuidoZ/FlipperZeroHondaFirmware | https://github.com/UberGuidoZ/FlipperZeroHondaFirmware | UberGuidoZ | CFW | C | ~91 | 2026-04-22 | GPL-3.0 | Active | Maintained mirror of nonamecoder's Honda fob FW (row 180) | N/A |
| 465 | RogueMaster/flipperzero-dabtimer | https://github.com/RogueMaster/flipperzero-dabtimer | RogueMaster | Bundle | C | ~39 | 2026-03-04 | unspecified | Active | Clock / timer FAP | N/A |
| 466 | grugnoymeme/flipperzero-StepCounter-fap | https://github.com/grugnoymeme/flipperzero-StepCounter-fap | grugnoymeme | Bundle | C | ~10 | 2026-03-04 | unspecified | Active | Pedometer FAP using Memsic2125 GPIO module | N/A — sensor pattern |
| 467 | JuanJakobo/FlipperZero-Playground | https://github.com/JuanJakobo/FlipperZero-Playground | JuanJakobo | Bundle | C | ~11 | 2025-12-10 | unspecified | Stale | Misc personal FAPs collection | N/A |
| 468 | jblanked/FlipperHTTP-App | https://github.com/jblanked/FlipperHTTP-App | jblanked | Library | C | ~17 | 2026-04-03 | unspecified | Active | New FlipperHTTP **companion app** — successor / consolidator over rows 223–230 | Gap — pairs with row 223 |
| 469 | jblanked/pico-game-engine | https://github.com/jblanked/pico-game-engine | jblanked | SDK | C++ | ~25 | 2026-04-24 | unspecified | Active | Lightweight C++ game engine for embedded LCDs — VGE-class adjacency | N/A — VGE adjunct |
| 470 | sacriphanius/Flipper-Zero-Ducky-Script-Generator | https://github.com/sacriphanius/Flipper-Zero-Ducky-Script-Generator | sacriphanius | Bundle | C | ~16 | 2026-04-08 | unspecified | Active | **On-device** DuckyScript editor / generator | Gap |
| 471 | sacriphanius/Flipper-Zero-IR-Signal-Generator | https://github.com/sacriphanius/Flipper-Zero-IR-Signal-Generator | sacriphanius | Bundle | C | ~24 | 2026-04-24 | unspecified | Active | On-device IR signal generator | Gap |
| 472 | jblanked AIAgent ecosystem note — *(see rows 223–231, 468, 469 + Gemini-Flipper row 240)* | — | jblanked / jamisonderek | n/a | n/a | n/a | 2026 | n/a | n/a | jblanked's FlipperHTTP sub-ecosystem now includes a dedicated companion app row 468 + a portable game engine row 469. Watch jblanked + jamisonderek user pages quarterly per the discovery guidance | n/a |
| 473 | claupper (Wet-wr-Labs) | https://github.com/Wet-wr-Labs/claupper | Wet-wr-Labs | AIAgent | C | ~18 | 2026-04-20 | unspecified | Active | **One-handed agentic remote** for FZ; bundles voice dictation, custom macros, an offline Claude-Code manual | Compete — narrow-scope sibling |
| 474 | FlipperAgent (jonastbrg) | https://github.com/jonastbrg/FlipperAgent | jonastbrg | AIAgent | Python | ~4 | 2026-04-21 | unspecified | Active | "CyberPhysical Agent" for FZ — early-stage Python LLM driver | Compete — early-stage sibling |
| 475 | flipperAgents (DumpySquare) | https://github.com/DumpySquare/flipperAgents | DumpySquare | AIAgent | TypeScript | ~2 | 2026-04-10 | unspecified | Active | TS-based "AI agents to extend Flipper" — narrow scope | Compete — early-stage sibling |
| 476 | flipper-blackhat-skill (Nikolaibibo) | https://github.com/Nikolaibibo/flipper-blackhat-skill | Nikolaibibo | AIAgent | Shell | ~3 | 2026-03-15 | unspecified | Active | Voice-assistant "skill" wrapping FZ commands — early-stage sibling | Compete — early-stage |
| 477 | tworjaga/flipper-rf-lab | https://github.com/tworjaga/flipper-rf-lab | tworjaga | Bundle | C | ~18 | 2026-04-13 | unspecified | Active | RF analysis platform: device fingerprinting, protocol detection, threat modeling, spectrum monitoring | Gap — defensive-leaning |
| 478 | flipper-zero-bw16-r4tkn | https://github.com/rusyln/flipper-zero-bw16-r4tkn | rusyln | AdjacentHW | (mix) | ~71 | 2026-04-19 | unspecified | Active | BW16 dual-band devboard (RTL8720DN — same chip as row 294 `delfyRTL`) variant | Gap — 5GHz add-on lineage |
| 479 | E07xESP32C5 | https://github.com/b1scuitdev/E07xESP32C5 | b1scuitdev | AdjacentHW | (mix) | ~17 | 2026-04-26 | unspecified | Active | Sub-GHz EBYTE E07-433M20S + ESP32-C5 + microSD + GPS module for FZ | N/A — hardware ecosystem |
| 480 | ESP32.Marauder.Double.Barrel.5G.by.ESP32.C5 | https://github.com/HoneyHoneyTeam/ESP32.Marauder.Double.Barrel.5G.by.ESP32.C5 | HoneyHoneyTeam | AdjacentHW | (mix) | ~30 | 2026-04-16 | unspecified | Active | **Double-barrel** ESP32 + ESP32-C5 board with GPS + 433MHz + battery — 2.4 + 5GHz Marauder | Gap — pairs with row 294 |
| 481 | ZeroWave_FlipperZero-BlueJammer | https://github.com/EmenstaNougat/ZeroWave_FlipperZero-BlueJammer | EmenstaNougat | AttackPoC | (mix) | ~57 | 2026-04-25 | unspecified | Active | ESP32 BlueJammer running on the ZeroWave extension board, controlled via FZ FAP | Gap; **Refuse-on-unauth-RF-jamming** |
| 482 | FuckingCheapFlipperZero (GthiN89) | https://github.com/GthiN89/FuckingCheapFlipperZero-DIY-Flipper-zero-The-real-on | GthiN89 | AdjacentHW | C | ~224 | 2026-04-26 | unspecified | Active | **DIY open-hardware Flipper clone** running optimized Momentum on off-the-shelf modules; arduino-skill build | N/A — hardware-target lineage candidate |
| 483 | Hizmos (Hiktron) | https://github.com/Hiktron/Hizmos | Hiktron | AdjacentHW | C | ~109 | 2026-04-26 | unspecified | Active | **HIZMOS** — ESP32-S3-based open-source Flipper-class pentest tool | N/A — emerging alternative-HW lineage |
| 484 | poseidon (GeneralDussDuss) | https://github.com/GeneralDussDuss/poseidon | GeneralDussDuss | AdjacentHW | C++ | ~33 | 2026-04-25 | unspecified | Active | 80+ feature pentesting FW for **M5Stack Cardputer-Adv** — WiFi/BLE/SubGHz/2.4GHz/LoRa/IR/BadUSB/DHCP attacks | N/A — adjacent-HW alternative |
| 485 | Zhilly (sacriphanius) | https://github.com/sacriphanius/Zhilly | sacriphanius | AdjacentHW | C++ | ~48 | 2026-04-21 | unspecified | Active | "AI-powered ESP32 pentesting device" for LilyGO T-Embed CC1101 / T-Deck — RF replay/jam, IR, BadUSB | N/A — adjacent AIAgent + HW |
| 486 | OzInFl/WaveSentinelPublic | https://github.com/OzInFl/WaveSentinelPublic---Squareline-Studio-UI-CC1101---ESP32 | OzInFl | AdjacentHW | C | ~95 | 2026-04-12 | unspecified | Active | WT32-SC01-PLUS host with CC1101 + WiFi + BT — **plays FZ `.sub` files** (downstream pipeline) | N/A — Flipper-pipeline downstream (sister to row 315) |
| 487 | external-cardputer-antenna | https://github.com/henriquesebastiao/external-cardputer-antenna | henriquesebastiao | AdjacentHW | (mix) | ~51 | 2026-03-19 | unspecified | Active | M5Stack Cardputer external-antenna mod guide — boosts sub-GHz reach | N/A — hardware mod |
| 488 | flipper-zero-internal-esp32 (W0rthlessS0ul) | https://github.com/W0rthlessS0ul/flipper-zero-internal-esp32 | W0rthlessS0ul | AdjacentHW | (mix) | ~37 | 2026-04-10 | unspecified | Active | DIY guide: install ESP32 **inside** the FZ shell to drive Marauder without an external devboard | N/A — hardware mod |
| 489 | diy_flipper_zero (lamtranBKHN) | https://github.com/lamtranBKHN/diy_flipper_zero | lamtranBKHN | AdjacentHW | C | ~23 | 2026-04-26 | unspecified | Active | DIY FZ firmware + hardware mapping for STM32WB55 | N/A — DIY hardware lineage |
| 490 | LTX128/Best-setting_user-for-key-fob | https://github.com/LTX128/Best-setting_user-for-key-fob | LTX128 | Bundle | (mix) | ~25 | 2026-04-20 | unspecified | Active | "Best settings" pack for key-fob workflows | N/A — ethically-gray-leaning corpus |
| 491 | Walgreens-SubGHz-FlipperZero (L-o-s) | https://github.com/L-o-s/Walgreens-SubGHz-FlipperZero | L-o-s | AttackPoC | (mix) | ~216 | 2026-04-09 | unspecified | Active | Walgreens customer-service bell SubGHz captures | N/A — corpus, ethically gray (employee disruption) |
| 492 | SubGhz_Cust_Serv (DRA6N) | https://github.com/DRA6N/SubGhz_Cust_Serv | DRA6N | AttackPoC | (mix) | ~503 | 2026-04-24 | unspecified | Active | Library of customer-service bell SubGHz files | N/A — corpus, same ethical class as row 491 |
| 493 | Cus-Assist-Buttons-Flipper-Zero (gam3r999) | https://github.com/gam3r999/Cus-Assist-Buttons-Flipper-Zero | gam3r999 | AttackPoC | (mix) | ~19 | 2026-03-14 | unspecified | Active | More retail customer-service bell `.sub` files | N/A — corpus, same ethical class |
| 494 | FlipperZero-Subghz-DB (Zero-Sploit) | https://github.com/Zero-Sploit/FlipperZero-Subghz-DB | Zero-Sploit | Bundle | Python | ~1.2k | 2026-04-26 | unspecified | Active | Large unsorted SubGHz `.sub` corpus | N/A — corpus, requires per-use audit |
| 495 | nocomp/Flipper_Zero_Badusb_hack5_payloads | https://github.com/nocomp/Flipper_Zero_Badusb_hack5_payloads | nocomp | Bundle | PowerShell | ~1.3k | 2026-04-25 | unspecified | Active | Hak5 BadUSB payloads ported to FZ | N/A — payloads (training data) |
| 496 | FalsePhilosopher/BadUSB-Playground | https://github.com/FalsePhilosopher/BadUSB-Playground | FalsePhilosopher | Bundle | PowerShell | ~657 | 2026-04-25 | unspecified | Active | Active FZ-geared BadUSB playground — sibling to row 38 | N/A |
| 497 | Zarcolio/flipperzero | https://github.com/Zarcolio/flipperzero | Zarcolio | Bundle | PowerShell | ~478 | 2026-04-26 | unspecified | Active | Author's Ducky/BadUSB scripts + companion PS scripts | N/A |
| 498 | grugnoymeme/flipperzero-badUSB | https://github.com/grugnoymeme/flipperzero-badUSB | grugnoymeme | Bundle | Shell | ~362 | 2026-04-25 | unspecified | Active | Curated BadUSB scripts | N/A |
| 499 | grugnoymeme/flipperducky-badUSB-payload-generator | https://github.com/grugnoymeme/flipperducky-badUSB-payload-generator | grugnoymeme | WebSerial | HTML | ~81 | 2026-04-21 | unspecified | Active | Browser GUI for building DuckyScript `.txt` payloads | N/A — host UX |
| 500 | tuconnaisyouknow/BadUSB_passStealer | https://github.com/tuconnaisyouknow/BadUSB_passStealer | tuconnaisyouknow | AttackPoC | PowerShell | ~217 | 2026-04-21 | unspecified | Active | Credential-stealer payload — same refusal class as appendix A4 | **Refuse** without engagement scope; cross-ref appendix A4 |
| 501 | evilvodun/wifi_passwords | https://github.com/evilvodun/wifi_passwords | evilvodun | AttackPoC | Python | ~198 | 2026-04-21 | unspecified | Active | Windows WiFi-password exfil via FZ BadUSB — refusal class | **Refuse** without authorized-recovery scope; cross-ref A4 |
| 502 | A3H1M4SA/Flipper-WiFi-Exfil-BadUSB | https://github.com/A3H1M4SA/Flipper-WiFi-Exfil-BadUSB | A3H1M4SA | AttackPoC | (mix) | ~44 | 2026-04-12 | unspecified | Active | Exfil all SSIDs/passwords to Discord webhook — refusal class | **Refuse**; same as row 502 |
| 503 | kyleschnirring/Flipper-Zero-AWS_Key_Theft | https://github.com/kyleschnirring/Flipper-Zero-AWS_Key_Theft | kyleschnirring | AttackPoC | (mix) | ~27 | 2025-12-23 | unspecified | Stale | macOS BadUSB stealer for AWS keys — explicit-malicious-framing | **Refuse**; cross-ref A4 |
| 504 | Retr0-0Sec/Windows_Exfil | https://github.com/Retr0-0Sec/Windows_Exfil | Retr0-0Sec | AttackPoC | JS | ~21 | 2026-02-13 | unspecified | Active | Windows data-collection + exfil PoC via FZ BadUSB | **Refuse**; cross-ref A4 |
| 505 | Shlucus/FlipperZero-GooglePortal | https://github.com/Shlucus/FlipperZero-GooglePortal | Shlucus | AttackPoC | HTML | ~83 | 2026-04-21 | unspecified | Active | "1:1 realistic Google captive portal" template for EvilPortal | **Refuse** named-brand template per Defensive Spec #3; cross-ref appendix A5 |
| 506 | InfoSecREDD/BadPS | https://github.com/InfoSecREDD/BadPS | InfoSecREDD | CLI | PowerShell | ~124 | 2026-03-30 | unspecified | Active | Host BadUSB payload dev/test/exec launcher — sibling to row 154 (REPG) | N/A — host harness |

## Detection sources

When refreshing this index, query these URLs in order. New repos that appear and are not yet in the table above are candidates for inclusion.

**GitHub topic listings** (sort by stars, then by recently-updated):
- https://github.com/topics/flipperzero
- https://github.com/topics/flipper-zero
- https://github.com/topics/flipperzero-firmware
- https://github.com/topics/flipperzero-app
- https://github.com/topics/flipperzero-fap
- https://github.com/topics/flipper-zero-app
- https://github.com/topics/qflipper
- https://github.com/topics/flipper-zero-tools
- https://github.com/topics/badusb
- https://github.com/topics/duckyscript

**Forks of upstream firmware** (filter by independent identity, not vanity rebuilds):
- https://github.com/flipperdevices/flipperzero-firmware/forks
- https://github.com/DarkFlippers/unleashed-firmware/forks

**Awesome lists to diff against:**
- https://github.com/RogueMaster/awesome-flipperzero-withModules ← most up-to-date
- https://github.com/djsime1/awesome-flipperzero
- https://github.com/Correia-jpv/fucking-awesome-flipperzero ← auto-stat-injected mirror
- https://github.com/123fzero/flipper-zero-awesome
- https://awesome-flipper.com/
- https://git.hackliberty.org/Awesome-Mirrors/awesome-flipperzero ← Forgejo mirror

**Wikis to monitor:**
- https://flipper.wiki/
- https://momentum-fw.dev/wiki

**Prolific-author user pages** (single-dev FAP collections accumulate fastest here):
- https://github.com/jamisonderek?tab=repositories
- https://github.com/jblanked?tab=repositories
- https://github.com/bettse?tab=repositories
- https://github.com/jaylikesbunda?tab=repositories
- https://github.com/CodyTolene?tab=repositories
- https://github.com/geo-tp?tab=repositories
- https://github.com/Firefox2100?tab=repositories
- https://github.com/equipter?tab=repositories
- https://github.com/AloneLiberty?tab=repositories
- https://github.com/MatthewKuKanich?tab=repositories
- https://github.com/luu176?tab=repositories

**Web search queries** (run quarterly):
- `flipper zero firmware fork {YEAR}`
- `flipper zero MCP server` *(AIAgent — fastest-growing category)*
- `flipper zero rust go cli`
- `flipper zero web serial`
- `qFlipper alternatives`
- `awesome flipperzero`
- `flipper zero badusb payloads github`
- `flipper zero arxiv {YEAR}` *(academic)*
- `site:defcon.org "flipper zero"`
- `site:usenix.org "flipper zero"`

**Threat-intel watch sources** (for adversarial appendix):
- https://hackmag.com/security/ — see "flipper-zero-firmwarez" + "flipper-unleashed" coverage
- https://www.bleepingcomputer.com/ — search "Flipper Zero"
- https://www.thyrasec.com/blog/ — BLE attack incident write-ups
- https://www.redhotcyber.com/ — dark-web firmware coverage
- https://upstream.auto/blog/ — automotive-security analysis
- https://blog.flipper.net/ — official Flipper Devices statements / disavowals
- DarkFlippers/unleashed-firmware README — canonical "no premium versions" disavowal

## Refresh procedure

```text
1. Run web search queries (above) and fetch the top GitHub topic pages.
2. For each candidate repo, capture: name, repo URL, author, language,
   stars (rounded), last commit date, license, one-line capability.
3. Diff candidate-list ↔ this table by repo URL. New rows = ecosystem deltas.
4. Update star counts and `Last` dates for existing rows in-place.
5. Re-classify Status: anything with `Last` >2 yr → Archived;
   6–24 mo → Stale; ≤6 mo → Active.
6. For each new entry, set `In PZ?`:
   - inspect docs/catalog/{firmware,apps,attacks,hardware}.md to see if
     the capability is already covered or proposed
   - mark Yes / Partial / Gap / N/A / Compete / Refuse accordingly
7. Sweep the threat-intel watch sources for new public disavowals,
   takedowns, or community callouts. Append to the appendix below.
8. Append a delta summary to docs/catalog/gap-analysis.md if Gap or
   Compete entries surfaced anything material.
```

A future Taskfile target (`task catalog:refresh`) could automate steps 1–4 by scripting the GitHub Search API + a diff against the URL column of this file.

---

## Adversarial / ethically-flagged appendix

**This is a threat-intel index, not an inclusion list.** Entries below are catalogued for defensive awareness — to inform PromptZero's firmware-allowlist Specs, payload-blocklist rules, and refusal policies. URLs to scam/malware/cracked content are deliberately withheld; URLs are included only for **disavowal / takedown / news-coverage sources**.

Ethics tags: **scam** (deceives users) · **malware payload** (ships executable harm) · **ethically gray** (legal but high collateral damage) · **disputed** (community disagrees on classification) · **unverified** (community signal only, no public disavowal located).

### A1. Scam firmware impersonators (paywalled "private/premium" forks)

| name (or handle) | provenance | category-of-concern | ethics tag | public disavowal source | description | PZ implication |
|---|---|---|---|---|---|---|
| **Private-Unleashed 2.0 / "PCFW 2.0"** (KommerZDealer) | GitHub README + dark-web forum cross-listing; URL withheld | Scam firmware impersonator | scam | Pavel Zhovner response: [hackmag.com/news/flipper-unleashed](https://hackmag.com/news/flipper-unleashed); Upstream Security: [upstream.auto/blog/flipper-zero-and-the-dark-web-evolution-of-unleashed-2-0/](https://upstream.auto/blog/flipper-zero-and-the-dark-web-evolution-of-unleashed-2-0/); DarkFlippers README disavowal | $600–$2000 tiered "Unleashed" impersonation, serial-bound, claims rolling-code car bypass; rebadged 10-yr-old vulns per Zhovner. **Public GitHub mirror surfaced 2026-04 at `KommerZDealer/Private-Unleashed-2.0-FlipperZero-Firmware` (~48★) — URL retained-withheld per catalog policy.** | Detect/refuse known SHA256s; warn on user-supplied firmware claiming "Private/Premium Unleashed" branding |
| **flipperc0d3r mirror** (alias) | GitHub + GitLab `git.selfmade.ninja` mirror; URL withheld | Scam firmware re-host | scam | Same Unleashed-team disavowal | Mirror/repackager with "PCFW 2.0 & Quantum FW v3" branding. **2026-04 public GH presence at `flipperc0d3r/Private-Unleashed-2.0-FlipperZero-Firmware` (~318★) — URL retained-withheld per policy.** | Treat as alias of the above; same SHA-list ingest |
| **JohnnyPrimus mirror** | GitHub re-host; URL withheld | Scam firmware re-host | unverified | Same | Third re-host of Private-Unleashed payload; intent unclear | Flag as alias |
| **"fully-unlocked" mirror (Azayzel)** | GitHub fork; URL withheld | Scam firmware re-host (high-fork-velocity) | scam | Same Unleashed-team disavowal | New 2026-Q2 fork: `Azayzel/fully-unlocked-Private-Unleashed-2.0-FlipperZero-Firmware` (~170★, 130 forks) — fork-storming pattern indicates active distribution. URL retained-withheld per policy | Add SHA256 to allowlist-miss block; raise priority on the rule that scans manifest for "Private Unleashed"/"PCFW"/"Quantum" strings |
| **"Daniel + Derrow" sellers** | Named in [redhotcyber.com](https://www.redhotcyber.com/en/post/the-new-flipper-zero-firmware-made-in-darkweb-becomes-the-key-to-every-car/) and [cybersecuritynews.com](https://cybersecuritynews.com/flipper-zero-darkweb-firmware/) | Underground vendor identities | scam | Coverage cited above + Zhovner | Allegedly Russian; ~150 buyers over 2 yr; same product family | Capture handles; refuse any workflow that imports firmware described as "Daniel/Derrow build" |
| **"Quantum FW" / "PCFW" branding (generic)** | Surfaces across repacks | Brand-cluster of scam impersonators | scam | Multiple disavowals above | Catch-all branding used by repackagers to evade single-name takedowns | Spec rule: warn on firmware ZIP whose `update.fuf` manifest contains "Quantum"/"PCFW"/"Private Unleashed" strings |

### A2. Backdoored CFW / FAP — verified cases

| name | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| *(none publicly verified at snapshot date)* | — | — | unverified | — | No public, named case of an upstream-distributed CFW/signed FAP shipping telemetry exfil or USB beaconing surfaced in surveyed sources | Don't fabricate threats. Track this row; revisit each refresh |
| **Flipper-Android-App arbitrary-file write** | Issue [#877](https://github.com/flipperdevices/Flipper-Android-App/issues/877) | Insecure default in *official* tooling | disputed (bug, not malware) | GitHub issue above | Shared-intent cache path trusts attacker-controlled filename | Not adversarial-by-intent; flag "validate version ≥ patched" if PZ federates with it |
| **"Trust the firmware ZIP" supply-chain risk class** (generic) | [hackmag.com/security/flipper-zero-firmwarez](https://hackmag.com/security/flipper-zero-firmwarez); [ragonet.com/flipper-zero-firmware-red-teaming-2025/](https://ragonet.com/flipper-zero-firmware-red-teaming-2025/) | Threat *class*, not a named repo | ethically gray | Per articles | "Malicious modifications, backdoors, keyloggers, or telemetry are all real risks" with dark-web firmware | Spec: refuse `firmware_install` from non-allowlisted SHA256s; require user override + audit log |

### A3. Paywalled "underground" packs (Telegram / dark-web brands)

URLs withheld. Brands captured by handle/label only.

| name (handle/brand) | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **"flipperzero_unofficial" Telegram (and clones)** | t.me handle visible in DarkFlippers README context | Distribution channel for cracked/paid packs | disputed | DarkFlippers README scam warning | Mixes legit Unleashed mirror content with paid-pack adverts | Don't ingest content sourced from Telegram channels; require GitHub provenance |
| **"DarkWeb Unleashed" tier ($600/$1k/$2k/$4k)** | Forum listings reported in [redhotcyber.com](https://www.redhotcyber.com/en/post/the-new-flipper-zero-firmware-made-in-darkweb-becomes-the-key-to-every-car/), [megabits.io 2025-08-26](https://megabits.io/index.php/2025/08/26/flipper-zeros-dark-side-inside-the-underground-trade-turning-a-hacker-s-gadget-into-a-car-thief-s-dream-tool/) | Dark-web commercial firmware tiers | scam + ethically gray | Coverage above | Crypto-payment, serial-locked builds; relay-attack hardware kits at higher tiers | Refuse "tier-locked" or "serial-locked" firmware artifacts |
| **"Premium Sub-GHz car-key packs"** | Megabits + RedHotCyber coverage | Paywalled `.sub` capture databases | ethically gray | Same | Curated rolling-code/keeloq capture sets sold per-region/per-OEM | Refuse `.sub` packs containing per-vehicle data without provenance; audit-log source |
| **"Premium hotel/transit MIFARE pack" category** | TikTok/IG diffusion (e.g. duplicatecard handle); URLs withheld | Paywalled key-dictionary distribution | ethically gray (unverified at repo level) | No formal disavowal | Curated MIFARE Classic key dictionaries scoped to specific hotels/transit systems | Require explicit per-use audit reason ("authorized red team for {target}") |

### A4. Malware-payload corpora dressed as BadUSB

URLs withheld for repos that ship working stealer/ransomware payloads.

| name | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **dransomware** (drapl0n) | GitHub topic search; ducky-script ransomware | Working ransomware payload labelled "BadUSB" | malware payload | Self-described | Userspace file encryption without root via DuckyScript | Payload-validator must `refuse_on_label_match: ["ransomware","encrypt files","lockbit","stealer"]` |
| **F0_BadUsb_wifi_password_stealer** (Lotverp) | GitHub topic search | Credential exfil dressed as BadUSB | malware payload (low-grade) | None — community signal only | Dumps Windows-stored WiFi creds to Flipper SD | Borderline dual-use; require explicit `purpose: authorized-recovery` in workflow |
| **Pico-Ducky-Info-Stealer** (KaazDW) | Pico-Ducky variant, ported to FZ BadUSB | PowerShell info stealer | malware payload | Self-described | Generic Win info stealer payload | Same refusal class |
| **"Mimikatz-dropping" Ducky payloads** (corpus class) | Surfaces in BadUSB-Payloads-style repos | Credential dump payload class | malware payload | Hak5 official corpus README scopes them to "security testing" | Drops + executes Mimikatz / lsass-dump | Detect Mimikatz/Rubeus/SharpHound binary-name strings; require operator confirmation |
| **RedLine / Lumma / Vidar dropper payloads** (threat class) | BleepingComputer reporting; not FZ-specific | Commodity stealer dropper class | malware payload | Threat-class only | Modern info-stealers commonly chained from BadUSB initial access | Maintain stealer-name regex blocklist; refuse + audit |
| **powershell-backdoor-generator** (Drew-Alleman) | GitHub | Persistent backdoor generator with FZ output mode | malware payload (operator-grade) | Self-described | Polymorphic PS reverse-backdoor; targets FZ + Rubber Ducky | Refuse unless workflow declares engagement scope; URL withheld |

### A5. Brand-impersonating phish kits

| name | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **Flipper_Jam** (zer0dayf) | GitHub; URL withheld due to brand-impersonation templates | **Brand-templated** portal kit (Google, Instagram, Facebook, Telegram, Starbucks, McDonald's) | ethically gray + brand-impersonation | Self-described README | Pre-built captive-portal templates impersonating named consumer brands — much higher misuse risk than blank evil-portal | Refuse to deploy named-brand templates without operator-sworn authorization; audit-log brand list |
| **bigbrodude6119/flipper-zero-evil-portal** *(see row 220)* | Public GitHub | Generic evil-portal framework | ethically gray (dual-use, legitimate red-team) | [Cyber Red Cell write-up](https://cyberredcell.nl/flipper-zero-harvesting-credentials-with-evil-portal/) explicitly notes "harvesting credentials this way is illegal" outside authorized testing | Generic captive-portal credential harvester | Catalogued in main index; require `engagement_scope` for any evil-portal flow |
| **Banking phish-kit class** (no named distribution) | — | Threat class | unverified | None | Marauder evil-twin + custom HTML — exists as a class; no named distribution | Treat as threat-class for refusal-policy design |

### A6. Mass-harm BLE Spam variants

| name | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **iOS 17.x crash vector (CVE-2023-42941)** | Original PoC by [Techryptic Sept 2023](https://techryptic.github.io/2023/09/01/Annoying-Apple-Fans/); writeup [ecto-1a.github.io/AppleJuice_CVE](https://ecto-1a.github.io/AppleJuice_CVE/); patched iOS 17.2 — [9to5Mac Dec 2023](https://9to5mac.com/2023/12/15/the-jig-is-up-flipper-zero-devices-can-no-longer-crash-iphones-running-ios-17-2/) | Mass-disruption BLE spam | ethically gray + documented harm | Sources above + [Thyrasec](https://www.thyrasec.com/blog/ble-attacks-and-real-world-consequences/) | Apple-pairing notification flood crashing iPhones/iPads in radius | Patched in iOS 17.2 — historical, but successor variants continue. Refuse `ble_spam_apple_pair` without `target_device_authorized=true` |
| **Xtreme BLE Spam app** (origin) | Xtreme-Firmware action workflow; main-index row 3 | Original distribution channel | disputed (Xtreme archived) | Xtreme repo Actions log + archival | First mainline CFW to ship the iOS-17 crash variant pre-built | Cross-ref row 3 capability column |
| **fl-BLE_SPAM (John4E656F)** *(see row 221)* | Public GitHub | Custom-message BLE spam | ethically gray | None | Configurable BLE spam payloads | Rate-limit + bystander-detection rule (refuse if N>1 non-target devices in range) |
| **Midwest FurFest 2023 incident** | [BleepingComputer "Wall of Flippers" coverage](https://www.bleepingcomputer.com/news/security/wall-of-flippers-detects-flipper-zero-bluetooth-spam-attacks/); Thyrasec | Documented mass-harm event | malware payload (in-use) — collateral on Square POS + insulin pump | Sources above | Conference-scale BLE spam disrupted Square payment terminals + an attendee's insulin-pump BLE control | Reference incident for PZ threat-model docs; justifies bystander-protection refusal |
| **Wall of Flippers (k3yomi)** *(see row 260)* | Public GitHub — *defensive* | Detection tool | n/a (defensive) | [Repo](https://github.com/k3yomi/Wall-of-Flippers) | MAC-prefix-based FZ + BLE-spam detector | Defensive Spec target; promoted to main index |
| **"Transit / stadium mass disruption" claims** | Referenced in [plisio.net](https://plisio.net/cybersecurity/flipper-zero) and Thyrasec; specific events: unverified | Threat class | ethically gray | Above | Anecdotal reports of FZ BLE spam on trains / coffee shops / concerts; no court-confirmed prosecution surfaced | Treat as threat-class for refusal-policy design; do not cite specific venues without verification |

### A7. Aggressive deauth-as-a-service builds

| name | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **Marauder + auto-target builds** (threat class) | Generic — surfaces across forks of `ESP32Marauder` | Mass-deauth automation class | ethically gray | None — class-level signal | Marauder builds packaged with auto-channel-hop + neighbor-AP enumeration + sustained deauth | Cap `deauth_duration` and require `target_bssid` allowlist (no broadcast deauth) |
| **HEX0DAYS/FlipperZero-PWNDTOOLS** *(see row 222)* | Public GitHub | Multi-attack pack incl. deauth | ethically gray | None individually | Catch-all "power wifi/dev stuff" pack | Same deauth-target requirement |
| **FlipWiFi (jblanked)** *(see row 224)* | Public GitHub | Captive portal + scan + **deauth** in one FAP | ethically gray (dual-use) | None | Active maintained multi-tool; deauth + evil portal | Same deauth-target requirement |

### A8. Stalker-tool concerns (FindMy emit)

| name | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **FindMyFlipper (MatthewKuKanich)** *(row 144)* | Public GitHub | FindMy / SmartTag / Tile emit | ethically gray | [Jamie Lord LinkedIn analysis](https://www.linkedin.com/posts/jamie-lord-3564472a4_github-matthewkukanichfindmyflipper-the-activity-7231555588021731328-2Q17): "any determined adversary can cycle through multiple virtual tag identities, completely bypassing the 24-hour alert system" | Dual-use: legit owner-tracking AND a documented anti-stalking-bypass vector | Spec `findmy_emit` must enforce `purpose: authorized-recovery`; refuse identity-rotation flag without elevated audit reason; surface AirGuard cross-ref |
| **"Stalker-variant builds"** | None publicly identified by name | Threat class | unverified | — | Watch for forks that auto-rotate keys | Mark for re-survey |

### A10. Cellular / IMSI-catcher deployment (URLs withheld)

URLs withheld for repos whose primary purpose is subscriber surveillance / unauthorized cellular capture. Detection-side tooling is in main index (rows 327, 328).

| name (or class) | provenance | category-of-concern | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **"FakeBTS / PMM" recipe class** | DC32 / 38C3 talk corpora; URLs withheld | Standalone IMSI-catcher build recipes | malware payload (unauthorized surveillance) | Talk videos (public); operational repos withheld | Pre-built rogue-BTS configs targeting subscriber capture | Refuse to federate any tooling that proxies cellular subscriber identity; do not vendor |
| **"Subscriber-targeting Stingray" forks** | Various; URLs withheld | Operator-grade IMSI-catcher derivatives | malware payload | None publicly disavowed individually | Forks of legitimate research stacks (srsRAN/OpenBTS) tuned for non-consensual capture | Audit any cellular stack import for "subscriber-target" config flags; refuse |
| **iOS jailbreak FZ wakers** | Jailbreak forums; URLs withheld | Jailbreak-dependent FZ RPC wakers | disputed (jailbreak ecosystem) | None | Wake FZ RPC pre-iOS-side restrictions via jailbreak tooling | No clean public repo at snapshot; jailbreak-tool dependency makes ethics rating risky |

### A11. EMV emulator class (URLs withheld)

| name (or class) | provenance | category-of-concern | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **"EMV emulator" forks (multiple)** | GitHub topic search; URLs withheld | EMV terminal emulation framed for payment-fraud | malware payload (payment-card territory) | None publicly disavowed individually | Most public "EMV emulator" repos are payment-fraud framed rather than research-framed | Refuse `nfc_apdu_*` flows targeting EMV PoS/Track2 without explicit `engagement_scope: emv_research`; audit per APDU |

Note: legitimate EMV-research building blocks remain catalogued in the main index — `cardpeek` (row 362), `seader` (row 130), `nfc_apdu_runner` (row 279), `nfc_relay` (row 277). Distinguishing line: the primary purpose of withheld forks is fraud-enabling against cardholders, not protocol research against test cards.

### A12. Operator-grade RKE / vehicle key recovery (URLs withheld for malicious framings)

URLs withheld for repos primarily framed as car-theft enablers. Research-framed equivalents are in main index (rows 175, 269, 270, 312, 313).

| name (or class) | provenance | category-of-concern | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| **RollJam-class derivatives (operator-grade)** | HOPE / DC talks; URLs withheld | RKE rolling-code capture-suppress-replay framed for vehicle theft | malware payload (vehicle theft) | RedHotCyber + Megabits coverage of the broader scene (cited in A1, A3) | Multiple GitHub repos exist; primary purpose is car theft rather than research | Refuse `subghz_capture_replay` against rolling-code targets without `engagement_scope: car_owner_authorized`; audit per replay |
| **BMW/Hyundai/Kia DST40/DST80 extraction forks** | KU Leuven / EYE / Hexway papers + companion code; some demo code public | Transponder break demonstrations | RES/WITHHELD | Academic papers cited above | Primary-purpose-malicious framings withheld; demo code mixed with operational forks | Catalogue research papers as citation sources; refuse extraction tooling without authorized owner |
| **"Single-fob rolling-code 2025 vulns"** | 2025 press coverage; no public clean Flipper FAP at snapshot | Press-described not-yet-public vehicle vulns | unverified | Press only | Several 2025 vehicle-key vulns were demoed but never released as Flipper FAPs | Watch quarterly; ensure refusal-policy covers any future drop |

### A9. Cracked / pirated commercial tooling

| name | provenance | category | ethics tag | source | description | PZ implication |
|---|---|---|---|---|---|---|
| *(no public Iceman/Proxmark cracked-commercial repo surfaced)* | — | — | — | — | Iceman is GPLv3, freely available — no commercial PM3 fork to "crack" exists | None |
| **Amiibo NFC dump repos** (FlipperAmiibo, Dr-SugarBooga/.nfc-Amiibos, Gustavas007/flipper_zero_amiibo, neverfa11ing/FlipperAmiibosNFC, Re3koning/AmiiboFiles) | Public GitHub | Nintendo IP redistribution | ethically gray + IP-disputed | No public Nintendo DMCA against these specific repos at snapshot — Nintendo's DMCAs have targeted Switch *emulators*, not Flipper amiibo dumps | Amiibo `.nfc` dumps; Nintendo holds keys/IP per `unfixed-info.bin` advisory | Catalogued (row 33); add note that broader amiibo redistribution is IP-disputed |
| **"Premium PM3 firmware sale" listings** | RedHotCyber + Megabits coverage | Resale of GPL firmware as "premium" | scam (license violation, not malware) | Coverage above | Same "Daniel/Derrow" type vendors also resell unmodified Iceman PM3 builds at premium | Mostly outside FZ scope; ecosystem-adjacent context |

---

## Defensive Spec recommendations

Concrete additions to PromptZero's `internal/tools/` registry and refusal-policy layer that fall directly out of the threat-intel survey:

1. **Firmware allowlist** — SHA256 allowlist for upstream Unleashed/Momentum/RogueMaster/OFW; refuse + audit on miss. Refuse on manifest containing `Private Unleashed`, `PCFW`, `Quantum`, or "Daniel/Derrow build" strings.
2. **Payload label-blocklist** — refuse DuckyScript whose body matches regex hits for `mimikatz`, `lsass`, `redline`, `lumma`, `vidar`, `lockbit`, `encrypt files`, `ransom`, etc. Require operator override + scope declaration.
3. **Brand-template refusal** — evil-portal flows must declare engagement scope; refuse named-brand impersonation (Google/Instagram/Facebook/Telegram/Starbucks/McDonald's, plus banking-name regex) without elevated authorization.
4. **BLE spam bystander rule** — refuse `ble_spam_*` if scanner shows N>1 non-target devices in range, OR cap duration <30s with mandatory cooldown.
5. **Deauth target requirement** — `wifi_deauth_*` requires `target_bssid` (not broadcast), capped duration, audit per packet-burst.
6. **FindMy-emit elevated reason** — `findmy_emit` requires `purpose: authorized-recovery`; refuse key-rotation flag entirely without separate audit reason; surface AirGuard cross-ref.
7. **Hotel/transit MIFARE provenance** — key dictionaries must declare source provenance; refuse curated per-target packs without engagement scope.
8. **Federation hygiene** — explicitly do NOT federate (MCP or otherwise) with: any "Private/Premium Unleashed" build; any Telegram-sourced firmware; any "tier-locked" / "serial-bound" firmware artifact.
9. **`Wall of Flippers` parity** — implement a defensive `ble_continuity_classify` / `flipper_presence_detect` Spec parallel to k3yomi's tool.
10. **Picopass downgrade detection** — given the `kitsunehunter` HID gist (row 264) + `PicoGen` (row 204) chain, add `iclass_dummy_mac_emulate` as a defensive Spec to detect downgrade attempts in audit logs.
11. **NFC relay engagement gating** — `nfc_relay_run` (proven by `leommxj/nfc_relay` row 277) requires explicit `engagement_scope` per session; audit per APDU; refuse against EMV PoS/Track2 without `engagement_scope: emv_research`.
12. **CAN-bus target allowlist** — `can_inject_*` (proven by `flipper-MCP2515-CANBUS` row 296) requires `engagement_scope: vehicle_owner_authorized` + `vehicle_vin` declaration; audit per frame; refuse Tesla/BMW/Hyundai/Kia VIN-bound flows without owner verification.
13. **SWD/JTAG chipdump audit** — `swd_dump` (proven by `flipper-swd_probe` row 299, `flipper-app-dap-link` row 300, `avr_isp` already in good-faps) requires `purpose: authorized_chipdump`; audit SHA256 of every dump artefact.
14. **POCSAG legal-jurisdiction warning** — `subghz_pocsag_decode` (proven by `flipper-pager` row 271) shows jurisdiction-specific wiretap-law caveat before enabling; require explicit operator acknowledgement.
15. **5GHz regulatory gate** — `wifi_5ghz_*` (proven by `delfyRTL` row 294) checks RegDomain via WiFi devboard; refuse on unlicensed bands (DFS/UNII-2C/UNII-3 in regions where unlicensed TX is prohibited).
16. **Long-range HID reader audit** — `lf_hid_capture_long_range` (proven by `RFID-Gooseneck` row 389) requires authorized-physical-pentest scope; refuse without engagement scope; audit per capture.
17. **TPMS spoof refusal** — `subghz_tpms_spoof` (proven by `TPMS-Flipper` row 342) refuses without authorized-vehicle scope; consider as defensive `tpms_anomaly_detect` peer per v0.8 audit.

## Documented incidents & takedown history

| Date | Event | Source |
|---|---|---|
| 2023-09 | iOS 17 BLE-spam crash PoC published (CVE-2023-42941) | [Techryptic](https://techryptic.github.io/2023/09/01/Annoying-Apple-Fans/) |
| 2023-09 | Midwest FurFest BLE-spam disruption (Square POS, insulin pump) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/wall-of-flippers-detects-flipper-zero-bluetooth-spam-attacks/) / [Thyrasec](https://www.thyrasec.com/blog/ble-attacks-and-real-world-consequences/) |
| 2023-12 | iOS 17.2 patches BLE-spam crash vector | [9to5Mac](https://9to5mac.com/2023/12/15/the-jig-is-up-flipper-zero-devices-can-no-longer-crash-iphones-running-ios-17-2/) |
| 2024-02 | Canada announces FZ import/sale ban (later softened to "restricted use") | [BleepingComputer](https://www.bleepingcomputer.com/news/security/canada-to-ban-the-flipper-zero-to-stop-surge-in-car-thefts/), [EFF response](https://www.eff.org/deeplinks/2024/03/restricting-flipper-zero-accountability-approach-security-canadian-government), [Flipper response](https://blog.flipper.net/response-to-canadian-government/) |
| 2023-04 → ongoing | Brand-impersonation phishing campaigns targeting infosec community (3+ X handles, 2+ fake stores) | [BleepingComputer](https://www.bleepingcomputer.com/news/security/ongoing-flipper-zero-phishing-attacks-target-infosec-community/), [Bitdefender](https://www.bitdefender.com/en-us/blog/hotforsecurity/new-flipper-zero-phishing-campaign-targets-infosec-community), [Malwarebytes](https://www.malwarebytes.com/blog/news/2023/04/fake-flipper-zero-sellers-are-after-your-money) |
| 2025–2026 | Private-Unleashed 2.0 / "PCFW" dark-web ecosystem matures (Daniel/Derrow sellers, ~150 buyers reported) | [RedHotCyber](https://www.redhotcyber.com/en/post/the-new-flipper-zero-firmware-made-in-darkweb-becomes-the-key-to-every-car/), [CybersecurityNews](https://cybersecuritynews.com/flipper-zero-darkweb-firmware/), [Megabits](https://megabits.io/index.php/2025/08/26/flipper-zeros-dark-side-inside-the-underground-trade-turning-a-hacker-s-gadget-into-a-car-thief-s-dream-tool/), [Upstream Security](https://upstream.auto/blog/flipper-zero-and-the-dark-web-evolution-of-unleashed-2-0/) |
| At snapshot | **No named DMCA** by Apple / NXP / HID / Tesla / BMW / Ford / Nintendo against named Flipper repos surfaced. Apple chose CVE patching over legal action; Canada's regulatory action is the closest analogue. | — |

---

## Findings summary

Highlights from the snapshot (full reasoning in agents' raw notes / catalog/gap-analysis.md):

1. **Two flipper-MCP servers already exist** in the wild (rows 155, 156) plus the more complete **`busse/flipperzero-mcp`** (row 257, modular USB+WiFi, Claude Desktop / Cursor compatible) — three direct competitors. PromptZero differentiates on Go + web + audit trail + workflows; consider exposing an MCP-server interface so PromptZero can act as both client and server.
2. **`fztea` (Go, ~391 stars, MIT)** remains the closest in-language analogue — strong port target.
3. **`pyFlipper` + `busse/flipperzero-mcp`** together form the most exhaustive CLI-verb coverage map publicly. Use as a coverage checklist.
4. **`Metroflip` (luu176, GPL-3.0, ~400 stars, active)** is the single biggest gap surfaced in the second pass — multi-protocol on-device transit reader (Bip!, Charliecard, Clipper, Suica, Opal, Navigo, Troika, +9 more). License-clean port candidate.
5. **`Flipper-ARF` (D4C1-Labs)** introduces a new pattern — **focused** automotive-research firmware (not a kitchen-sink CFW). Worth considering for PromptZero's own scope discipline.
6. **`FlipperHTTP` (jblanked, ~600 stars)** is now the foundational HTTP library underneath an entire jblanked sub-ecosystem (FlipWiFi/FlipDownloader/FlipWeather/FlipSocial/FlipWorld/WebCrawler). Treat as a Library, not just one app.
7. **GhostESP-Revival** (`jaylikesbunda/Ghost_ESP` + `ghost_esp_app`, MIT, active) is the live successor to the archived original at row 162 — caught in the second pass.
8. **`PicoGen` + `kitsunehunter` HID iCLASS downgrade gist** together formalize a picopass downgrade workflow that's currently only referenced indirectly in the catalog.
9. **`Wall of Flippers` (k3yomi, row 260)** is the canonical defensive tool; PromptZero should ship parity in `defensive` Specs.
10. **Format converters** (rows 107–110, 196, 197, 199, 201) translate directly to a host-side `internal/flipper/{nfc,ir}/convert` Go package. ~7 quick wins, all license-compatible.
11. **`projectZero` (C5Lab)** introduces **WPA3-SAE overflow** as a 2026 attack vector — not in the existing `attacks.md`. Add to next gap-analysis pass.
12. **`bettercap` (Go, ~19k, GPL-3.0)** is the gold-standard Go reference for 802.11/BLE attack code — vendorable under our AGPL.
13. **`rtl_433`** stays the obvious MCP federation target for sub-GHz decoding.
14. **OpenHaystack + FindMyFlipper** combo is the canonical FindMy-emit recipe — port the host key-derivation to Go, with the anti-stalking-bypass guardrails listed in the appendix.
15. **No public lab.flipper.net repo** — official web-serial flasher is closed source. **`kuba2k2/firefox-webserial` (row 195)** is the strategic dependency that makes any future browser-PromptZero feasible on Firefox.
16. **Kiisu-io** is an emerging hardware-target lineage (Lab401 board) — watch for fork divergence creating a third firmware base alongside Unleashed and Momentum.
17. **Adversarial cluster has matured** since the first pass: `Private-Unleashed 2.0` is now a multi-vendor ecosystem (Daniel/Derrow sellers, "PCFW"/"Quantum FW" branding, ~150 buyers reported, $600–$4000 tiers). Drove the 10 defensive Spec recommendations above.
18. **No public, named backdoored upstream CFW or signed FAP** at snapshot date. The verified "official tool" issue is `Flipper-Android-App` issue #877 (insecure default, not malware).
19. **No named-DMCA** by Apple / NXP / HID / Tesla / Nintendo against named Flipper repos. Apple chose CVE patching; Canada's regulatory action is the closest analogue.
20. **Two prolific authors** drive a disproportionate share of the long tail: **jamisonderek** (rows 232, 233, 236–246, 248) and **jblanked** (rows 223–230) together account for ~25 long-tail entries. Watching their user pages quarterly is high-signal for new ecosystem activity.

### Third-pass deltas (offensive-capability deepening)

21. **`leommxj/nfc_relay` (row 277)** is the single highest-leverage offensive-FAP gap surfaced — a proven two-Flipper NFCA APDU relay. Maps directly to the `nfc_relay_run` Spec listed in v0.8 audit §2b but never had a public reference impl in the catalog. Pair with `SpenserCai/nfc_apdu_runner` (row 279) for full multi-frame APDU coverage.
22. **`ElectronicCats/flipper-MCP2515-CANBUS` (row 296)** fills the CAN-bus capability gap entirely (sniff/log/save/modify/inject/error-detect via EC add-on). Combined with `flipper-canutils` (row 297), `caringcaribou` (row 338), and `python-can` (row 340) it forms a complete vehicle-fuzzing pipeline. Drove the new Defensive Spec #12.
23. **`g3gg0/flipper-swd_probe` (row 299) + `flipper-app-dap-link` (row 300) close `workflow_glitch_chip_dump` data path** — the v0.8 audit §2d flagged this workflow as undefined past "Faultier sweep + Bus Pirate listener." With these two FAPs (auto-detect SWD pinout + Free-DAP/CMSIS-DAP under PyOCD/OpenOCD) plus the `avr_isp` already in `good-faps`, the workflow can now ship.
24. **`portapack-mayhem/mayhem-firmware` (row 315)** contains an explicit **`FlipperTX` app that imports FZ `.sub` recordings to H1/H2/H4M** — the canonical Flipper-pipeline-downstream tool for SDR replay beyond CC1101 reach. PortaPack belongs in the `catalog/hardware.md` Top-7 for the next pass.
25. **`gorebrau/delfyRTL` (row 294)** is the only credible 5GHz attack FAP for Flipper (via RTL8720DN devboard). Drove Defensive Spec #15.
26. **`noproto` family (rows 272, 273, 288, 289)** has emerged as the canonical author for both offensive NFC primitives (FlipperMfkey on-device, Pacs-Pwn iCLASS chain) AND BLE-spam OFW ports. Watch this user page quarterly.
27. **`H4ckd4ddy/flipperzero-sentry-safe-plugin` (row 282, ~1.5k stars, 2023)** is the highest-starred standalone offensive-FAP not previously catalogued — opens any Sentry Safe / Master Lock electronic safe via factory-reset wire pulse (electromechanical, not RF). Drove Defensive Spec #16-equivalent (require physical-pentest scope).
28. **`MaxwellDPS/Flock-You-Android` (row 304)** introduces a new defensive class — counter-surveillance that detects ALPRs / IMSI catchers / trackers across 7 protocols + 75+ device sigs. Build pipeline ships an FZ FAP companion. Belongs alongside `Wall-of-Flippers` (row 260) and `AirGuard` (row 143) in defensive Spec design.
29. **`muylder/Chameleon_Flipper` (row 281)** establishes the federation pattern — a Flipper FAP that drives a Chameleon Ultra peripheral over USB/BLE for attacks the Flipper alone can't run. Generalisable to PromptZero MCP-federation design.
30. **`Ghost6220/keeloq-exploit-toolkit` (row 313)** is the most aggressive new offensive-framing repo since the first pass — explicit "exploitation" branding for KeeLoq rolling-code crypto attacks. Tagged `Refuse-on-unauth` rather than withheld because the underlying KeeLoq research (Eng1n33r lineage row 173) is already widespread.
31. **Confirmed not present as standalone FAPs (despite category demand)**: TPMS spoof (only `Crsarmv7l/TPMS-Flipper` row 342 generates `.sub` files; no on-device TX FAP), FLEX pager decode, DESFire write/exploit, NTAG password recovery, WPS pixie-dust on-Flipper, PEAP/EAP downgrade, DNS/NBNS spoof, BLE pairing MITM, GSM IMSI catcher, GPS spoof FAP, GPIO voltage glitcher FAP, Onity/Saflok/Salto/Assa standalone exploit FAPs (parsers only — Unsaflok/Wouters & Carroll responsible-disclosure stance holds).
32. **Most "offensive FAP" extension is happening *inside firmware monorepos*** (Momentum-Apps row 27, all-the-plugins row 29, RogueMaster wPlugins row 5) rather than as standalone repos. Useful subdir-only entries within those parents: `Rolling Flaws` and `Genie Recorder` inside `jamisonderek/flipper-zero-tutorials` (row 55) — Sammy-Kamkar-style rolling-code research FAPs; `AVR ISP Programmer` inside `Momentum-Apps`; `24Cxx EEPROM programmer` inside `RogueMaster wPlugins`.

### Fourth-pass deltas (long-tail FAP + alternative-HW + new AIAgent siblings)

33. **`i12bp8/TagTinker` (row 393, ~1.2k stars, 2026-04)** opens a brand-new attack-surface class — **Electronic Shelf Label (ESL) research over IR**, based on Furrtek's protocol work. Not previously catalogued; warrants an `ir_esl_*` Spec class.
34. **`0xchocolate/flipperzero-esp-flasher` (row 394, ~609 stars)** removes the PC dependency from Marauder/devboard onboarding entirely — **flash ESP chips directly from the Flipper**. Replaces the `task setup:marauder` host workflow (row 136) on supported boards.
35. **Three independent CC1101 / nRF24 jammer FAPs surfaced** (rows 395–398, combined ~1.4k stars) — `RocketGod-git/flipper-zero-rf-jammer`, `huuck/FlipperZeroNRFJammer`, `W0rthlessS0ul/FZ_nRF24_jammer`, `d1mov/FlipperzeroNRFJammer`. RF jamming is illegal in most jurisdictions (FCC §15.5; UK Wireless Telegraphy Act 2006). Drove a new defensive note (row 400) and a refusal-policy requirement: jurisdiction-specific block in `subghz_jam_*` Specs with operator-authorization + RegDomain check.
36. **`frux-c/uhf_rfid` (row 401, ~313 stars)** extends Flipper into the **UHF RFID 860–960 MHz EPC Gen2 band** via the YRM100 module — an entirely new band class for warehouse/asset-tag research. Add `uhf_rfid_*` Spec class.
37. **`c0d3r-SubGHz/Flipper-Zero-RollJam-Single-Chip-PoC` (row 418)** is the **first credible single-chip RollJam PoC for Flipper** — atomic-replay attacks via TDM on a single CC1101. Supersedes the rougher row 312 PoC; should be cross-referenced from appendix A12 and `subghz_capture_replay` Spec must require `engagement_scope: car_owner_authorized` per Defensive Spec already covered.
38. **Two defensive-framed FAPs surfaced** (`matthewkayne/flipper-access-audit` row 435, `sacriphanius/Flipper-Zero-Ghost-Camera-Detector` row 436) — first explicit defensive-framing apps for access-control audit + IR hidden-camera detection. Both belong alongside `Wall-of-Flippers` (row 260) and `Flock-You-Android` (row 304) in defensive Spec design.
39. **`agentzex/FlipperZero-BadUSB-Wireshark` (row 445)** is the first public Wireshark dissector + DuckyScript reconstructor for FZ/Rubber-Ducky USB-HID traffic — **defensive forensics primitive**. Add to defensive-Spec design.
40. **ElectronicCats trio fills three industrial / IoT bands at once** — `flipper-rs485modbus` (row 409, Modbus RTU / PLC-SCADA), `flipper-SX1262-LoRa` (row 410, LoRaWAN), pairing with the existing `flipper-MCP2515-CANBUS` (row 296). Combined with `SAMS0N1TE/ZeroMesh` (row 457, Meshtastic over LoRa), this completes the LoRa/industrial-protocol picture for FZ.
41. **`SocialSisterYi/T-Union_Master` (row 441)** adds **China Transit-Union (交通联合)** card support — fills a CN-region gap in Metroflip-class transit coverage (row 208).
42. **Three new AIAgent siblings** (rows 473–476: `Wet-wr-Labs/claupper`, `jonastbrg/FlipperAgent`, `DumpySquare/flipperAgents`, `Nikolaibibo/flipper-blackhat-skill`) bring the total LLM-driven Flipper-driver count to **8** across all surveyed implementations (rows 155, 156, 157, 240, 257, 259 + the four new ones). PromptZero remains the only Go + audit-trail + workflows + web implementation; differentiation thesis still holds.
43. **Two emerging "alternative hardware" CFW lineages worth watching** — `KaraZajac/Moon-Firmware` (row 458, XIP flash exec + full BLE + automotive SubGHz) and `Sor3nt/Flipper-Zero-ESP32-Port` (row 460, FZ FW ported to ESP32). Combined with the existing Kiisu lineage (rows 14, 15) this is now **three** non-STM32WB55 firmware bases.
44. **DIY Flipper-clone hardware accelerating** — `GthiN89/FuckingCheapFlipperZero` (row 482, ~224★, Momentum on off-the-shelf modules), `Hiktron/Hizmos` (row 483, ESP32-S3 alt), `GeneralDussDuss/poseidon` (row 484, M5Stack Cardputer-Adv), `lamtranBKHN/diy_flipper_zero` (row 489, STM32WB55 mapping), `W0rthlessS0ul/flipper-zero-internal-esp32` (row 488, ESP32-inside-Flipper mod). PromptZero's serial-transport assumptions should remain device-agnostic to track this lineage.
45. **`OzInFl/WaveSentinelPublic` (row 486)** is a sister-pattern to `mayhem-firmware/FlipperTX` (row 315) — a **WT32-SC01-PLUS host that plays FZ `.sub` files** directly. Confirms `.sub` as the de-facto SubGHz interchange format across non-Flipper hardware; PromptZero's `.sub` codec choices should optimise for ecosystem compatibility, not just Flipper firmware.
46. **`ClusterM/flipper_rc` (row 455)** — first **Home Assistant integration** that emulates IR remotes via FZ. Suggests an `homeassistant_bridge` Spec class for two-way smart-home federation.
47. **Stalker / scam-firmware ecosystem still growing** — appendix A1 added `Azayzel/fully-unlocked-Private-Unleashed-2.0-FlipperZero-Firmware` (~170★, 130 forks, fork-storm pattern) as the fourth confirmed public mirror. Per existing policy URLs remain withheld; SHA256 ingest list should be expanded.
48. **Confirmed not present at fourth-pass snapshot (despite category demand)**: still no public on-Flipper EMV emulator (per appendix A11 policy), no public DESFire write/exploit standalone FAP, no NTAG password recovery FAP, no WPS pixie-dust on-Flipper, no GSM IMSI catcher, no GPS spoof FAP, no GPIO voltage glitcher FAP, no Onity/Saflok/Salto/Assa standalone exploit FAPs.
49. **`pbek/usb_hid_autofire` (row 421)** + **`AGO061/BadBT` (row 452)** — minimal HID-class examples worth using as USB/BLE-HID design references; BadBT in particular extends the BadKB Spec class (row 41) with explicit BLE keyboard delivery.
50. **`uzyn/flipper-bambu` (row 433)** is an independent NFC parser for Bambu Lab filaments, parallel to `jamisonderek/FZBambuFilamentReader` (row 233) — confirms the single-vendor 3D-printer NFC read pattern as ecosystem-stable.

## Cross-references

- Per-protocol/per-primitive deep dives: [`docs/catalog/`](./catalog/)
- Existing PromptZero capability registry: `internal/tools/`
- Audit + roadmap context: [`docs/refactor/v0.8-team-audit.md`](./refactor/v0.8-team-audit.md), [`docs/specs/roadmap.md`](./specs/roadmap.md)
