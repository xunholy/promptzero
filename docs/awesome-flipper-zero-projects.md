---
name: Awesome Flipper Zero — ecosystem project index
description: Flat, diffable index of every Flipper-Zero-adjacent project on GitHub and the open web — one row per repo. Snapshot 2026-04-26 (second-pass discovery + threat-intel appendix added).
type: reference
created: 2026-04-26T00:00
tags: [catalog, flipper, ecosystem, market-analysis, threat-intel]
related: [[catalog/README]] [[catalog/firmware]] [[catalog/apps]] [[catalog/attacks]] [[catalog/hardware]] [[catalog/gap-analysis]]
---

# Awesome Flipper Zero — ecosystem project index

A **flat, sortable index** of every Flipper-Zero-adjacent project (firmwares, bundles, host tools, libraries, mobile apps, attack PoCs, adjacent hardware, awesome lists, wikis, AI agents, defensive tools, academic research) discovered as of **2026-04-26**. A second discovery pass on this date added long-tail legitimate entries (rows 171–268) plus an **Adversarial / ethically-flagged appendix** (separate table, URLs withheld for malware/scam/cracked categories per the catalog policy on `Private-Unleashed 2.0`).

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
| **Private-Unleashed 2.0 / "PCFW 2.0"** (KommerZDealer) | GitHub README + dark-web forum cross-listing; URL withheld | Scam firmware impersonator | scam | Pavel Zhovner response: [hackmag.com/news/flipper-unleashed](https://hackmag.com/news/flipper-unleashed); Upstream Security: [upstream.auto/blog/flipper-zero-and-the-dark-web-evolution-of-unleashed-2-0/](https://upstream.auto/blog/flipper-zero-and-the-dark-web-evolution-of-unleashed-2-0/); DarkFlippers README disavowal | $600–$2000 tiered "Unleashed" impersonation, serial-bound, claims rolling-code car bypass; rebadged 10-yr-old vulns per Zhovner | Detect/refuse known SHA256s; warn on user-supplied firmware claiming "Private/Premium Unleashed" branding |
| **flipperc0d3r mirror** (alias) | GitHub + GitLab `git.selfmade.ninja` mirror; URL withheld | Scam firmware re-host | scam | Same Unleashed-team disavowal | Mirror/repackager with "PCFW 2.0 & Quantum FW v3" branding | Treat as alias of the above; same SHA-list ingest |
| **JohnnyPrimus mirror** | GitHub re-host; URL withheld | Scam firmware re-host | unverified | Same | Third re-host of Private-Unleashed payload; intent unclear | Flag as alias |
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

## Cross-references

- Per-protocol/per-primitive deep dives: [`docs/catalog/`](./catalog/)
- Existing PromptZero capability registry: `internal/tools/`
- Audit + roadmap context: [`docs/refactor/v0.8-team-audit.md`](./refactor/v0.8-team-audit.md), [`docs/specs/roadmap.md`](./specs/roadmap.md)
