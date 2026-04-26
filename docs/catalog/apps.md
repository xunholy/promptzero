---
type: reference
created: 2026-04-25T08:30
tags: [catalog, flipper, apps, plugins, ecosystem]
related: [[firmware]] [[hardware]] [[attacks]]
---

# Flipper Zero apps & plugins catalog

Survey of notable Flipper Zero applications/plugins that expose hardware
capabilities, drawn from the four largest ecosystem sources as of
**2026-04-25**:

| Bundle | Repo | Bundled apps surveyed |
|---|---|---|
| `flipper-good-faps` (Official) | <https://github.com/flipperdevices/flipperzero-good-faps> | ~25 |
| `Momentum-Apps` | <https://github.com/Next-Flip/Momentum-Apps> | 245 |
| `all-the-plugins` (xMasterX) | <https://github.com/xMasterX/all-the-plugins> | 68 base + 163 non-catalog |
| `flipperzero-firmware-wPlugins` (RogueMaster) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins> | 638 external |
| `unleashed-firmware` | <https://github.com/DarkFlippers/unleashed-firmware> | 11 main + community |

After dedup the union universe is **774 unique app directories**. This
document indexes the ~190 that expose a hardware capability (read,
clone, emulate, decode, synth, replay, sniff, fuzz, glitch, brute) and
that are therefore relevant to PromptZero Spec coverage. Pure
games/UI/utilities are intentionally omitted unless they expose an
underlying primitive.

## Legend

- **Primitive** — `read | clone | emulate | decode | synth | replay | sniff | fuzz | brute | glitch | jam | exfil | bridge`
- **Firmware origin** — abbreviated: `OFW` Official, `M` Momentum, `RM` RogueMaster, `U` Unleashed, `ATP` xMasterX/all-the-plugins, `STA` standalone (must be sideloaded)
- **Stock-Spec** — coverage in PromptZero's `internal/tools/` registry:
  - `✅ <spec_name>` — primitive covered today
  - `⚠️ <spec_name>` — partial / variant of an existing Spec
  - `❌` — primitive **not** covered; candidate for new Spec
- **Last commit** — upstream repo `pushed_at` where verified;
  `bundled` where vendored without separate upstream;
  `stale (>1y)` for any unmaintained repo
- **Repo URLs** — every link below was HEAD-checked or listed via
  GitHub Contents API. Bundle subtree URLs (e.g. `Momentum-Apps/tree/dev/<app>`)
  are stable as of 2026-04-25.

---

## NFC / RFID

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| Picopass (iClass) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/picopass> | OFW, M, RM, U, ATP | read / emulate / loclass-feed | bundled (M) | ✅ `loader_picopass` + `iclass_loclass_recover` | Loclass key recovery on-host. PromptZero ports the algorithm natively. |
| Seader (HID iClass SE/SEOS/DESFire via SAM) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/seader> | M, RM, ATP | read (SAM-mediated), credential-extract | bundled (M) | ⚠️ `loader_seader` (loader-only, no native SAM bridge) | High-value: SE + SEOS + Crescendo support. New `nfc_seader_credential_read` flagged in v0.8 audit. |
| Metroflip | <https://github.com/luu176/Metroflip> | M, RM | decode (transit cards) | 2026-04-05 | ❌ | Octopus, Suica, Calypso, OPAL, Charliecard, etc. ~15 issuer parsers. v0.8 audit §2b top item. |
| NFC Magic | <https://github.com/flipperdevices/flipperzero-good-faps/tree/dev/nfc_magic> | OFW, M, RM, U, ATP | clone (Gen1A/Gen2/Gen4 magic UID) | 2026-02 | ✅ `loader_nfc_magic` | |
| MFKey32 | <https://github.com/flipperdevices/flipperzero-good-faps/tree/dev/mfkey> | OFW, M, RM, ATP | brute (Mifare Classic auth nonces) | 2026-02 | ✅ `loader_mfkey` + `mfkey32_recover` (native) | |
| Flipper Nested (mfoc-nested on-device) | <https://github.com/AloneLiberty/FlipperNested> | M, RM, U | brute (nested attack) | bundled-only | ⚠️ `mfoc_attack` (host-side); on-device port not exposed | |
| Mifare Fuzzer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/mifare_fuzzer> | M, RM | fuzz (Classic + DESFire APDU) | bundled | ❌ | Generates malformed CMD/DATA, useful pre-`nfc_apdu` |
| NFC APDU Runner | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nfc_apdu_runner> | M, RM | script-run (APDU sequences) | bundled | ⚠️ `nfc_apdu` (single-frame); script runner is new |
| NFC Eink writer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nfc_eink> | M, RM | write (NFC tag-driven Eink) | bundled | ❌ | Niche, but real NFC write primitive |
| NFC Maker | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nfc_maker> | M, RM | synth (NDEF / vCard / WiFi / SMS) | bundled | ⚠️ partial via `nfc_build` |
| NFC Playlist | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nfc_playlist> | M, RM | replay (sequential) | bundled | ❌ |
| NFC RFID detector | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nfc_rfid_detector> | M, RM, ATP | sniff (field-presence) | bundled | ❌ | Uses GPIO field probe |
| NFC Login | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nfc_login> | M, RM | NDEF login flow | bundled | ❌ |
| NFC Comparator | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/.subtrees> | RM | diff (two .nfc dumps) | bundled | ⚠️ `fileformat_diff` (host) |
| NFC MFP Reader | <https://github.com/Next-Flip/Momentum-Apps/tree/dev> | RM | read (Mifare Plus SL1) | bundled | ❌ |
| Amiibo Toolkit | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/amiibo_toolkit> | RM | clone (Amiibo NTAG215 + AES) | bundled | ❌ |
| TagTinker | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/TagTinker> | ATP | edit (NDEF on-device) | bundled | ⚠️ `fileformat_edit` (host) |
| MagSpoof (Flipper) | <https://github.com/zacharyweiss/magspoof_flipper> | M, RM (variant) | synth (mag-stripe wireless emulation) | stale (>1y) | ❌ | Samy Kamkar port; tracks mag-stripe over GPIO coil |
| MagSpoof (Electronic Cats) | <https://github.com/ElectronicCats/magspoof_flipper> | STA | synth (with external Electronic Cats coil) | stale | ❌ | |
| ULC Brute (Mifare Ultralight C) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ulc_brute> | M, RM | brute (3DES auth) | bundled | ❌ | Crypto-1 sibling for MFUL-C |
| ULC Relay | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ulc_relay> | M, RM | relay (BLE NFC tunnel) | bundled | ❌ | Two-Flipper relay attack |
| ULCFkey | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ulcfkey> | M, RM | clone (MFUL-C key import) | bundled | ❌ |
| SaFlip (Saflok) | <https://github.com/aaronjamt/SaFlip> | M, RM | clone (Saflok hotel keys, MFC v3.5) | active | ❌ | Pairs with Unsaflok 2024 disclosure. v0.8 audit §2a item. |
| SeoSplitter / Seos parser | bundled (RM `seos`) | RM | decode (SEOS PACS) | bundled | ⚠️ `loader_seader` |
| Picopass loclass (host) | (PromptZero ships natively) | n/a | recover (iClass SE keys) | n/a | ✅ `iclass_loclass_recover` | Already shipped; we beat the on-device version |
| Mifare Classic UID brute (uid_brute_smarter) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/uid_brute_smarter> | RM | brute (UID enumeration) | bundled | ❌ |
| ISO15693 NFC Writer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/iso15693_nfc_writer> | M, RM | write (ISO15693 tags) | bundled | ❌ | HF tag-it/ICODE writer |
| FDX-B Maker | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/fdxb_maker> | RM, ATP (`fdxb-maker`) | synth (animal microchip 134.2 kHz) | bundled | ❌ | LF biothermo |
| EM4100 Generator | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/em4100_generator> | M, RM, ATP | synth (LF EM4100 ID) | bundled | ⚠️ `rfid_build` covers it |
| T5577 Multi-writer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/t5577_multiwriter> | M, RM, ATP | write (T5577 LF tag) | bundled | ✅ `loader_t5577_multiwriter` |
| T5577 Raw writer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/t5577_raw_writer> | M, RM, ATP | write (raw blocks) | bundled | ⚠️ via `rfid_write` |
| Simultaneous RFID Reader (UHF) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/simultaneous_rfid_reader> | M, RM | read (UHF EPC Gen2 via M6E-Nano module) | bundled | ❌ | Needs UHF reader module — adjacent HW |
| UHF RFID | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/uhf_rfid> | M, RM | read/write (UHF EPC) | bundled | ❌ |
| iButton Converter | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ibutton_converter> | M, RM, ATP | decode (key formats) | bundled | ⚠️ `fileformat_*` |
| Wiegand reader/dumper | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/wiegand> | ATP, RM | sniff (D0/D1 over GPIO) | bundled | ❌ | v0.8 audit §2b: `gpio_wiegand_capture/replay` |
| RFID Beacon | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/flipper_rfidbeacon> | ATP | emulate (LF beacon loop) | bundled | ⚠️ `rfid_emulate` |
| GS1 RFID Parser | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/gs1_rfid_parser> | RM | decode (GS1 EPC) | bundled | ❌ |
| MagicBand Plus | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/magicband_plus> | RM | decode (Disney MagicBand+) | bundled | ❌ | Niche but well-known |
| MiBand NFC writer | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/miband_nfc_writer> | RM | write (Xiaomi MiBand NFC) | bundled | ❌ |
| NFC Sniffer (proprietary frame logger) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/nfc_sniffer> | RM | sniff (raw-bit) | bundled | ⚠️ `nfc_raw_frame` (synth, not sniff) |
| NFC Relay | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/nfc_relay> | RM | relay (Flipper-to-Flipper) | bundled | ❌ | Powerful — proxy ISO14443A frames |
| NFCurl (HTTP from NDEF) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/nfcurl> | RM | exfil (URL via NDEF read) | bundled | ❌ |
| NFC Dictionary Manager | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/nfc_dicts_manager> | RM | management (dict files) | bundled | ⚠️ `corpora` |
| Crypto Dictionary | <https://github.com/Next-Flip/Momentum-Apps/tree/dev> | RM | management (crypto1 dicts) | bundled | ⚠️ `corpora` |
| HID Cookie / HID Exfil | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/hid_cookie> | RM | exfil (HID over NFC) | bundled | ❌ |
| GateKeeper (HID Prox decode) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/gatekeeper> | RM | decode (HID Prox / EM4xxx) | bundled | ⚠️ `rfid_raw_analyze` |
| Pacs-Pwn (HID PACS replay) | <https://github.com/noproto/Pacs-Pwn> (404 — folded into RM bundle) | RM | replay (PACS) | bundled-only | ❌ | Original repo unavailable; living in RM |

---

## Sub-GHz

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| Sub-GHz (built-in) | OFW | OFW, all | read/emulate (CC1101) | n/a | ✅ `subghz_*` family | Baseline OFW; PromptZero wraps |
| Sub-GHz Bruteforcer | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/subghz_bruteforcer> | M, RM, U | brute (fixed-code OOK) | bundled | ✅ `loader_subghz_bruteforcer` + `subghz_bruteforce` |
| Sub-GHz Playlist | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/subghz_playlist> | M, RM, ATP | replay (queued .sub) | bundled | ✅ `loader_subghz_playlist` |
| Sub-GHz Playlist Creator | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/subghz_playlist_creator> | M, RM | synth (build .sub list) | bundled | ⚠️ `subghz_build` |
| Sub-GHz Remote (multi-button) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/subghz_remote> | M, RM, ATP | replay (remote-style) | bundled | ⚠️ |
| Sub-GHz Scheduler | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/subghz_scheduler> | M, RM | replay (cron-style) | bundled | ❌ |
| Sub-GHz Toolkit | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/subghz_toolkit> | RM | synth + tools | bundled | ⚠️ |
| Spectrum Analyzer (jolcese fork) | <https://github.com/jolcese/flipperzero-firmware/tree/spectrum/applications/spectrum_analyzer> | M, RM, ATP, U | sniff (RSSI sweep) | bundled | ✅ `loader_spectrum_analyzer` + `subghz_freq_sweep` |
| Sub-GHz Spectrum (subghz_spectrum) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/subghz_spectrum> | RM | sniff | bundled | ⚠️ |
| Sub Analyzer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/sub_analyzer> | M, RM | decode (.sub introspect) | bundled | ⚠️ `subghz_classify` |
| Sub Dup / Flipper Sub Dup | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/flipper_sub_dup> | ATP, RM (as `sub_dup`) | clone (one-shot capture+replay) | bundled | ⚠️ via `subghz_receive`+`subghz_transmit` |
| Sub-GHz Bruteforce (tobiabocchi corpus) | <https://github.com/tobiabocchi/flipperzero-bruteforce> | STA (corpus) | corpus (pre-rolled brute files) | active | ⚠️ `corpora` ingest |
| ProtoView | <https://github.com/antirez/protoview> | M, RM, ATP, U | decode (raw signal classifier) | active | ✅ `loader_protoview` + `subghz_classify` |
| Weather Station | <https://github.com/flipperdevices/flipperzero-good-faps/tree/dev/weather_station> | OFW, M, RM, ATP | decode (433 MHz sensors) | 2026-02 | ❌ | LaCrosse/Acurite/Oregon parsers |
| TPMS Reader | <https://github.com/wosk/flipperzero-tpms> | M, RM, ATP | decode (Schrader/Renault/Citroën/Toyota TPMS) | active | ❌ | v0.8 audit §2b: `subghz_tpms_decode` |
| TPMS Synth (Crsarmv7l) | <https://github.com/Crsarmv7l/TPMS-Flipper> | STA | synth (TPMS .sub) | active | ❌ | Pairs w/ Tesla CVE-2025-2082 |
| Esubghz Chat | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/esubghz_chat> | M, RM, ATP, U | bridge (encrypted chat over Sub-GHz) | bundled | ✅ `subghz_chat` |
| Signal Generator | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/signal_generator> | M, RM, ATP | synth (CW / OOK arbitrary) | bundled | ✅ `loader_signal_generator` |
| Subghz Signal Generator | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/subghz_signal_generator> | ATP, RM | synth | bundled | ⚠️ |
| Pocsag Pager | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/pocsag_pager> | M, RM, ATP, U | decode (POCSAG paging) | bundled | ❌ | Real adversarial primitive (paging dragnet) |
| LoRa Term / LoRa Relay | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/LORA_term> | ATP, RM | bridge (LoRa SX126x) | bundled | ⚠️ `bruce_lora_scan` (Bruce backend, not Flipper-LoRa module) |
| Loradar | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/loradar> | RM | sniff (LoRa) | bundled | ❌ |
| HC-11 modem | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/hc11_modem> | M, RM | bridge (HC-11 433 MHz UART) | bundled | ❌ |
| Tesla FSD (TPMS+door) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/tesla_fsd> | RM | replay (Tesla key fob) | bundled | ❌ | Adversarial (auto-pwn) |
| Flipper Tesla Mod | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/flipper_tesla_mod> | ATP | replay (charge port open) | bundled | ❌ |
| Flipsignal (FlipBoard signal) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flipboard_signal> | M | replay (FlipBoard hardware) | bundled | ❌ | FlipBoard add-on, niche |
| RollJam PoC (educational) | <https://github.com/d4rks1d33/Flipper-Zero---RollJam-PoC> | STA | model (state-machine only) | active | ❌ | Display-only PoC, no RF action |
| RollBack (dark-web "Private-Unleashed 2.0") | not on GitHub | leaked CFW | replay (rolling-code resync) | unmaintainable | ❌ | v0.8 audit calls for `subghz_rollback_detect` |
| Rolling Flaws | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/rolling_flaws> | M, RM, ATP | analyze (KeeLoq/HCS) | bundled | ✅ `keeloq_*` family |
| Sub-GHz Jammer Detect | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/subghz_jammer_detect> | RM | sniff (RSSI floor + dwell heuristic) | bundled | ❌ | Pairs with v0.8 detect-RollBack |
| Sub-GHz Jammer (Z3BRO; CFW-only) | <https://github.com/Z3BRO/Flipper-Zero-Sub-GHz-Jammer> (404 — taken down) | leaked CFW | jam | unmaintainable | ❌ | Mention only — not implementable in PromptZero |
| Frequency Analyzer (built-in) | OFW | OFW, all | sniff | n/a | ✅ |
| Frequency Analyzer Ext | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/freq_analyzer_ext> | ATP | sniff (extended) | bundled | ⚠️ |
| FMF→sub | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/fmf_to_sub> | M, RM | decode (Funny .fmf to .sub) | bundled | ❌ |
| Genie Recorder | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/genie-recorder> | ATP | record (Genie garage) | bundled | ⚠️ part of `subghz_decode` |
| GeoCache (NRF24 + freq utils) | (RM bundle) | RM | utility | bundled | ⚠️ |
| FlipperATM | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/FlipperATM> | ATP | display | bundled | ❌ skip (no real HW) |
| Allstar Firefly | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/allstar_firefly> | ATP | radio (Allstar amateur) | bundled | ❌ | Amateur-radio control |
| ESubGHz Chat (built-in) | OFW | OFW | bridge | n/a | ✅ |

---

## Infrared

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| Infrared (built-in) | OFW | OFW, all | read/transmit/decode | n/a | ✅ `ir_*` family | |
| XRemote | <https://github.com/kala13x/flipper-xremote> | M, RM, ATP | replay/synth (universal IR) | 2026-03-15 | ⚠️ `ir_universal_list` covers some |
| IR Remote | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ir_remote> | M, RM, ATP | replay | bundled | ✅ |
| Xbox Controller (IR) | <https://github.com/gebeto/flipper-xbox-controller> | M, RM, ATP | synth (Xbox One IR) | 2025-08-01 | ✅ via `ir_transmit` |
| IR Intervalometer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ir_intervalometer> | M, RM | synth (camera trigger) | bundled | ✅ |
| IR Scope | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ir_scope> | M, RM, ATP | sniff (timing visualization) | bundled | ⚠️ |
| IR Decoder | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/ir_decoder> | RM | decode | bundled | ✅ `ir_decode_file` |
| IR Blaster | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/ir_blaster> | RM | synth (high-power) | bundled | ⚠️ |
| IR Transfer | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/ir_transfer> | RM | bridge (file via IR) | bundled | ❌ |
| IR Signal Generator | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/ir_signal_generator> | RM | synth (raw timings) | bundled | ⚠️ `ir_transmit_raw` |
| IR Bruteforcer (tv-b-gone style) | OFW (`ir_bruteforce`) | OFW | brute | n/a | ✅ `ir_bruteforce` |
| Hitachi AC Remote | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/hitachi_ac_remote> | M, RM | synth (AC vendor codeset) | bundled | ⚠️ |
| Mitsubishi AC Remote | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/mitsubishi_ac_remote> | M, RM | synth | bundled | ⚠️ |
| Midea AC Remote | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/midea_ac_remote> | M, RM | synth | bundled | ⚠️ |
| Cross Remote | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/cross_remote> | M, RM | synth (mixed IR/SubGHz) | bundled | ❌ |
| FlipIRFreq | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/flipIRFreq> | ATP | analyze (IR carrier freq) | bundled | ❌ |
| TV-B-Gone (universal off) | OFW (`ir_universal_list`) | OFW | brute | n/a | ✅ |

---

## BadUSB / USB

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| BadUSB (built-in) | OFW | OFW, all | run (DuckyScript) | n/a | ✅ `badusb_*` family + `bruce_badusb_run` |
| Bad USB Pro | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/bad_usb_pro> | RM | run (DuckyScript v2 + variables) | bundled | ⚠️ `badusb_run` covers script-run; pro adds vars |
| Mass Storage | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/mass_storage> | M, RM, ATP | emulate (USB-MSD from .img) | bundled | ❌ |
| MTP | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/mtp> | M, RM | emulate (Media Transfer Protocol) | bundled | ❌ |
| HID App (consumer keys) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/hid_app> | RM | emulate (HID multi-class) | bundled | ⚠️ `bt_hci_info`+`run_payload` |
| USB Consumer Control | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/usb_consumer_control> | M, RM | emulate (media keys) | bundled | ⚠️ |
| USB MIDI | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/usb_midi> | M, RM | emulate (MIDI device) | bundled | ❌ |
| Mouse Jiggler | <https://github.com/MuddledBox/flipperzero-firmware/tree/Mouse_Jiggler/applications/mouse_jiggler> | RM, ATP | run (anti-screensaver) | stale (>1y) | ⚠️ `bruce_badusb_run` payload |
| BC Scanner Emulator | <https://github.com/polarikus/flipper-zero_bc_scanner_emulator> | RM, ATP | emulate (HID barcode scanner) | stale | ❌ |
| USB HID Autofire | <https://github.com/pbek/usb_hid_autofire> | RM, ATP | run (auto-clicker) | stale | ⚠️ |
| Vulnerability Scanner (BadUSB script) | <https://github.com/MarkCyber/BadUSB> | corpus | scan (DuckyScript payload) | stale | ⚠️ corpus-only |
| HID File Transfer | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/hid_file_transfer> | RM, ATP | exfil (raw HID Tx) | bundled | ❌ |
| HID Cookie | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/hid_cookie> | RM | exfil (browser cookies) | bundled | ❌ |
| Flipper Wedge | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flipper_wedge> | M, RM | run (BLE-bridged HID) | bundled | ❌ |
| AirMouse / VGM Air Mouse | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/airmouse> | M, RM, ATP | emulate (mouse over IMU) | bundled | ❌ |
| XInput | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/xinput> | M, RM | emulate (Xbox gamepad) | bundled | ❌ |
| Flipboard Keyboard | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flipboard_keyboard> | M | run (HID hardware add-on) | bundled | ⚠️ |

---

## Bluetooth / BLE

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| BLE Spam | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ble_spam> | M, RM | spam (Apple/Android/Windows + Samsung) | bundled | ✅ `wifi_ble_spam` (via Marauder) — Flipper-side missing |
| BLE Spam OFW (deprecated) | <https://github.com/noproto/ble_spam_ofw> | STA | spam | stale (2023-12) | ⚠️ |
| FindMyFlipper (AirTag emu) | <https://github.com/MatthewKuKanich/FindMyFlipper> | M, RM, STA | emulate (Apple FindMy / Samsung SmartThings) | 2025-04-01 | ❌ | v0.8 audit §2b: `ble_findmy_emulate` (Critical risk). OpenHaystack-compatible. |
| Continuity (passive sniff) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/continuity> | RM | sniff (Apple Continuity advertisements) | bundled | ⚠️ `defense_classify_advertisement` |
| BLE Scanner | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/ble_scanner> | RM | sniff (BLE adv) | bundled | ⚠️ |
| BLE Killer | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/ble_killer> | RM | jam (connection oriented) | bundled | ❌ |
| Evil BLE | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/evil_ble> | RM | spam + spoof | bundled | ⚠️ |
| BT Trigger | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/bt_trigger> | M, RM | replay (camera-shutter HID) | bundled | ❌ |
| Claude Remote BLE | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/claude_remote_ble> | ATP | bridge (LLM tool over BLE) | bundled | ❌ | Note: pre-existing project, unrelated to Anthropic |
| BT HID Kodi | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/bt_hid_kodi> | ATP | emulate (Kodi HID) | bundled | ⚠️ |
| YuriCable | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/yuricable> | RM | emulate (BLE OMG cable) | bundled | ❌ |
| Eth Troubleshooter (mDNS over USB-eth) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/eth_troubleshooter> | M, RM, ATP | scan (LAN discovery) | bundled | ⚠️ via Marauder |

---

## iButton / 1-Wire

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| iButton (built-in) | OFW | OFW, all | read/write/emulate | n/a | ✅ `ibutton_*` |
| iButton Converter | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ibutton_converter> | M, RM, ATP | decode (Cyfral/Metakom/Dallas) | bundled | ⚠️ |
| Wire Tester | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/wire_tester> | M, RM | utility (1-Wire bus probe) | bundled | ⚠️ `onewire_search` |
| Key Copier (LF physical) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/key_copier> | M, RM | clone | bundled | ⚠️ |

---

## GPIO / external HW modules

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| GPIO (built-in) | OFW | OFW, all | read/set | n/a | ✅ `gpio_read`/`gpio_set` |
| Sentry Safe | <https://github.com/H4ckd4ddy/flipperzero-sentry-safe-plugin> | M, RM, ATP | replay (factory backdoor seq) | 2025-07-11 | ❌ | Adversarial: opens any Sentry/Master safe |
| GPS NMEA | <https://github.com/ezod/flipperzero-gps> | M, RM, ATP | read (UART NMEA) | 2025-02-04 | ⚠️ `marauder_nmea` (Marauder backend) |
| Unitemp | <https://github.com/quen0n/unitemp-flipperzero> | M, RM, ATP | read (DHT/BMP/HTU/DS18B20) | 2026-03-19 | ⚠️ `loader_unitemp` |
| Servo Tester | <https://github.com/mhasbini/ServoTesterApp> | M, RM, ATP | synth (PWM) | stale | ⚠️ `gpio_set` |
| HC-SR04 (ultrasonic ranger) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/hc_sr04> | M, RM, ATP | read (echo time) | bundled | ❌ |
| Flipper Scope (oscilloscope) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/oscilloscope> | M, RM | sniff (1-MSPS ADC) | bundled | ❌ | Companion to logic analyzer |
| Logic Analyzer | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/logic_analyzer> | RM | sniff (8-ch capture) | bundled | ❌ | Adjacent to Bus Pirate |
| AVR ISP Programmer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/avr_isp> | M, RM, ATP | bridge (ICSP flashing) | bundled | ❌ | Real chipdump primitive |
| SWD Probe | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/swd_probe> | M, RM, ATP | bridge (ARM SWD) | bundled | ❌ | Pairs with `glitch_*` workflow for chip dump |
| WCH SWIO Flasher | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/wch_swio_flasher> | RM | flash (CH32V SWIO) | bundled | ❌ |
| DAP Link | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/dap_link> | M, RM, ATP | bridge (CMSIS-DAP debug) | bundled | ❌ | Plug-and-play J-Link analog |
| SPI Flash Dump / SPI Mem Manager | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/spi_mem_manager> | M, RM, ATP | dump (SOIC-8 SPI flash) | bundled | ✅ `loader_spi_mem_manager` + `buspirate_spi_dump` |
| SPI Terminal | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/spi_terminal> | M, RM | bridge (raw SPI) | bundled | ⚠️ `buspirate_*` |
| 24Cxx EEPROM programmer | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/24cxxprog> | RM | dump (I²C EEPROM) | bundled | ⚠️ `buspirate_i2c_scan` |
| Coffee EEPROM | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/coffee_eeprom> | ATP | dump (coffee-machine EEPROM) | bundled | ⚠️ |
| I²C Tools | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/i2ctools> | M, RM, ATP | scan (I²C bus) | bundled | ✅ `buspirate_i2c_scan` / `i2c_scan` |
| I²C Explorer | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/i2c_explorer> | RM | bridge | bundled | ⚠️ |
| INA Meter (current/voltage) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ina_meter> | M, RM, ATP | read | bundled | ❌ |
| Geiger | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/geiger> | M, RM | read (CPM counter) | bundled | ❌ |
| UV Meter (AS7331) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/uv_meter_as7331> | M | read | bundled | ❌ |
| Lightmeter | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/lightmeter> | M, RM, ATP | read | bundled | ❌ |
| CO2 Logger | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/co2_logger> | M, RM | read | bundled | ❌ |
| Cyborg Detector (RF/EMF) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/cyborg_detector> | M, RM | sniff (broadband RF) | bundled | ❌ |
| Lidar Emulator | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/lidar_emulator> | M, RM | emulate | bundled | ❌ |
| LD Toypad Emulator (LEGO Dimensions) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ldtoypad> | M, RM, ATP (`ld_toypad_emulator`) | emulate (NTAG215 toypad) | bundled | ❌ |
| Pokémon Trading | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/pokemon_trading> | M, RM | emulate (Game Boy serial) | bundled | ❌ |
| Malveke GB Cartridge / Camera / Photo | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/malveke_gb_cartridge> | M, RM | bridge (Malveke add-on) | bundled | ❌ | Hardware add-on family |
| Mayhem Camera / Marauder / NannyCam | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/mayhem_camera> | M, RM | bridge (Mayhem boards) | bundled | ❌ | Mayhem hardware addon |
| Camera Suite | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/camera_suite> | M, RM, ATP | read (ESP32-CAM via UART) | bundled | ❌ |
| Flipper Black Hat | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flipper_blackhat> | M | bridge (offensive add-on board) | bundled | ❌ |
| Cli Bridge | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/cli_bridge> | M, RM | bridge (host CLI ↔ Flipper UI) | bundled | ⚠️ `flipper_raw_cli` covers the inverse |
| UART Terminal | <https://github.com/cool4uma/UART_Terminal> | M, RM, ATP, U | bridge (UART) | active | ✅ `loader_uart_terminal` + `buspirate_uart_bridge` |
| UART Sniff | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/uart_sniff> | RM | sniff | bundled | ⚠️ |
| UBlox (GPS) | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/ublox> | ATP | read (UBX) | bundled | ⚠️ |
| MH-Z19 (CO2 over UART) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/mh_z19> | RM | read | bundled | ❌ |
| RCWL-0516 (microwave radar) | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/rcwl_0516> | RM, ATP | read | bundled | ❌ |
| MagSafe / NFC pin tester (Malveke pin test) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/malveke_pin_test> | M | utility | bundled | ❌ |
| GPIO Reader / Explorer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/gpio_explorer> | M, RM | utility | bundled | ✅ |
| GPIO Badge / Controller | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/gpio_badge> | M | output | bundled | ✅ |

---

## NRF24 / 2.4 GHz

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| NRF24 Mousejacker | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nrf24mousejacker> | M, RM, ATP | inject (HID over NRF24) | bundled | ✅ `loader_nrf24mousejacker` + `nrf24_mousejack_start` |
| NRF24 Sniff | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nrf24sniff> | M, RM, ATP | sniff (Promiscuous) | bundled | ✅ `nrf24_sniff_start` |
| NRF24 Scan | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nrf24scan> | M, RM, ATP | scan (channel) | bundled | ⚠️ |
| NRF24 Channel Scanner | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nrf24channelscanner> | M, RM, ATP | scan | bundled | ⚠️ |
| NRF24 Batch | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/nrf24batch> | M, RM, ATP | replay | bundled | ❌ |
| NRF24 Tool | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/nrf24tool> | ATP | utility | bundled | ⚠️ |
| NRF24 Monitor | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/nrf24monitor> | RM | sniff | bundled | ⚠️ |
| NRF24 Jammer (fz_nrf24_jammer) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/fz_nrf24_jammer> | RM | jam | bundled | ❌ |

---

## WiFi (devboard / ESP32 add-ons)

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| WiFi Marauder companion | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/wifi_marauder_companion> | M, RM, ATP, U | scan/deauth/beacon-spam (Marauder front-end) | bundled | ✅ entire `wifi_*` family |
| WiFi Scanner | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/wifi_scanner> | M, RM, ATP | scan (devboard ESP) | bundled | ✅ |
| Evil Portal (bigbrodude) | <https://github.com/bigbrodude6119/flipper-zero-evil-portal> | M, RM, ATP | phish (captive portal) | 2024-07-26 | ✅ `wifi_evil_portal_start/stop` + `evil_portal_template_pick` |
| Flipper Evil Portal (variant) | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/flipper_evil_portal> | ATP | phish | bundled | ⚠️ |
| Ghost ESP companion | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/ghost_esp> | M, RM, STA | scan/spam/deauth (GhostESP firmware) | bundled | ❌ | v0.8 audit §2c: GhostESP backend |
| Ghost ESP App | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/ghost_esp_app> | ATP | scan/spam | bundled | ⚠️ |
| Ghost ESP (origin firmware) | <https://github.com/Spooks4576/Ghost_ESP> | STA | firmware | archived 2025-04 | ⚠️ | Use Ghost-ESP-Revival fork |
| Wardriver | <https://github.com/Sil333033/flipperzero-wardriver> | M, RM, ATP | scan + log (ESP32+GPS) | active | ⚠️ `marauder_gps_*` |
| WiFi Deauther | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/wifi_deauther> | M, RM, ATP | deauth | bundled | ✅ `wifi_deauth` |
| ESP Flasher | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/esp_flasher> | M, RM, ATP | flash (ESP firmware over UART) | bundled | ❌ | We could ship `esp_flash` Spec |
| ESP8266 Deauth | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/esp8266_deauth> | M, ATP | deauth (8266 backend) | bundled | ⚠️ |
| ESP32 Gravity | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/esp32_gravity> | RM | offensive WiFi (Mana, KARMA) | bundled | ❌ |
| FlipWifi / Flip WiFi | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_wifi> | M, RM | scan + WPS attack | bundled | ⚠️ |
| Evil BW16 | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/evil_bw16> | RM | spam (RTL8720 BW16 backend) | bundled | ❌ |
| Portal of Flipper | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/portal_of_flipper> | RM | phish | bundled | ⚠️ |
| FlipperPwn | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/flipperpwn> | RM | scan + handshake | bundled | ⚠️ |
| WiFi Map | <https://github.com/Next-Flip/Momentum-Apps/tree/dev> | RM, ATP | viz (wardrive db) | bundled | ❌ |

---

## CAN bus / automotive

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| CAN Tools | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/can_tools> | M, RM, ATP | sniff/inject | bundled | ✅ `canbus_*` family |
| CAN Commander | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/can_commander> | M, RM, ATP | inject (preset frames) | bundled | ✅ `canbus_inject` |
| CAN Bus Attack | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/can_bus_attack> | RM | replay/fuzz | bundled | ⚠️ `canbus_replay` (no fuzz yet) |
| CAN FD | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/can_fd> | RM | sniff (CAN-FD framing) | bundled | ❌ | Newer 2.0+ standard, FlexCAN |
| CAN Transceiver | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/can_transceiver> | RM | utility | bundled | ⚠️ |
| Flipper Tesla Mod (charge port) | (above) | RM | replay | bundled | ❌ |
| VIN Decoder | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/vin_decoder> | ATP | decode (VIN→year/make) | bundled | ❌ |
| Voyah Password (gen) | <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/voyah_password> | RM | synth (Voyah service code) | bundled | ❌ |
| Ford Radio Codes | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/fz_fordradiocodes> | ATP | decode | bundled | ❌ |

---

## Pentest / utility (HW-relevant)

| Name | Repo | Firmware origin | Primitive | Last commit | Stock-Spec? | Notes |
|---|---|---|---|---|---|---|
| U2F (built-in) | OFW | OFW, all | sign (HID U2F) | n/a | ❌ | Real-world FIDO key fallback |
| Flipper Authenticator (TOTP) | <https://github.com/akopachov/flipper-zero_authenticator> | M, RM, ATP | sign (RFC6238) | 2025-05-19 | ❌ |
| FlipBIP (BIP-39 wallet) | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/FlipBIP> | M, ATP | sign (offline crypto wallet) | bundled | ❌ |
| Passy (password store) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/passy> | M, RM | store | bundled | ❌ |
| Flip Crypt | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_crypt> | M, RM | crypto | bundled | ⚠️ `crypto_store_key` |
| Combo Cracker | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/combo_cracker> | M, RM, ATP | brute (3-wheel padlock) | bundled | ❌ | Physical-pentest |
| WCH SWIO Flasher | (above) | RM | flash | bundled | ❌ |
| DCF77 Clock Spoof | <https://github.com/xMasterX/all-the-plugins/tree/dev/non_catalog_apps/dcf77_clock_spoof> | ATP | synth (LF time signal) | bundled | ❌ | Time-source spoofing |
| Multi Fuzzer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/multi_fuzzer> | M, RM | fuzz (multi-protocol) | bundled | ❌ |
| Sub-GHz Bruteforce (tobiabocchi corpus) | (above) | corpus | corpus | active | ⚠️ |
| BPM Tapper | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/bpmtapper> | M, RM, ATP | utility | bundled | ❌ skip |
| Tasks (todo) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/tasks> | M | utility | bundled | ❌ skip |
| Flipper Share (BLE file XFR) | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flipper_share> | M, RM, ATP | bridge | bundled | ❌ |
| Flip Downloader | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_downloader> | M, RM | bridge (HTTP→file via FlipperHTTP) | bundled | ❌ | v0.8 audit §2b: `flipperhttp_fetch/post` |
| Web Crawler | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/web_crawler> | M, RM | exfil (URL crawl over FlipperHTTP) | bundled | ❌ |
| Flip Telegram | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_telegram> | M, RM | bridge | bundled | ❌ |
| Flip Trader | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_trader> | M | bridge (price API) | bundled | ❌ skip |
| Flip Weather | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_weather> | M, RM | bridge | bundled | ❌ skip |
| Flip Library | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_library> | M, RM | bridge (book search) | bundled | ❌ skip |
| Flip Social | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_social> | M | bridge | bundled | ❌ skip |
| Flip TDI | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/flip_tdi> | M, RM, ATP | bridge (FT232 CDC) | bundled | ⚠️ |
| Mass Storage / MTP | (above) | M, RM | emulate | bundled | ❌ |
| Hex Editor / Hex Viewer | <https://github.com/Next-Flip/Momentum-Apps/tree/dev/hex_editor> | M, RM, ATP | utility (file edit) | bundled | ⚠️ `fileformat_edit` |

---

## Top-20 missing primitives

Ranked by **(adversarial impact × ecosystem prevalence)** — i.e. apps
that have shipped widely on Momentum/RogueMaster, expose a real
hardware capability, and have **no existing PromptZero Spec coverage**.
Each row identifies (1) the app(s), (2) the primitive, (3) the
PromptZero package the new Spec(s) would extend.

| # | Primitive | Anchoring app(s) | Why it ranks high | Extends PromptZero pkg |
|---|---|---|---|---|
| 1 | **AirTag / FindMy emulation** (Apple FindMy + Samsung SmartThings) | FindMyFlipper (MatthewKuKanich), v0.8 audit §2b `ble_findmy_emulate` | Highest stalking-class abuse pattern of 2024-26; ecosystem-wide BLE adv flooding; trivially deployable. | `internal/marauder` (BLE adv) → new `internal/ble/findmy/` |
| 2 | **TPMS decode + synth** (Schrader, Citroën, Renault, Toyota, Ford) | wosk/flipperzero-tpms, Crsarmv7l/TPMS-Flipper, M `tpms_reader` | Huge install base; pairs with Tesla CVE-2025-2082; tells operators what cars are around. | `internal/flipper` Sub-GHz proto pipeline → `subghz_tpms_decode`, `subghz_tpms_synth` |
| 3 | **Transit-card decode** (Octopus, Suica, Calypso, OPAL, Charliecard, Clipper) | Metroflip (luu176, 2026-04 active) | Pure decode (no emul/clone) — defensible; 15+ issuer parsers ready to port. | `internal/tools/nfc.go` family → `nfc_metroflip_<region>` |
| 4 | **HID iClass SE / SEOS via SAM** | Seader (Momentum), aaronjamt SaFlip | Modern HID corporate badges (post-iClass); SAM-mediated diversification. v0.8 audit §2b. | `internal/tools/iclass.go` + new SAM workflow → `nfc_seader_credential_read` |
| 5 | **Saflok hotel-key forge** (Unsaflok 2024) | aaronjamt/SaFlip | Headlines 2024-26; 3M+ vulnerable hotel locks; existing Mifare Classic write infra suffices. | `internal/tools/mifare.go` + KDF table → `nfc_unsaflok_forge` |
| 6 | **Wiegand capture + replay** (D0/D1 over GPIO) | xMasterX/all-the-plugins `wiegand` | Universal physical-pentest primitive — every PACS reader speaks Wiegand. v0.8 audit §2b. | `internal/tools/canbus.go` (similar GPIO sniff pattern) → `gpio_wiegand_capture/replay` |
| 7 | **Mifare Classic on-device nested (Flipper Nested)** | AloneLiberty/FlipperNested (vendored RM/M) | Lets the Flipper crack MFC keys without a host — eliminates `mfoc_attack` round-trip for field use. | `internal/tools/mifare.go` → host-orchestrated `nfc_flippernested_run` |
| 8 | **Mifare Plus SL1 read** | RogueMaster `nfc_mfp_reader` | Bridge gap to MIFARE Plus deployments; SL1 is still classic-equivalent. | `internal/tools/mifare.go` → `nfc_mfp_sl1_read` |
| 9 | **Mag-stripe wireless emulation (MagSpoof)** | zacharyweiss/magspoof_flipper, ElectronicCats variant | Real adversarial TX of T1/T2/T3 over GPIO coil; complementary to NFC. | new `internal/magstripe/` → `magspoof_emulate` |
| 10 | **Sentry Safe / Master Lock electronic safe replay** | H4ckd4ddy/flipperzero-sentry-safe-plugin (active) | Factory-backdoor sequence opens any Sentry/Master safe; real-world physical-pentest. | `internal/flipper` GPIO/UART → `gpio_sentry_safe_open` |
| 11 | **Pocsag/paging decode** | M `pocsag_pager` | Paging dragnet still alive in Europe; FCC/Ofcom-relevant decode primitive. | `internal/flipper` Sub-GHz → `subghz_pocsag_decode` |
| 12 | **Weather-station 433 MHz decode** (LaCrosse, Acurite, Oregon) | OFW `weather_station` | Real-world decode primitive; pairs with TPMS in `subghz_classify` pipeline. | `internal/flipper` Sub-GHz proto → `subghz_weather_decode` |
| 13 | **NFC relay (two-Flipper proxy)** | RM `nfc_relay`, M `ulc_relay` | Enables full ISO14443A relay attacks; corp-badge cloning at distance. | `internal/tools/nfc.go` + dual-target → `nfc_relay_start/stop` |
| 14 | **NFC APDU script runner** | M `nfc_apdu_runner` | Beyond single-frame `nfc_apdu`; full APDU sequence files (ISO7816 dialogues). | `internal/tools/nfc.go` → `nfc_apdu_script_run` |
| 15 | **HID Prox / EM4xxx PACS decode** | RM `gatekeeper`, noproto Pacs-Pwn (vendored) | Companion to Wiegand; LF reader-cloning baseline. | `internal/tools/rfid.go` → `rfid_pacs_decode` |
| 16 | **AVR ICSP + ARM SWD bridging** | M `avr_isp`, M `swd_probe`, M `dap_link` | Chip-dump primitive; pairs directly with Faultier glitching workflow. v0.8 §2d `workflow_glitch_chip_dump` blocked on this. | `internal/buspirate` SWD or new `internal/swd/` → `swd_dump`, `avr_isp_read` |
| 17 | **Logic analyzer / oscilloscope (8-ch / 1 MS)** | M `oscilloscope`, RM `logic_analyzer` | Sole device-internal scope primitive; pairs with hw_recon workflows. | `internal/buspirate` (similar GPIO sample loop) → `gpio_logic_capture` |
| 18 | **CAN-FD sniff** | RM `can_fd` | `canbus_*` covers classic 2.0; FD is current-gen automotive (incl. Tesla). | `internal/canbus` → `canbus_fd_sniff` |
| 19 | **GhostESP backend Specs** | M `ghost_esp`, ATP `ghost_esp_app` | v0.8 audit §2c #4: alternate ESP32 backend with KARMA/Mana/PMKID; complements Marauder/Bruce. | new `internal/ghostesp/` → ~12 Specs |
| 20 | **FlipperHTTP fetch + post** | M `flip_downloader`, M `web_crawler`, M `flip_telegram` | v0.8 audit §2b: generic HTTP from Flipper unlocks many bridge scenarios (exfil, IFTTT, on-device LLM). | `internal/flipper` HTTP wrapper → `flipperhttp_fetch`, `flipperhttp_post` |

### Honourable mentions (rank 21-30)

These didn't make the top-20 because they are partial overlaps with
existing Specs or have lower ecosystem prevalence, but are still
worth tracking:

- **POCSAG synth** (out-of-scope adversarial; capture-only is rank 11)
- **NFC sniffer (raw-bit)** — RM `nfc_sniffer`
- **Apple Continuity classifier** — RM `continuity` (defense-leaning; v0.8 §2d `workflow_apple_continuity_audit`)
- **EvilCrowRF firmware target** — h-RAT bridge (alt RF backend)
- **Allstar Firefly** (Allstar amateur-radio link control)
- **GS1 EPC / UHF Gen2 stack** (`uhf_rfid`, `simultaneous_rfid_reader`) — adjacent HW
- **DCF77 time-signal synth** (xMasterX `dcf77_clock_spoof`) — LF time-spoof
- **3-wheel padlock combo cracker** (`combo_cracker`) — niche but real physical primitive
- **DAP-Link CMSIS-DAP target debugger** — chip-dump companion for ARM
- **W5500 LAN analyser** — Ethernet pentest add-on

---

## Ecosystem health observations

- **Bundle dominance**: 90 % of the apps surveyed live as subtrees in
  Momentum-Apps / all-the-plugins / RogueMaster rather than at a
  per-app upstream. The bundle maintainers carry the long tail.
- **Active maintainers (≥1 commit in last 90 days)**: luu176
  (Metroflip + Saflip-adjacent), kala13x (XRemote), aaronjamt (SaFlip),
  MatthewKuKanich (FindMyFlipper), wosk (TPMS), quen0n (unitemp).
- **Common stale patterns**: standalone repos from 2022-23
  (mothball187/flipperzero-nrf24, MuddledBox forks, MarkCyber/BadUSB)
  are vendored into RM/M and continue to ship even though upstream is
  dead.
- **Adversarial-tilt repos taken down**: the historical
  Z3BRO/Sub-GHz-Jammer and various rolljam PoCs return 404 — they
  survive only inside leaked CFW images. PromptZero's audit-of-RF
  posture (capture-only `subghz_rollback_detect`) is the right call.
- **Catalog API**: the official `catalog.flipperzero.one` is
  cloudflare-fronted and its `/api/v0` endpoints all 404 from a plain
  HTTP client — front-door scraping requires a browser session.
  `lab.flipper.net/apps` is the user-facing equivalent. Bundle
  enumeration via GitHub Contents API is the practical dataset.

## What the v0.8 audit §2b missed

The audit listed 8 high-priority new Flipper Specs. Versus this
broader survey, items that the audit **did not call out** but are
top-20 here:

1. **NFC relay (two-Flipper proxy)** — listed only implicitly via
   `ulc_relay`. Cross-bundle `nfc_relay` is more general and
   higher-impact.
2. **MagSpoof** — entirely absent from the audit, despite being a
   real adversarial primitive in M and RM and pairing with payment
   pentest scenarios.
3. **Sentry Safe replay** — absent; standalone H4ckd4ddy app is widely
   shipped.
4. **POCSAG decode** — absent; `subghz_classify` doesn't reach paging
   protocols.
5. **NFC APDU script runner** — `nfc_apdu_run` is in the audit, but
   the `*_script_run` variant for stored APDU sequences was not split
   out.
6. **AVR ICSP / SWD chip-dump primitives** — these are *implicitly*
   needed for `workflow_glitch_chip_dump` (audit §2d) but the audit
   did not list the underlying Specs (`swd_dump`, `avr_isp_read`).

These six should be folded into Phase 2b before sequencing
`workflow_*` items that depend on them.

## Sources audit

Every link in the tables above falls into one of three classes:

1. **Bundle subtree URL** (`Next-Flip/Momentum-Apps/tree/dev/<app>`,
   `xMasterX/all-the-plugins/tree/dev/<sub>/<app>`,
   `RogueMaster/flipperzero-firmware-wPlugins/tree/main/applications/external/<app>`) —
   verified against the GitHub Contents API listing performed
   2026-04-25 (file `/tmp/momentum-apps.txt`, `/tmp/atp-base.txt`,
   `/tmp/atp-noncat.txt`, `/tmp/rm-unique.txt`).
2. **Standalone upstream** — verified by HTTP HEAD request to the
   exact URL on 2026-04-25; only 200/301 responses retained.
3. **Repos returning 404 in 2026** — explicitly flagged in their row
   ("404 — folded into RM bundle", "404 — taken down") rather than
   linked broken.

No app on this list was added without one of the three confirmations.
