---
type: reference
created: 2026-04-25T17:00
tags: [catalog, gap-analysis, v0.8, specs]
related: [[firmware]] [[apps]] [[attacks]] [[hardware]] [[v0.8-team-audit]]
---

# Gap analysis — catalogs vs PromptZero Specs

Synthesises the four researcher catalogs (`firmware.md`, `apps.md`,
`attacks.md`, `hardware.md`) against the current Spec inventory and the
existing v0.8 roadmap (`docs/refactor/v0.8-team-audit.md`). Goal: surface
**what the prior audit missed**, not re-list what it already covered.

## Inputs (snapshot 2026-04-25)

| Source | Lines | Inventory |
|---|---|---|
| `docs/catalog/firmware.md` | 748 | 11 firmwares |
| `docs/catalog/apps.md` | 470 | 233 apps surveyed; ~190 with hw primitives |
| `docs/catalog/attacks.md` | 614 | 34 attack entries (2024-2026) |
| `docs/catalog/hardware.md` | 338 | 38 hardware entries |
| `docs/refactor/v0.8-team-audit.md` | 257 | existing roadmap (the floor) |
| `internal/tools/` registry | — | **230 Spec `Name:` registrations / 221 unique** (verified by `grep -rohE 'Name:\s+"[a-z0-9_]+"' --exclude="*_test.go" \| sort -u`) |

## Headline finding

The v0.8 audit covers the **strategic surface** (Phase 1 architecture,
Phase 2 capability themes) very well. The four researcher catalogs
broaden the picture in exactly two ways:

1. **Tactical Spec gaps** the audit didn't enumerate — defensive
   classifiers, forensic-side decoders, and a handful of widely-shipped
   Flipper apps (NFC relay, MagSpoof, Sentry Safe, POCSAG, AVR ICSP /
   SWD).
2. **Two net-new hardware backends** beyond audit §2c —
   **Proxmark3 (Iceman)** and **CatSniffer V3 / Sniffle dongle**.

That is the entire delta. **Diminishing returns set in fast.** Below ~30
items the new findings tail off into stuff already implied by the audit
or out-of-scope by policy. The "Top-30" list at §3 is therefore the
honest ceiling, not a quota.

One **factual correction to a researcher claim**: `firmware.md` §4.2
lists `subghz_chat` as missing. It is **already a Spec**
(`internal/tools/subghz.go:123`). Treat that as a stale finding; the
remaining four firmware-catalog gaps stand.

The **Cuyler36** entry from the original task #7 spec was confirmed
**not a Flipper firmware** by the firmware researcher (their §2.11). It
**does not appear in `docs/refactor/v0.8-team-audit.md`** — the typo
lives only in the task system / earlier draft notes, so no patch to the
audit is required. Recommendation: drop it from any future spec drafts;
no PromptZero detection branch should be added.

---

## 1. Coverage matrix

Every primitive identified in the four catalogs as a row. Columns:

- **Native** — Spec exists today in `internal/tools/`
- **Container-bridge** — wraps a containerised tool (mfoc/mfcuk/hashcat
  pattern) — counts as covered if the bridge is wired
- **Federation** — reachable via `mcpfed` prefix (e.g. `pm3.*`,
  `secsec.*`)
- **Gap** — not covered by any of the above today

✅ = present · ⚠️ = partial / variant · ❌ = missing.
"§2a"/"§2b"/"§2c" cells reference the corresponding row in the v0.8
audit (`docs/refactor/v0.8-team-audit.md`).

### 1.1 NFC / RFID

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| Mifare Classic mfoc / mfcuk / mfkey32 | apps + audit baseline | ✅ `mfoc_attack`, `mfcuk_attack`, `mfkey32_recover` | ✅ | ✅ via pm3 | — |
| Mifare hardnested host-bridge | attacks + audit Q2 | ⚠️ `mifare_hardnested_host` (bridge) | ✅ | ✅ | — |
| Mifare FM11RF08(S) backdoor | attacks #2 | ❌ | — | — | **§2a — already on roadmap** |
| Mifare Classic on-device nested (FlipperNested) | apps top-20 #7 | ❌ | — | — | **§2b** ⟶ `nfc_flippernested_run` |
| Mifare Plus SL1 read | apps top-20 #8 | ❌ | — | — | New gap |
| Mifare Ultralight C 3DES brute (`ulc_brute`) | apps NFC | ❌ | — | — | New gap |
| Mifare Classic UID enumeration brute | apps `uid_brute_smarter` | ❌ | — | — | New gap |
| iClass loclass key recovery | attacks + audit | ✅ `iclass_loclass_recover` | — | ✅ pm3 | — |
| iClass dummy-MAC emulate | attacks #9 | ❌ | — | ✅ pm3 | **NEW vs audit** |
| iClass SE/SEOS downgrade | attacks | ❌ | — | ✅ pm3 | Federation-only by policy |
| HID iClass SE / DESFire via SAM (Seader) | apps top-20 #4 | ⚠️ `loader_seader` (loader-only) | — | — | **§2b** ⟶ `nfc_seader_credential_read` |
| Saflok / dormakaba forgery | attacks + apps top-20 #5 | ❌ | — | — | **§2a** ⟶ `nfc_unsaflok_forge` |
| Metroflip transit cards | apps top-20 #3 | ❌ | — | — | **§2b** ⟶ `nfc_metroflip_*` |
| NFC Magic write Gen1A/2/4 | apps + capabilities | ✅ `loader_nfc_magic` | — | — | — |
| NFC APDU single-frame | baseline | ✅ `nfc_apdu` | — | — | — |
| NFC APDU **script** runner (sequence files) | apps top-20 #14 | ⚠️ `nfc_apdu` (1 frame) | — | — | **NEW vs §2b** ⟶ `nfc_apdu_script_run` |
| NFC raw frame TX | baseline | ✅ `nfc_raw_frame` | — | — | — |
| NFC sniffer (raw-bit) | apps `nfc_sniffer` | ⚠️ `nfc_raw_frame` (synth-only) | — | ✅ pm3 | **NEW** small gap |
| NFC relay (two-Flipper proxy) | apps top-20 #13 | ❌ | — | — | **NEW vs audit** ⟶ `nfc_relay_start/stop` |
| ULC / SEOS BLE-tunnel relay | apps `ulc_relay` | ❌ | — | — | New gap |
| ISO15693-3 writer | firmware §4.2 #4 | ❌ | — | — | **NEW** small gap |
| EMV parse (visa/mc) | firmware §4.2 #3 | ✅ `nfc_emv_decode` (+ `nfc_emv_encode`) — BER-TLV walker + ~80-tag dictionary; `nfc_emv_track2_decode` v0.414 cracks tag 57 (PAN/expiry/service code, Luhn-gated); `nfc_emv_dol_decode` v0.415 walks PDOL/CDOL/DDOL/TDOL (tag,length) lists; `nfc_emv_afl_decode` v0.416 expands tag 94 (SFI/record ranges → READ RECORD list) | — | — | shipped — BER-TLV + Track-2 + DOL + AFL field decode. Cryptogram/online-auth flow deliberately out of scope (needs issuer keys). |
| Wiegand D0/D1 capture + replay | apps top-20 #6 + attacks #6 | ❌ | — | — | **§2b** ⟶ `gpio_wiegand_capture/replay` |
| HID Prox / EM4xxx PACS decode | apps top-20 #15 | ⚠️ `rfid_raw_analyze` | — | ✅ pm3 | **NEW** ⟶ `rfid_pacs_decode` |
| LF EM4100 / T5577 read+write | baseline | ✅ `rfid_*`, `loader_t5577_multiwriter`; offline `em4100_decode` (ID forms) + `em4100_encode` (64-bit frame) + `em4100_frame_decode` v0.417 (parity-validating frame→ID inverse) | — | — | — |
| FDX-B / DCF77 / niche LF synth | apps NFC | ⚠️ `rfid_build` covers EM4100 only | — | — | Low-priority gaps |
| UHF EPC Gen2 (M6E-Nano) | apps `uhf_rfid` | ❌ | — | — | Adjacent-HW gap |
| Mag-stripe wireless emulation (MagSpoof) | apps top-20 #9 | ❌ | — | — | **NEW vs audit** ⟶ `magspoof_emulate` |

### 1.2 Sub-GHz

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| Sub-GHz read/transmit/decode/bruteforce/sweep | baseline | ✅ `subghz_*` family + `loader_*` | — | — | — |
| Sub-GHz protocol classify (ProtoView) | baseline + apps | ✅ `subghz_classify`, `loader_protoview` | — | — | — |
| KeeLoq (decrypt / brute / dictionary) | baseline | ✅ `keeloq_*` family | — | — | — |
| URH decode bridge | baseline | ✅ `urh_decode_sub` | ✅ | — | — |
| RollBack RKE replay (offensive) | attacks + audit Q5 | — by policy — | — | — | Intentional skip |
| RollBack capture-only detect | attacks #5 | ✅ `subghz_rollback_detect` | — | — | shipped v0.386 — offline defensive sequence analyser: flags non-consecutive duplicate rolling codes (key-free replay/RollBack signature; consecutive burst repeats excluded) + counter regressions when decrypted counters are supplied. Observation-not-verdict, no RF/TX. |
| Sub-GHz `chat` verb | firmware §4.2 #2 | ✅ `subghz_chat` | — | — | **researcher claim was stale** |
| TPMS decode (Schrader/Citroën/Renault/Toyota/Ford) | attacks #1 + apps top-20 #2 | ✅ `subghz_tpms_decode` | — | — | shipped v0.360 — Manchester (both conventions/alignments) + CRC-8 disambiguation + 32-bit sensor ID |
| TPMS synth | attacks + apps | ✅ `subghz_tpms_synth` | — | — | shipped v0.377 — offline inverse of `subghz_tpms_decode` ([sensor ID][payload][CRC-8] Manchester frame, round-trip-verified; generation only, no TX). Per-model pressure/temp scaling left to the caller (unverifiable). |
| Tesla VCSEC TPMS anomaly detect | attacks #15 | ⚠️ partial | — | — | `tpms_anomaly_detect` shipped v0.367 — Sub-GHz-side sequence analyser (excess unique sensor IDs vs wheel count + CRC-invalid frames, observation-not-verdict framing). The Tesla VCSEC **BLE-side** malformed-cert angle (CVE-2025-2082) is a separate, still-unshipped primitive. |
| Weather-station 433 MHz decode (LaCrosse/Acurite/Oregon) | apps `weather_station` | ✅ `subghz_weather_decode` (+ `subghz_weather_synth` v0.378, the inverse generator, round-trip-verified) | — | — | shipped v0.361 — LaCrosse TX141TH-Bv2 + Acurite 609TXC (fixed-40-bit, checksum-gated); Oregon/5n1 deferred |
| POCSAG paging decode | apps top-20 #11 | ✅ `subghz_pocsag_decode` (+ `subghz_pocsag_synth` v0.379, the inverse generator with real BCH(31,21), round-trip + idle-codeword verified) | — | — | shipped — sync/idle framing, numeric + alphanumeric, parity check |
| Sub-GHz playlist / scheduler / remote | apps | ✅ `loader_subghz_playlist` | — | — | — (`subghz_scheduler` low-priority) |
| Spectrum analyzer / freq sweep | baseline + apps | ✅ `subghz_freq_sweep`, `loader_spectrum_analyzer` | — | — | — |
| Sub-GHz signal generator | apps | ✅ `loader_signal_generator` | — | — | — |
| LoRa SX126x bridge | apps `LORA_term` | ⚠️ `bruce_lora_scan` (Bruce only) | — | — | New gap if Flipper-LoRa target |
| Sub-GHz jammer-detect | apps `subghz_jammer_detect` | ❌ | — | — | New gap (pairs with rollback_detect) |

### 1.3 BLE / Bluetooth

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| BLE Spam (Marauder backend) | apps + audit | ✅ `wifi_ble_spam` | — | — | — |
| BLE Spam (Flipper-native FAP) | firmware §4.2 #1 | ❌ | — | — | **NEW** small gap (capability bit `HasBLESpam` detected but no Flipper-side handler) |
| BLE FindMy / AirTag emulation | attacks #10 + apps top-20 #1 | ❌ | — | — | **§2b** ⟶ `ble_findmy_emulate` (nRootTag is the strong PoC) |
| nRootTag advertisement spoof | attacks | ❌ | — | — | Subsumed by `ble_findmy_emulate` |
| Apple Continuity classifier (defensive) | attacks #8 | ⚠️ `defense_classify_advertisement` | — | — | **NEW vs audit** ⟶ `ble_continuity_classify` |
| BLE proximity-tracking audit (passive long-running) | attacks BLE | ❌ | — | — | New gap (defensive) |
| BLE 5 connection follow (PHY/CSA hops) | hardware §4 (Sniffle) | ❌ | — | — | Needs CatSniffer/Sniffle backend |
| Stealtooth forced-pairing | attacks | — research-only — | — | — | Out of scope |
| BadKB (Bluetooth-HID BadUSB) | firmware + apps | ✅ via `badusb_*` + `bruce_badusb_run` | — | — | — |

### 1.4 802.11 / WiFi

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| WiFi scan / deauth / beacon-spam / probe / evil-portal | baseline | ✅ Marauder `wifi_*` family (≈70 Specs) | — | — | — |
| WiFi PMKID capture (Marauder) | baseline | ✅ `wifi_sniff_pmkid` | — | — | — |
| WiFi PMKID → hashcat 22000 pipeline | attacks #7 | ✅ native `.hc22000` PMKID writer `wifi_pmkid_hc22000` (v0.390 — pure-Go `WPA*01*…` line builder, anchored on hashcat's published example; removes the hcxpcapngtool shell-out for the clientless-PMKID case) | ✅ hashcat | — | EAPOL (type 02) pcap extraction still via hcxpcapngtool |
| WiFi SSID Confusion (Vanhoef WiSec'24) | attacks + audit §2a | ❌ | — | — | **§2a** ⟶ `wifi_ssid_confusion` |
| WiFi PEAP downgrade audit (CVE-2023-52160) | attacks #13 | ❌ | — | — | **NEW vs audit** ⟶ `wifi_peap_downgrade_audit` |
| WiFi FragAttacks audit (Vanhoef WiSec'25) | attacks #14 | ❌ | ⚠️ via Pineapple+container | — | **NEW vs audit** ⟶ `wifi_fragattacks_audit` |
| Pineapple REST surface | hardware §7 + audit §2c #3 | ❌ | — | — | **§2c #3 — backend pending** |
| GhostESP backend (Apple-spam, Pwnagotchi-friend, RGB) | hardware §1 + audit §2c #4 | ❌ | — | — | **§2c #4** |
| ESP flash / bring-up (`esp_flasher`) | apps WiFi | ❌ | — | — | New gap |

### 1.5 USB / BadUSB / HID

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| BadUSB run / validate / DuckyScript corpus | baseline | ✅ `badusb_*`, `bruce_badusb_run` | — | — | — |
| BadUSB **forensic classifier** (DuckyScript reconstruct from usbmon pcap) | attacks #11 | ✅ `usb_badusb_classify` | — | — | shipped — HID Boot-Protocol report decode → DuckyScript; v0.366 added raw Linux usbmon-capture ingestion (auto-strips per-URB framing). USBPcap (Windows) framing still deferred. |
| USB Rubber Ducky compile-and-drop | hardware §8 + audit §2c #5 | ❌ | — | — | **§2c #5** |
| O.MG Cable / Plug push | hardware §8 | ❌ | — | — | New gap (low priority) |
| Mass storage / MTP / MIDI emulate | apps BadUSB | ❌ | — | — | Niche; low priority |

### 1.6 GPIO / hardware bridges / chip-dump

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| GPIO read/set | baseline | ✅ `gpio_read`, `gpio_set` | — | — | — |
| 1-Wire search | baseline | ✅ `onewire_search` | — | — | — |
| iButton read/write/emulate | baseline | ✅ `ibutton_*` | — | — | host-side `ibutton_decode` (Dallas ROM dissector) + `ibutton_encode` (v0.385 — offline ROM-ID builder, family + 48-bit serial + Maxim CRC-8, round-trip + Maxim AN-27 vector verified) close the offline clone-prep loop |
| Bus Pirate I²C / SPI / UART | baseline | ✅ `buspirate_*` family | — | — | — |
| AVR ICSP programmer / read | apps top-20 #16 | ❌ | — | — | **NEW vs audit** ⟶ `avr_isp_read` (block on `workflow_glitch_chip_dump`) |
| ARM SWD probe / dump | apps top-20 #16 | ❌ | — | — | **NEW vs audit** ⟶ `swd_dump` |
| CMSIS-DAP debug bridge | apps `dap_link` | ❌ | — | — | New gap |
| WCH SWIO flasher | apps GPIO | ❌ | — | — | Niche |
| 8-channel logic analyzer / oscilloscope | apps top-20 #17 | ❌ | — | — | **NEW** ⟶ `gpio_logic_capture` |
| Sentry Safe / Master Lock electronic safe replay | apps top-20 #10 | ❌ | — | — | **NEW vs audit** ⟶ `gpio_sentry_safe_open` |
| Faultier glitch (arm/fire/sweep/disarm) | baseline | ✅ `glitch_*` family | — | — | — (Phase 0 hotfixes #2, #4) |

### 1.7 NRF24

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| NRF24 mousejack / sniff / payload-build / list-targets | baseline | ✅ `nrf24_*` family | — | — | — |
| NRF24 channel scanner / batch / monitor / jammer | apps NRF24 | ⚠️ partial | — | — | Low-priority gaps |

### 1.8 CAN bus / automotive

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| CAN init/sniff/inject/replay/info | baseline | ✅ `canbus_*` family | — | — | Phase 0 hotfix #3 (input validation) |
| CAN-FD sniff | apps top-20 #18 | ❌ | — | — | **NEW** ⟶ `canbus_fd_sniff` |
| UDS-on-DoIP attacks | attacks Auto | ⚠️ via `canbus_replay`; native `uds_decode` (v0.397 — ISO 14229 service / NRC / sub-function / DID decode, offline) | ✅ python-uds | — | Workflow extension (transport/ISO-TP still external) |
| ISO 15118 EVCC / PLC | attacks Auto | ❌ | — | — | Out of scope (PLC HW) |
| DroneID receive | attacks #12 + audit §2a #5 | ❌ | — | — | **§2a + §2c** (blocked on HackRF) |

### 1.9 Firmware introspection / fork detection

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| Per-fork capability bitmap | firmware catalog backbone | ✅ `firmware_introspect` | — | — | — |
| Firmware extract / blob inspect | baseline | ✅ `firmware_extract` (group fix in Phase 0 #5) | — | — | — |
| Adversarial CFW detection (Private-Unleashed 2.0) | firmware §2.12 | ⚠️ implicit via `subghz_rollback_detect` | — | — | Detection-only, intentional |

### 1.10 Hardware backends (existing + missing)

| Backend | Native? | Notes |
|---|:---:|---|
| Flipper (USB-CDC + BLE) | ✅ `internal/flipper/` | — |
| ESP32 Marauder | ✅ `internal/marauder/` | — |
| Bruce (ESP32) | ✅ `internal/bruce/` | — |
| Faultier | ✅ `internal/faultier/` | — |
| Bus Pirate 5 | ✅ `internal/buspirate/` | — |
| HackRF + PortaPack | ❌ | **§2c #1** |
| ChameleonUltra | ❌ | **§2c #2** |
| WiFi Pineapple Mark VII | ❌ | **§2c #3** |
| GhostESP-Revival | ❌ | **§2c #4** |
| USB Rubber Ducky (compile-only) | ❌ | **§2c #5** |
| **Proxmark3 (Iceman)** | ❌ | **NEW vs audit §2c — containerbridge** |
| **CatSniffer V3 / Sniffle dongle** | ❌ | **NEW vs audit §2c — BLE-5 sniffing gap** |
| ChipSHOUTER PicoEMP | ❌ | Honourable mention (complements Faultier) |
| Glasgow Interface Explorer | ❌ | Honourable mention (chip-dump union of BP+GoodFET) |
| CANable v2 (SocketCAN) | ❌ | New native backend would unlock CAN-FD |

---

## 2. De-duplication — gaps already covered by v0.8 audit

These are **already in `docs/refactor/v0.8-team-audit.md`** and are *not*
re-listed in the prioritised gap section below. References use the
audit's own §2a/§2b/§2c/§2d/Q-numbers for cross-link. The catalogs
*confirm* every one of them — none of the audit's Phase 2 picks looks
weakened on second pass.

| Spec / item | Audit anchor | Catalog confirmation |
|---|---|---|
| `mifare_fm11rf08_backdoor` | §2a row 1 | attacks #2 (Quarkslab Aug 2024 — confirmed strongest) |
| `nfc_unsaflok_forge` | §2a row 2 | attacks #3 + apps top-20 #5 |
| `subghz_rollback_detect` | §2a row 3 + Q5 | attacks #5 + firmware §2.12 (adversarial CFW) |
| `wifi_ssid_confusion` | §2a row 4 | attacks #4 (Vanhoef WiSec'24) |
| `dronid_receive` | §2a row 5 | attacks #12 (blocked on HackRF — sequencing right) |
| `nfc_metroflip_*` | §2b | apps top-20 #3 (Metroflip 2026-04 active) |
| `subghz_tpms_decode` + `_synth` | §2b | attacks #1 + apps top-20 #2 — **promote to first-in (S effort, biggest ROI)** |
| `nfc_seader_credential_read` | §2b | apps top-20 #4 |
| `ble_findmy_emulate` | §2b | attacks #10 (nRootTag is the strongest 2025 PoC backing it — stronger than the original audit citation) |
| `gpio_wiegand_capture` + `_replay` | §2b | apps top-20 #6 + attacks #6 |
| `nfc_apdu_run` | §2b | apps NFC — **note: §3 below splits the script-runner variant** |
| `flipperhttp_fetch` + `_post` | §2b | apps `flip_downloader`, `web_crawler`, `flip_telegram` |
| `nfc_flippernested_run` | §2b | apps top-20 #7 |
| HackRF + PortaPack backend | §2c #1 | hardware §3 + §11 #1 |
| ChameleonUltra backend | §2c #2 | hardware §2 + §11 #2 |
| WiFi Pineapple Mark VII backend | §2c #3 | hardware §7 + §11 #4 |
| GhostESP-Revival backend | §2c #4 | hardware §1 + §11 #5 |
| USB Rubber Ducky compile-and-drop | §2c #5 | hardware §8 + §11 #7 |
| `workflow_evil_twin_fullcap` | §2d | attacks 802.11 cluster |
| `workflow_glitch_chip_dump` | §2d | apps GPIO — **note: §3 below names the Specs that block it** |
| `workflow_canbus_replay_capture` | §2d | attacks Automotive |
| `workflow_iclass_pickup` | §2d | apps NFC + attacks iCLASS |
| `workflow_keeloq_capture_and_crack` | §2d | attacks KeeLoq |
| `workflow_apple_continuity_audit` | §2d | attacks BLE |

**Cuyler36** — the audit doc itself does **not** mention this, so no
audit patch is needed. The reference lives only in the task #7
description and the firmware researcher's §2.11 stand-down. Drop it
from any future spec drafts; no detection branch in PromptZero.

---

## 3. Prioritised gap list — top 30 missing capabilities

Scoring: `prevalence × adversarial-leverage / effort`. Effort tags:
**S** ≤ 1 week · **M** 1-3 weeks · **L** 3+ weeks · **XL** ≥ 2 months.
Items already in the audit (§2 above) are excluded — this list is the
**delta** the audit missed.

| # | Spec / capability | Source | Why it ranks | Effort | Pkg / extends |
|---|---|---|---|:---:|---|
| 1 | `nfc_relay_start` + `_stop` (two-Flipper ISO14443A proxy) | apps `nfc_relay`, `ulc_relay` | High adversarial leverage (corp-badge clone-at-distance); apps shipped widely in RM/M; complements `ble_findmy_emulate`. | M | `internal/tools/nfc.go` + dual-target |
| 2 | `gpio_sentry_safe_open` (Sentry / Master factory backdoor) | apps top-20 #10 (`H4ckd4ddy/flipperzero-sentry-safe-plugin`) | Real physical-pentest primitive; tiny GPIO/UART sequence. | S | new `internal/safe/` or `flipper.go` GPIO path |
| 3 | `magspoof_emulate` (mag-stripe T1/T2/T3 wireless coil) | apps top-20 #9 (`zacharyweiss/magspoof_flipper`) | Untouched by audit; complements NFC payment pentest; widely shipped Samy-Kamkar port. | M | new `internal/magstripe/` |
| 4 | `subghz_pocsag_decode` (paging dragnet) | apps top-20 #11, attacks (rtl_433-adjacent) | Universal European paging still alive; fits `subghz_classify` pipeline. | S | extend `subghz_classify` |
| 5 | `subghz_weather_decode` (LaCrosse / Acurite / Oregon 433 MHz) | apps `weather_station` | ✅ shipped v0.361 — LaCrosse TX141TH-Bv2 + Acurite 609TXC, checksum-gated; Oregon/5n1 deferred. | S | `internal/weather/` |
| 6 | `tpms_anomaly_detect` (Tesla VCSEC malformed certs, BLE side) | attacks #15 (CVE-2025-2082) | ⚠️ Sub-GHz-side analyser **shipped v0.367** (excess unique sensor IDs + CRC-invalid frames, on the same wire as `subghz_tpms_decode`). The Tesla VCSEC **BLE-side** malformed-cert primitive (CVE-2025-2082) is still unshipped — needs a BLE classifier. | M | `subghz` + BLE classifier |
| 7 | `wifi_pmkid_capture` (native `.hc22000` writer + hashcat federate) | attacks #7 (hcxdumptool / hashcat 22000) | Closes the loop on Marauder PMKID capture; pure Go, no new HW. | M | `marauder`, future `pineapple` |
| 8 | `ble_continuity_classify` (Apple Continuity dissector) | attacks #8 (furiousMAC) + AppleJuice | Pure decode; pairs with audit's §2d `workflow_apple_continuity_audit`. | M | `marauder` BT pcap, `defense.go` |
| 9 | `iclass_dummy_mac_emulate` (legacy iClass, no MAC keys) | attacks #9 (bettse/Flipper picopass app) | Small change in existing emulation path; opens lab/red-team flows currently PM3-only. | S | `internal/iclass/` |
| 10 | `usb_badusb_classify` (DuckyScript reconstruct from usbmon pcap) | attacks #11 (agentzex Wireshark dissector) | ✅ **shipped** — HID Boot-Protocol report → DuckyScript decode (`internal/usbhid`); v0.366 added raw Linux usbmon-capture ingestion. USBPcap (Windows) framing deferred. | M | `internal/usbhid` |
| 11 | `swd_dump` + `avr_isp_read` (chip-dump Specs) | apps top-20 #16 | **Blocks audit §2d `workflow_glitch_chip_dump`** — without these the workflow has no data path. | M | new `internal/swd/` or extend `buspirate` |
| 12 | `gpio_logic_capture` (8-channel logic analyzer / oscilloscope) | apps top-20 #17 | Pairs with hw_recon workflows; only device-internal scope primitive. | M | extend `buspirate` GPIO sample loop |
| 13 | `nfc_apdu_script_run` (sequence-file APDU runner) | apps top-20 #14 | Audit named `nfc_apdu_run` (single-frame); script-file variant is a separate Spec. | S | extend `nfc.go` |
| 14 | `wifi_peap_downgrade_audit` (CVE-2023-52160) | attacks #13 | Adjacent to SSID Confusion; same hostapd backend; net-new attack-class. | M | future `pineapple` |
| 15 | `wifi_fragattacks_audit` (Vanhoef WiSec'25 follow-up) | attacks #14 | Defensive coverage of FragAttacks remediation status. | L | future `pineapple`, container-bridge |
| 16 | `subghz_jammer_detect` (RSSI floor + dwell heuristic) | apps `subghz_jammer_detect` | Pairs with `subghz_rollback_detect` (§2a #3) — natural sibling; same signal path. | S | extend `subghz` |
| 17 | `canbus_fd_sniff` (CAN-FD framing) | apps top-20 #18 | ✅ offline-decode sibling `canbus_fd_decode` shipped v0.362 — candump grammar + CAN-FD DLC↔length + SAE J1939 PGN; live sniff still TODO. | M | extend `canbus` |
| 18 | `ble_proximity_audit` (long-running passive Find-My / SmartThings flagging) | attacks BLE (Liu et al. USENIX'25) | Defensive complement to `ble_findmy_emulate`; needs Sniffle/CatSniffer. | M | new `internal/sniffle/` |
| 19 | `rfid_pacs_decode` (HID Prox / EM4xxx PACS payload decode) | apps top-20 #15 + attacks #6 | ✅ shipped — decode + the inverse `rfid_pacs_encode` (v0.376: H10301/H10306; v0.420: H10304 + H10302 37-bit, round-trip-verified, generation-only). Closes the reader-cloning loop. Corporate-1000 (35/48-bit) encode still deferred — self-referential/proprietary parity the decoder validates only best-effort. | S | `internal/pacs` |
| 20 | `nfc_iso15693_writer` (HF tag-it / ICODE write) | firmware §4.2 #4 + apps `iso15693_nfc_writer` | Net-new write surface added by Momentum 2025-2026. | S | `nfc.go` |
| 21 | `nfc_emv_parse` (EMV co-branded card decode) | firmware §4.2 #3 + apps | Read-only decode; defensible primitive. | M | `nfc.go` parser |
| 22 | `ble_spam_flipper_native` (Flipper-side BLE spam handler) | firmware §4.2 #1 | Capability bit `HasBLESpam` is detected today but no Flipper-side dispatch — only Marauder side (`wifi_ble_spam`) exists. **Defensive scope: keep classify-only**, do not add offensive TX. | S | `bluetooth.go` (new) — defensive only |
| 23 | `nfc_mfp_sl1_read` (Mifare Plus SL1 read) | apps top-20 #8 | Bridges Classic→Plus SL1 deployments while audit still says "no PoC for SL3". | S | `mifare.go` |
| 24 | `nfc_ulc_brute` (Mifare Ultralight C 3DES brute) | apps NFC `ulc_brute` | Crypto1 sibling; existing `internal/crypto1/` infra applies. | M | `mifare.go` + 3DES |
| 25 | `subghz_lora_recv` (LoRa SX126x for Flipper LoRa add-on) | apps `LORA_term`, `loradar` | Bruce already has `bruce_lora_scan`; Flipper-side is unsupported; new attack class (LoRaWAN replays). | M | new `internal/lora/` |
| 26 | `pm3_*` containerbridge (Proxmark3 Iceman) | hardware §11 #3 — **NEW vs §2c** | Containerbridge exactly the way mfoc/mfcuk are wired today; closes LF-EM4x sniff and HID-downgrade gaps the Chameleon can't reach. | S | new `internal/containerbridge/pm3` |
| 27 | `catsniffer_*` / `sniffle_*` containerbridge | hardware §11 #6 — **NEW vs §2c** | Sole BLE 5 connection-following primitive; Ubertooth replacement; CatSniffer V3 ($95) bundles Sniffle+LoRa+Zigbee. | M | new `internal/sniffle/` |
| 28 | `picoemp_emfi_*` (ChipSHOUTER PicoEMP) | hardware §5 (Bus Pirate-shape) | Cheap EM-FI complement to Faultier ($133); different physics. | M | new `internal/picoemp/` |
| 29 | `glasgow_*` applets (JTAG/SWD/SPI flash dump) | hardware §6 | Best chip-dump union (BP + GoodFET + cheap JTAG); containerbridge to `glasgow` CLI. | L | `internal/containerbridge/glasgow` |
| 30 | `canable_*` (SocketCAN backend, mature `go.einride.tech/can`) | hardware §10 | Cheapest unlock for real automotive Spec set; native Go bindings exist. | M | new `internal/canable/` |

### Honourable mentions (rank 31-40)

Below the line — small gaps, niche surfaces, or duplicates of items
above pending evidence:

- `nfc_amiibo_clone` (RM `amiibo_toolkit`)
- `nfc_dicts_manager` (already covered by `corpora` Spec — keep as is)
- `dcf77_clock_spoof` (LF time-signal synth) — ⚠️ telegram-synth shipped v0.375 (`dcf77_synth`: offline 60-bit minute-telegram generator, BCD + even parity, round-trip-verified against `dcf77_decode`). The long-wave TX stage (actual spoof transmission) remains a separate loader step.
- `ir_raw_decode` (raw infrared timing → protocol) — ✅ shipped v0.413 — the IR analogue of `subghz_decode` and the complement to `ir_decode_file` (which only reads a .ir file's already-parsed entries). Decodes the NEC family (standard / extended / repeat) gated on NEC's address & command bitwise-inverse checksum, Samsung32 (v0.419) gated on its command-byte inverse (addr·addr·cmd·~cmd), and Sony SIRC (12/15/20-bit, v0.418) gated structurally on the 2400µs leader + exact bit count + per-bit timing (no confidently-wrong output); dispatched by leader pulse, every bit tolerance-matched. RC5/RC6 (Manchester) deferred. Offline read, no IR hardware (`internal/ir`).
- `combo_cracker` (3-wheel padlock — niche physical primitive)
- `m2_lin_capture` / `m2_j1850_decode` (Macchina M2 — superset of CANable)
- `ghostesp_pwnagotchi_friend` (rolled into §2c #4 backend Specs)
- `mayhem_pocsag_decode` / `mayhem_aprs_decode` (PortaPack-side
  variants of HackRF Specs — same protocols, different backend)
- `nrf52_sniff_advertising` (custom-FW sub-variant of CatSniffer)
- `wch_swio_flash` (CH32V flasher; niche)
- `bruce_lora_scan` extension to LoRaWAN replay (audit Q4 deferred
  pending shared `esp32backend`)

---

## 4. Recommended additions to the v0.8 roadmap

A PR-able patch for `docs/refactor/v0.8-team-audit.md`. File:line
anchors below reference that file as it stands at HEAD
(`a911fcb` 2026-04-25, 257 lines).

> ⚠️ This section produces a patch only. Do **not** edit the audit doc
> as part of this gap-analysis task — the user applies these inserts.

### 4.1 Insert into §2a (attack Specs) — after line 140

Add three rows below the existing five-row §2a table. Anchor: insert
between `dronid_receive` (line 140) and `### 2b. New Flipper tool Specs`
(line 142):

```markdown
| `tpms_anomaly_detect` | Tesla CVE-2025-2082 BLE VCSEC defensive classifier | Medium |
| `iclass_dummy_mac_emulate` | bettse/Flipper picopass app (2024) | Low |
| `wifi_peap_downgrade_audit` | CVE-2023-52160 wpa_supplicant phase-2 bypass | Medium |
```

Rationale: all three sourced from `attacks.md` Top-15 (rows 9, 13, 15);
all three are 2024-2026 in-window with public PoC and no new hardware.

### 4.2 Insert into §2b (Flipper tool Specs) — after line 153

Add five rows below the existing eight-row §2b table. Anchor: between
`nfc_flippernested_run` (line 153) and `### 2c. New hardware backends`
(line 155):

```markdown
| `nfc_relay_start` + `nfc_relay_stop` | Two-Flipper ISO14443A proxy — apps `nfc_relay`, `ulc_relay` | Medium |
| `magspoof_emulate` | Mag-stripe T1/T2/T3 wireless coil — apps `magspoof_flipper` | Medium |
| `gpio_sentry_safe_open` | Factory-backdoor sequence — apps `flipperzero-sentry-safe-plugin` | Low |
| `subghz_pocsag_decode` | Paging dragnet — apps `pocsag_pager` | Low |
| `nfc_apdu_script_run` | Stored APDU sequence runner — splits from existing `nfc_apdu_run` | Low |
| `swd_dump` + `avr_isp_read` | Chip-dump primitives — apps `swd_probe`, `avr_isp` (blocks §2d `workflow_glitch_chip_dump`) | Medium |
```

Rationale: all six come from `apps.md` Top-20 (#9, #10, #11, #13, #14,
#16) and `firmware.md` cross-cutting gaps. The `swd_dump` row is the
**most consequential**: §2d's `workflow_glitch_chip_dump` is currently
listed without naming the Specs that produce the captured bytes;
without those Specs the workflow has no data path.

### 4.3 Insert into §2c (hardware backends) — after line 163

Add two rows below the existing five-item §2c list. Anchor: between
item 5 (`USB Rubber Ducky`, line 163) and `### 2d. New workflows`
(line 167):

```markdown
6. **Proxmark3 (Iceman)** — `internal/containerbridge/pm3` + ~10 Specs.
   Containerbridge to the `pm3` CLI exactly the way mfoc/mfcuk are
   wired today. Fills the LF EM4x sniff + HID-downgrade gap the
   ChameleonUltra (§2c #2) cannot reach. Pairs with §2d
   `workflow_iclass_pickup`.
7. **CatSniffer V3 / Sniffle dongle** — `internal/sniffle/` (or
   containerbridge to `sniff_receiver.py`) + ~6 Specs. Sole commodity
   tool that follows BLE 5 connections through PHY/CSA hops. Closes
   the gap behind `ble_findmy_emulate` (§2b) and the new
   `ble_proximity_audit` defensive Spec.
```

Rationale: both come directly from `hardware.md` §11 ("Top-7 backends
to add in v0.8"), explicitly marked **NEW** there. Proxmark3 was
omitted from §2c because the original audit treated it as
federation-only; on second pass the containerbridge route is days of
work. CatSniffer/Sniffle was missed entirely; given accelerating BLE
attack research (nRootTag, Stealtooth, BLE proximity-tracking 2025),
the absence of a sniffer backend is a real gap.

### 4.4 Adjust §2d (workflows) — line 168

No insertion; tighten the existing `workflow_glitch_chip_dump` row to
record its dependency on §4.2's new `swd_dump`/`avr_isp_read` Specs.
Suggested replacement for line 170:

```markdown
- `workflow_glitch_chip_dump` — Faultier sweep + Bus Pirate UART
  listener concurrently (depends on `swd_dump` / `avr_isp_read` Specs
  added in §2b)
```

### 4.5 Reprioritise §2b ordering (no insertion, reordering only)

`attacks.md` Top-15 row #1 puts `subghz_tpms_decode` ahead of every
other §2b row on ROI grounds (S effort, ~150 LoC per per-vendor
decoder, no new HW). Recommend moving the existing `subghz_tpms_decode`
row in `docs/refactor/v0.8-team-audit.md` (currently line 147) to the
**top** of the §2b table so sequencing follows ROI, not the original
order. Mechanical reorder; no content change.

### 4.6 Optional: §6 "What NOT to do" minor expansion

Two items from the catalogs warrant explicit no-go calls so future
contributors don't re-research them. Insert after line 251:

```markdown
- **Original Z3BRO Sub-GHz Jammer** — repo 404 since 2025; only
  survives in leaked CFW. Do not implement; use `subghz_jammer_detect`
  (offensive symmetric not in scope).
- **Pacs-Pwn** — original repo 404; lives only in RogueMaster bundle.
  Capability is captured by the `rfid_pacs_decode` Spec
  (gap-analysis §3 row 19); do not chase the standalone PoC.
```

---

## 5. Honest limits of this analysis

- **Volume is misleading.** §3 caps at 30 because below that the gap
  list is a long tail of marginal items (UV meter, Geiger counter,
  niche AC remotes). The **first 12 rows are where the real value is**;
  rows 13-30 are filler that some operator will eventually want.
- **The audit is mostly right.** Of 24 audit Phase-2 rows the catalogs
  reviewed, **0** look weakened on second pass. Two get **stronger**
  citations (`ble_findmy_emulate` ⟵ nRootTag; `mifare_fm11rf08_backdoor`
  ⟵ confirmed Quarkslab strongest 2024 source). The audit's strategic
  shape is sound.
- **One stale researcher claim found.** `firmware.md` §4.2 #2 lists
  `subghz_chat` as a missing handler. It exists at
  `internal/tools/subghz.go:123`. Treat as already-resolved.
- **Cuyler36 typo** lives only in the task system / draft notes; the
  audit doc itself is clean. No audit patch needed.
- **Out-of-scope by policy** (do not gap-flag): RollBack offensive
  replay, Apple BLE-spam offensive, DroneID transmit, KeeLoq
  manufacturer-key replay, Mifare Plus SL3 / DESFire EV2/EV3, 5G
  test-gear (5Ghoul / SNI5GECT / 5G-SPECTOR), TETRA:BURST exploit
  reproduction.
- **What this analysis did not do.** Did not re-verify the four
  catalogs' GitHub URLs (trusting the researchers' 2026-04-25
  fetches). Did not crawl `lab.flipper.net/apps` directly (apps.md §
  ecosystem-health flagged its API as cloudflare-fronted). Did not
  attempt any hands-on hardware verification.

---

## 6. Sources

- `/home/michael/projects/promptzero/docs/catalog/firmware.md`
- `/home/michael/projects/promptzero/docs/catalog/apps.md`
- `/home/michael/projects/promptzero/docs/catalog/attacks.md`
- `/home/michael/projects/promptzero/docs/catalog/hardware.md`
- `/home/michael/projects/promptzero/docs/refactor/v0.8-team-audit.md`
  (HEAD `a911fcb`, 257 lines)
- `/home/michael/projects/promptzero/internal/tools/` Spec registry
  (230 `Name:` registrations / 221 unique;
  `grep -rohE 'Name:\s+"[a-z0-9_]+"' --exclude="*_test.go" | sort -u`
  on 2026-04-25)
- `/home/michael/projects/promptzero/internal/flipper/capabilities.go`
  (per-fork bitmap)
