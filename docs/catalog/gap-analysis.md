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
| EMV parse (visa/mc) | firmware §4.2 #3 | ✅ `nfc_emv_decode` (+ `nfc_emv_encode`) — BER-TLV walker + ~80-tag dictionary; `nfc_emv_track2_decode` v0.414 cracks tag 57 (PAN/expiry/service code, Luhn-gated); `nfc_emv_dol_decode` v0.415 walks PDOL/CDOL/DDOL/TDOL (tag,length) lists; `nfc_emv_afl_decode` v0.416 expands tag 94 (SFI/record ranges → READ RECORD list); `nfc_emv_cvm_decode` v0.426 cracks tag 8E (X/Y amounts + CVM method/condition rules) | — | — | shipped — BER-TLV + Track-2 + DOL + AFL + CVM-List field decode. Cryptogram/online-auth flow deliberately out of scope (needs issuer keys). |
| Wiegand D0/D1 capture + replay | apps top-20 #6 + attacks #6 | ❌ | — | — | **§2b** ⟶ `gpio_wiegand_capture/replay` |
| HID Prox / EM4xxx PACS decode | apps top-20 #15 | ⚠️ `rfid_raw_analyze` | — | ✅ pm3 | **NEW** ⟶ `rfid_pacs_decode` |
| LF EM4100 / T5577 read+write | baseline | ✅ `rfid_*`, `loader_t5577_multiwriter`; offline `em4100_decode` (ID forms) + `em4100_encode` (64-bit frame) + `em4100_frame_decode` v0.417 (parity-validating frame→ID inverse) | — | — | — |
| FDX-B / DCF77 / niche LF synth | apps NFC | ⚠️ `rfid_build` covers EM4100 only; **FDX-B offline *decode* shipped v0.464.0 (`fdxb_decode`)**, DCF77 telegram-synth v0.375 | — | — | Low-priority gaps (LF *synth*/build side remains EM4100-only) |
| UHF EPC Gen2 (M6E-Nano) | apps `uhf_rfid` | ⚠️ | — | — | Adjacent-HW gap for *reading*; **offline EPC *decode* shipped v0.468.0 (`epc_decode`, SGTIN-96)** |
| Mag-stripe wireless emulation (MagSpoof) | apps top-20 #9 | ⚠️ partial | — | — | offline half ✅ `magstripe_decode` (v0.453 — ISO 7813 Track 1/2 ASCII swipe parser); the wireless-coil TX emulation remains a hardware loader step |

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
| BLE address-type / RPA classification | scan post-processing | ✅ `ble_addr_classify` v0.425 — random subtype from the top 2 bits (static / resolvable-private RPA / non-resolvable / reserved) or public OUI; the BLE counterpart of `mac_classify`, the privacy/tracking-resistance signal over scan-result addresses | — | — | shipped |
| BLE 5 connection follow (PHY/CSA hops) | hardware §4 (Sniffle) | ❌ | — | — | Needs CatSniffer/Sniffle backend |
| Stealtooth forced-pairing | attacks | — research-only — | — | — | Out of scope |
| BadKB (Bluetooth-HID BadUSB) | firmware + apps | ✅ via `badusb_*` + `bruce_badusb_run` | — | — | — |

### 1.4 802.11 / WiFi

| Primitive | Anchor source | Native | Container | Federation | Gap |
|---|---|:---:|:---:|:---:|:---:|
| WiFi scan / deauth / beacon-spam / probe / evil-portal | baseline | ✅ Marauder `wifi_*` family (≈70 Specs) | — | — | — |
| WiFi PMKID capture (Marauder) | baseline | ✅ `wifi_sniff_pmkid` | — | — | — |
| MAC randomization / admin-bit classify | scan post-processing | ✅ `mac_classify` v0.423 — I/G (multicast) + U/L (locally-administered → randomized/privacy-MAC signal) + broadcast, plus the known-attack-OUI cross-check; offline analysis over scan-result MACs | — | — | shipped |
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
| VIN decode/validate (ISO 3779) | UDS DID F190 / OBD-II Mode 09 | ✅ `vin_decode` v0.421 — check-digit validation (the anchor) + region + model-year candidates + WMI/VDS/VIS split; offline complement to the UDS/OBD VIN read. Manufacturer-from-WMI lookup deferred (proprietary). | — | — | shipped |
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
- `ipv6_eui64_recover` (IPv6 → MAC deanonymisation) — ✅ shipped v0.424 — recover the hardware MAC embedded in an IPv6 Modified-EUI-64 interface identifier (detect the FF:FE marker, strip it, flip the U/L bit). The offline complement to `ndp_decode` / `dhcpv6_decode` (which surface IPv6 addresses); chains the recovered MAC into `mac_classify` so a MAC-derived SLAAC address is deanonymised and a randomized one is flagged. Observation-framed (privacy/RFC-7217 IIDs carry no marker), no hardware (`internal/macaddr`).
- `hash_identify` AD-roasting coverage — ✅ v0.434 extended the existing hash-format identifier with the Active Directory roasting loot: Kerberos TGS-REP (`$krb5tgs$`, Kerberoast → hashcat 13100/19600/19700), AS-REP (`$krb5asrep$` → 18200), AS-REQ pre-auth (`$krb5pa$` → 7500), DCC2/mscash2 (`$DCC2$` → 2100), and NetNTLMv1/v2 (the `user::domain:…` Responder format → 5500/5600). Definitive `$`-prefixes (no confidently-wrong); the colon-prefix strip now skips `$`-structured and `::` NetNTLM hashes so they reach the identifier intact. Ties to `kerberos_decode`. v0.435 added WPA hashcat-22000 lines (`WPA*01*` PMKID / `WPA*02*` EAPOL — closing the coherence gap with `wifi_pmkid_hc22000`, which emits them) and Cisco-IOS type 8 (`$8$` → 9200) / type 9 (`$9$` → 9300) (`internal/tools/security.go`).
- Werkzeug **scrypt** (`scrypt:N:r:p$…`) — ✅ v0.459 extended `internal/webpass` (and so `pbkdf2_password` verify/compute + the `hash_crack` `werkzeug` mode) to cover Werkzeug's **modern default** password hash (Werkzeug ≥2.3 / current Flask), closing the scrypt deferral noted when pbkdf2_password shipped (v0.457). The `werkzeug` cracker now auto-detects pbkdf2 vs scrypt; compute via `scheme=werkzeug-scrypt` (N/r/p). `Wrap-vs-native: wrap` — `golang.org/x/crypto/scrypt` (already a dep; native port infeasible), with a 1 GiB memory-cost cap against hostile N/r and our own `scrypt:N:r:p$salt$hex` framing. Verified byte-for-byte against the reference Werkzeug library + Go's x/crypto/scrypt. No new tool. (`internal/webpass`)
- `phpass_password` (WordPress $P$ / phpBB $H$) + `hash_crack` phpass — ✅ shipped v0.458 — the phpass portable-hash format used by **WordPress** (the most-deployed CMS) and phpBB3 — among the most common user-DB offline-crack targets (hashcat 400). Compute or verify (constant-time), and `hash_crack_dictionary` gained a `phpass` dictionary mode so a dumped wp_users table can be cracked directly. Iterated MD5 finished with phpass's own base64; reuses the crypt `itoa64` alphabet. A hostile embedded cost (> 2^24 rounds) is rejected rather than allowed to hang. Verified byte-for-byte against the reference **passlib** library (an independent oracle) — `Compute` reproduces the passlib hash exactly; fuzz-clean. Native — `crypto/md5`, stdlib only (`internal/phpass`).
- `pbkdf2_password` (Django / Werkzeug PBKDF2 password hashes) + `hash_crack` django/werkzeug — ✅ shipped v0.457 — the user-credential format in a **Python web-app database dump** (Django `pbkdf2_sha256$…`, Werkzeug/Flask `pbkdf2:sha256:…`) — a top offline-crack target the toolkit couldn't previously handle. Compute or verify (framework auto-detected, constant-time, sha256/sha1/sha512), and `hash_crack_dictionary` gained `django`/`werkzeug` dictionary modes (high-iteration → workers capped) so a dumped user table can be cracked directly. Reuses the generic `internal/wpa.PBKDF2`. Verified against reference **Django and Werkzeug** library output (an independent oracle) + raw `hashlib.pbkdf2_hmac`; fuzz-clean. Offline, no hardware (`internal/webpass`).
- `flask_session` (Flask/itsdangerous session cookie decode / verify / forge) — ✅ shipped v0.456 — the **web-pentest analogue of the JWT trio** for Flask, the most common Python web framework. A Flask session is signed-not-encrypted, so **decode** reads the payload with no key; **verify** tests a candidate `SECRET_KEY` or a list (the **flask-unsign weak-key attack** — a top web finding, parallel to the JWT weak-secret test); **forge** mints a validly-signed cookie (e.g. `{"admin":true}`) for an authorized test. Handles itsdangerous's HMAC-SHA1 signing, the `HMAC-SHA1(SECRET_KEY, "cookie-session")` key derivation, the 2011 timestamp epoch, and transparent zlib payload inflation. **Verified byte-for-byte against the reference itsdangerous library** (an independent oracle via a venv) — decode/verify against itsdangerous-produced cookies (compressed + uncompressed) and `Sign` reproduces an itsdangerous cookie exactly; fuzz-clean. Native — HMAC-SHA1 + base64url + zlib, stdlib only (`internal/flasksession`).
- `icmp_packet_decode` embedded-packet decode — ✅ v0.475.0 — continued the chain-to-existing-decoder seam: an ICMP **error** message (Destination Unreachable / Time Exceeded / Parameter Problem / Redirect / Packet-Too-Big) quotes the original IP packet that triggered it (the IP header + ≥8 bytes of payload), and that quote was previously surfaced as raw hex "to feed into `ip_packet_decode`". It is now **decoded in place** via `internal/ipdecode`, so the offending flow's source/dest addresses, protocol and (for UDP, or a long-enough TCP quote) ports appear directly in the ICMP decode. Also added v6 Destination Unreachable (type 1) / Time Exceeded (type 3) — previously raw-hex — routing their embedded IPv6 packet through the same path. No confidently-wrong output: a quote that doesn't parse as IP is reported with `embedded_decode_error` and the raw hex preserved (truncated TCP quotes degrade gracefully — IP layer + ports as available). Verified with embedded IPv4/UDP + IPv6/UDP vectors (inner addresses + ports asserted) + a garbage-quote fallback; added an icmp fuzz harness, fuzz-clean through the embedded→ipdecode path. No new tool — extends `icmp_packet_decode` (`internal/icmp` → `internal/ipdecode`).
- `dtls_decode` Certificate body — ✅ v0.474.0 — sibling-swept the v0.473 TLS Certificate decode into **DTLS**: the DTLS Certificate handshake message (msg_type 11) body uses the same TLS 1.2 layout, so each DER cert is chained through `internal/x509decode` (subject / issuer / validity / SAN / fingerprints / CA). Gated on the DTLS handshake message being **unfragmented** (the existing dispatch already returns early on a fragment, so a partial cert is never mis-decoded); mismatched list-length → note; unparseable DER → raw + `decode_error`. Self-verified with `crypto/x509`-generated certs (single + chain) wrapped in a DTLS 1.2 Certificate record; added a DTLS fuzz harness (cert→x509 seed), fuzz-clean. No new tool — extends `dtls_decode` (`internal/dtls` → `internal/x509decode`).
- `tls_handshake_decode` Certificate body — ✅ v0.473.0 decoded the TLS **Certificate handshake message** (previously labelled-but-deferred): the TLS 1.2 (and earlier) certificate_list is walked and each DER certificate is chained through `internal/x509decode`, so a captured handshake now yields the server's full cert chain — subject / issuer / validity / SAN / fingerprints / CA flag — in one decode (the network-pentest analogue of the NDEF→WSC/BT-OOB carrier wirings). In TLS 1.3 the Certificate message is encrypted (post-key-exchange), so the plaintext form in a passive capture is the pre-1.3 layout decoded here; a body that doesn't match it is reported with a note, never mis-parsed; a cert whose DER fails to parse is surfaced raw with a `decode_error` rather than a confident decode. Self-verified by wrapping `crypto/x509`-generated certs (single + chain) in a Certificate record and asserting the chained x509 fields, plus malformed-list-length / garbage-DER cases; fuzz-clean (5M execs through the cert→x509 path, 0 panics). No new tool — extends `tls_handshake_decode` (`internal/tlsdecode` → `internal/x509decode`).
- `epc_decode` SGTIN-198 — ✅ v0.472.0 extended `epc_decode` with **SGTIN-198** (header 0x36), the 198-bit SGTIN whose serial is a variable-length **alphanumeric** 7-bit-ASCII string (up to 20 chars) rather than a numeric value — used where the GS1 serial isn't purely numeric (e.g. pharmaceutical serialisation), and previously reported "unsupported". `Decode` now dispatches by length: 12 bytes → the 96-bit schemes, 25/26 bytes → SGTIN-198 (the word-aligned form a RAIN reader emits; the 140-bit serial is twenty null-padded 7-bit chars). Company prefix / item reference / GTIN-14 reconstruction are shared with SGTIN-96; only the serial decode differs. Anchored byte-for-byte against the epc-encoding-utils oracle — `3614257BF7194E60C286C5933…` → `sgtin-198:0.0614141.812345.ABC123` and `…6C59B4B5C8…` → `…812345.XYZ-9`. The other 198-bit variants (GRAI-170 / GIAI-202 / SGLN-195) remain reported-unsupported. No new tool. Fuzz-clean. (`internal/epc`)
- `epc_decode` SGLN-96 / GRAI-96 / GIAI-96 — ✅ v0.471.0 **completed the 96-bit EPC family** in `epc_decode` by adding the three GS1-keyed schemes deferred at v0.470 (the prior fire HELD on these for lack of an authoritative source): **SGLN-96** (header 0x32, location — company prefix + location reference + extension), **GRAI-96** (0x33, returnable asset — company prefix + asset type + serial), and **GIAI-96** (0x34, individual asset — company prefix + asset reference). The remaining-source problem was solved with the **venv-oracle technique**: the `epc-encoding-utils` Python library was installed and used as an oracle to extract the authoritative partition tables and generate decoded vectors, anchoring each scheme byte-for-byte — `3214257BF460720000000190` → `sgln-96:0.0614141.12345.400`, `3314257BF40C0E400000162E` → `grai-96:0.0614141.12345.5678`, `3414257BF400000000003039` → `giai-96:0.0614141.12345` (+ a 12-digit-prefix GIAI partition-0 vector). Each decodes filter / partition / company prefix / reference fields + the EPC tag and pure-identity URIs, matching the oracle's formatting exactly (per-scheme zero-padding rules). `epc_decode` now covers all six 96-bit schemes (SGTIN/SSCC/SGLN/GRAI/GIAI/GID); 198-bit variants remain reported-unsupported. No new tool. Fuzz-clean. (`internal/epc`)
- `epc_decode` GID-96 — ✅ v0.470.0 extended `epc_decode` with **GID-96** (EPC header 0x35), the General Identifier — the EPC scheme used when no GS1 key (GTIN/SSCC/GLN/…) applies. Three fixed-width fields, no partition table / company prefix / check digit: general manager number (28 bits) + object class (24) + serial number (36), plus the EPC tag / pure-identity URIs. **Verified byte-for-byte against three worked vectors** — `3500079FF00000B00000000C` → `gid-96:31231.11.12`, `3500E82D900000F000000001` → `gid-96:951001.15.1`, `350000A2600019003ADE56FA` → `gid-96:2598.400.987649786`. Remaining GS1-keyed schemes (SGLN/GRAI/GIAI, which still need their own partition tables) stay identified-not-decoded. No new tool. Fuzz-clean. (`internal/epc`)
- `epc_decode` SSCC-96 — ✅ v0.469.0 extended `epc_decode` with **SSCC-96** (EPC header 0x31), the GS1 Serial Shipping Container Code — the logistics-unit (case/pallet/container) scheme, the second-most-common EPC after SGTIN. Decodes filter / partition / company prefix / serial reference and reconstructs the **SSCC-18** (extension digit + company prefix + serial-reference remainder + recomputed GS1 mod-10 check digit) plus the EPC tag / pure-identity URIs. The SSCC partition table (distinct from SGTIN's — no item reference, wider serial reference) and the SSCC-18 reconstruction are **verified byte-for-byte against the worked vector** `3134257BF4499602D2000000` → `urn:epc:tag:sscc-96:1.0614141.1234567890` (company prefix 0614141, serial reference 1234567890, SSCC-18 106141412345678908). The 24 trailing reserved bits are checked (non-zero noted). Remaining 96-bit schemes (SGLN/GRAI/GIAI/GID) still identified-not-decoded. No new tool. Fuzz-clean. (`internal/epc`)
- `epc_decode` (GS1 EPC UHF RAIN RFID — SGTIN-96) — ✅ shipped v0.468.0 — decodes the GS1 **Electronic Product Code** binary on UHF RAIN RFID (EPC Gen2 / ISO 18000-63) tags — retail item-level tagging and supply-chain logistics — a **whole RFID band the toolkit did not decode** (it covered HF ISO 14443/15693/NDEF and LF EM4100/HID/FDX-B/T5577, but not UHF EPC). Reading a UHF tag needs a RAIN reader (hardware, out of scope), but the captured 96-bit EPC decodes entirely offline. **SGTIN-96** (header 0x30, the dominant retail scheme) is fully decoded: filter, partition, company prefix, item reference, serial number, the canonical EPC tag URI (`urn:epc:tag:sgtin-96:…`) and pure-identity URI (`urn:epc:id:sgtin:…`), and the reconstructed **GTIN-14** (with a recomputed GS1 mod-10 check digit). The SGTIN-96 layout, the partition table, and the SGTIN→GTIN reconstruction are taken from the **GS1 EPC Tag Data Standard** and **verified byte-for-byte against its canonical worked example** — `3074257BF7194E4000001A85` → `urn:epc:tag:sgtin-96:3.0614141.812345.6789` (company prefix 0614141, item ref 812345, serial 6789, GTIN-14 80614141123458) — not recalled. No confidently-wrong output: the other 96-bit schemes (SSCC/SGLN/GRAI/GIAI/GID, 0x31-0x35) are identified by name but not field-decoded (raw + note) rather than guessed; unknown headers and 198-bit variants are reported unsupported. Verified against the canonical vector + a second GS1 check-digit cross-check + other-scheme/unknown/error cases; fuzz-clean (3.4M execs, 0 panics). Native — fixed bit-field extraction + GS1 mod-10, stdlib only (`internal/epc`).
- `nfc_t2t_tlv_decode` (NFC Type 2 Tag data-area TLV walker) — ✅ shipped v0.467.0 — walks the TLV blocks in a Type 2 Tag's **data area** (user memory from page 4 onward) and **decodes the NDEF message in place**, bridging a raw tag-memory dump to `ndef_decode`: a Type 2 Tag (NTAG / MIFARE Ultralight) stores its NDEF inside a TLV structure (NULL 0x00 / Lock Control 0x01 / Memory Control 0x02 / NDEF 0x03 / Proprietary 0xFD / Terminator 0xFE), and this locates and decodes it. The data-area complement to `nfc_t2t` (which decodes the page 0-3 header: UID/BCC/lock/CC) — previously an operator had to manually extract the NDEF bytes from a dump to feed `ndef_decode`. Each block is reported with type/offset/length/raw value; the NDEF TLV value is handed to the shared NDEF walker (URI/Text/Smart Poster/handover/MIME). The 1-or-3-byte length form (0xFF big-endian escape) is handled and the Terminator ends the walk. The TLV type values + length encoding are from the **NFC Forum Type 2 Tag Operation Specification** (cross-checked vs the Nordic nrfxlib T2T docs). No confidently-wrong output: a TLV whose declared length overruns the buffer is reported as truncated, and the Lock/Memory Control reserved-area descriptors are surfaced raw rather than guessed. Verified against a full Lock+NDEF+Terminator data area (NDEF Text record decoded in place) + NULL-skip / 3-byte-length / unknown-type / truncated / no-terminator / error cases; fuzz-clean (3.8M execs, 0 panics). Native — TLV framing over the shared NDEF walker (`internal/t2t`).
- `ntag_config_decode` (NTAG213/215/216 configuration-page decode) — ✅ shipped v0.466.0 — decodes the NTAG21x **configuration pages**, the registers controlling an NFC Type-2 tag's password protection, lock state, NFC counter, and UID/counter ASCII-mirror — answering an operator's first questions about a dumped tag: is it password-protected, **read+write or write-only (PROT)**, is the config **permanently locked (CFGLCK)**, how many failed password attempts are allowed (**AUTHLIM**), is the NFC read counter enabled. The protection-state complement to `ndef_decode` / `nfc_t2t` (which decode the tag's *data*, not its access registers). Decodes **AUTH0** (first protected page), the **ACCESS** byte (PROT/CFGLCK/NFC_CNT_EN/NFC_CNT_PWD_PROT/AUTHLIM), and the **MIRROR** byte (MIRROR_CONF UID/counter mirror, MIRROR_BYTE/PAGE, strong-modulation) from CFG0+CFG1 (8 bytes; 16 bytes adds PWD+PACK). The config pages live at different addresses per variant (29h/83h/E3h) but the layout is identical, so it decodes the page bytes regardless of origin. The page layout (Table 8), MIRROR byte (Table 9), ACCESS byte (Table 10), and every field value meaning (Table 11) were **extracted and verified byte-for-byte from the NXP NTAG213/215/216 data sheet rev 3.2 §8.5.7** (read directly from the PDF — not recalled). No confidently-wrong output: an undocumented MIRROR_CONF value (0b11) is surfaced as reserved; AUTH0=0xFF (protection disabled) is noted rather than asserted against an unknown memory size. Verified against factory-default / read+write-protected / CFGLCK+mirror / NFC-counter / PWD+PACK / error cases; fuzz-clean (4.8M execs, 0 panics). Native — fixed bit-field extraction, stdlib only (`internal/ntag`).
- `t5577_config_decode` (T5577 / ATA5577 configuration-register decode) — ✅ shipped v0.465.0 — decodes the **T5577 block-0 configuration register**, the 32-bit word that controls how an LF 125 kHz tag modulates/clocks its data. The T5577 is the ubiquitous rewritable LF blank used to clone EM4100 / HID Prox / Indala / AWID; decoding its config block surfaces the **modulation** (Direct / FSK1/2/1a/2a / ASK-Manchester / PSK1/2/3 / Biphase / Biphase-a), **data bit rate** (RF/8…RF/128), PSK clock, AOR, **max block**, password-enabled and sequence-terminator flags — the diagnostic complement to the project's T5577 clone/write tooling (`rfid_write` / `loader_t5577_multiwriter`, which set these configs but couldn't read them back). The bit layout, bit-rate table, and the modulation value→name table are taken from the **Proxmark3 reference** (`doc/T5577_Guide.md` + `client cmdlft55xx.c GetModulationStr`) and verified byte-for-byte against **two real config words**: `0x00148040` (EM4100 → RF/64, Manchester, 2 blocks) and `0x00107060` (HID Prox → RF/50, FSK2a, 3 blocks). (Verification caught a recalled error — PSK1 is modulation value 1, not 0x0A.) No confidently-wrong output: a modulation value outside the documented set is surfaced as a numeric code, and extended mode (master key 0x6/0x9, which reinterprets the reserved bits) is flagged rather than mis-decoded. Verified against both vectors + constructed PSK/flags / extended-mode / error cases; fuzz-clean (4.2M execs, 0 panics). Native — fixed bit-field extraction, stdlib only (`internal/t55xx`).
- `fdxb_decode` (ISO 11784/11785 FDX-B animal/pet-microchip LF decode) — ✅ shipped v0.464.0 — decodes the **FDX-B data block**, the 134.2 kHz LF transponder format in pet/animal microchips (and many asset/biothermo tags) — the LF complement to the project's EM4100 / HID-Prox / PACS decoders (it read/emulated FDX-B on hardware but had no offline data-block decode). Recovers the **country code** (10-bit LSB-first), the **38-bit national identification number** (LSB-first), the data-block-status and animal-application flags, and validates the **CRC-16** (CCITT poly 0x1021, init 0x0000, refin=false/refout=true, over the 8-byte ID block — the integrity gate). On-air framing (11-bit preamble + control-bit stuffing) is the demodulator's job and out of scope, so the decode is deterministic. The field layout, LSB-first bit order, and CRC-16 parameters are taken from the **Proxmark3 reference** (`common/crc16.c crc16_fdxb` + `client cmdlffdxb.c`) and **verified byte-for-byte against two real decoded tags** — country 528 (Netherlands) / national 140000795552 (raw ID `05 D9 4D 19 04 21 00 01`) and country 999 / national 1500030037 (CRC `0x8A1C`) — not recalled. No confidently-wrong output: a CRC-failed frame is reported as such (never asserted as a real tag), a 900-999 manufacturer/test country code is noted rather than mapped, and the reserved/extended bits are surfaced raw. Verified against both real vectors + CRC-mismatch / extended-block / error cases; fuzz-clean (5.6M execs, 0 panics). Native — fixed bit/byte extraction + CRC-16, stdlib only (`internal/fdxb`).
- NDEF **Connection Handover** records (`Hs` / `Hr` / `ac` / `cr` / `err`) — ✅ shipped v0.463.0 — completes the tap-to-pair / tap-to-connect decode tree in `ndef_decode` (no new tool — recursive NDEF, like Smart Poster). A real handover tag's top-level record is a **Handover Select** (`Hs`) or **Handover Request** (`Hr`): a 1-byte version (major high nibble / minor low) + a nested NDEF message that the decoder now **recurses**, so the **Alternative Carrier** (`ac`) records and the **Wi-Fi WSC / Bluetooth OOB carrier-config records they reference by ID** (shipped v0.461/v0.462) are decoded in place — previously the `Hs` payload was opaque hex and the carriers were never reached. The `ac` record decodes the Carrier Power State (0=inactive / 1=active / 2=activating / 3=unknown), the carrier-data reference (the carrier record's ID), and the auxiliary-data references; `cr` (Collision Resolution) the 2-byte random number; `err` the error-reason byte. Values verified verbatim against the **nfcpy/ndeflib reference** (CPS tuple, `ac` byte layout, version-byte nibbles, `Hs`=version+message) — not recalled. **Also hardened a latent stability bug**: nested-message decode (the pre-existing Smart Poster path and these new handover paths) had **no recursion-depth cap** — a maliciously self-nesting record could exhaust the stack; added a depth=16 guard that leaves the payload raw with a warning past the limit. No confidently-wrong output: reserved error reasons surfaced as `reserved(0xNN)`, truncated `ac` references reported. Verified against a full hand-constructed `Hs → ac → referenced BT-OOB carrier` tree + aux-refs / cr / err / depth-guard cases; fuzz-clean (1.7M execs, 0 panics). Native — recursive descent, stdlib only (`internal/ndef`).
- `bluetooth_oob_decode` (Bluetooth OOB pairing / NFC handover record decode) — ✅ shipped v0.462.0 — decodes the **tap-to-pair** payload: the Bluetooth Secure Simple Pairing OOB data block carried by an NFC handover tag, in both MIME forms — `application/vnd.bluetooth.ep.oob` (BR/EDR "Easy Pairing": a 2-byte little-endian OOB Data Length + 6-byte little-endian BD_ADDR + EIR) and `application/vnd.bluetooth.le.oob` (Bluetooth LE: a bare AD-structure sequence). Recovers the peer's Bluetooth address, device class, LE role, local name, and the SSP OOB key material a tag offers. Both variants run through the **shared `internal/ble` EIR/AD walker**, which this work extended with value decoders for the OOB-critical AD types it previously only named: **LE Role** (0x1C → Peripheral / Central / preferred, per Bluetooth CSS Part A §1.17), **LE Bluetooth Device Address** (0x1B → 6 LE address bytes + public/random type flag), and **Class of Device** (0x0D → 24-bit value + named Major Device Class) — so `ble_gap_decode` benefits too. The BR/EDR framing and the LE value formats are taken **verbatim from the Bluetooth Core Specification Supplement and the NFC Forum "Bluetooth Secure Simple Pairing Using NFC" application document (as implemented in the ndeflib reference)** — verified, not recalled. No confidently-wrong output: the declared OOB length is checked-not-asserted (mismatch noted), reserved LE-role values are surfaced as `reserved(0xNN)`, and the opaque OOB key material (Hash C / Randomizer R / LE SC confirmation+random / SM TK) is left as raw hex. The same record is decoded automatically when it appears as an `ndef_decode` MIME payload (the tap-to-pair sibling of the v0.461 tap-to-connect WSC wiring). Verified against hand-constructed BR/EDR + LE vectors (BD_ADDR endianness, CoD major class, LE role/address, length-mismatch, reserved role) + an NDEF-wrapped integration test; fuzz-clean (btoob 4.1M + new GAP harness 3.3M execs, 0 panics). Native — thin BR/EDR framing over the shared EIR walker, stdlib only (`internal/btoob` + `internal/ble`).
- `wifi_wsc_decode` (Wi-Fi Simple Config / WPS credential decode) — ✅ shipped v0.461.0 — decodes the `application/vnd.wfa.wsc` credential blob: the payload behind a **tap-to-connect Wi-Fi NFC tag** (an NDEF MIME record) and the Credential carried in WPS Registrar messages (M7/M8). Recovers the provisioned network's **SSID**, authentication type (Open / WPA-PSK / WPA2-PSK / WPA-Enterprise / WPA2-Enterprise, decoded as bit flags), encryption type (None / WEP / TKIP / AES), MAC, and — the operative field for an authorized engagement — the **network key (the PSK)**. Walks the WSC TLV grammar (big-endian type:2 / length:2 / value) and recurses into the Credential attribute (0x100E). The attribute IDs and auth/encr flag values are taken **verbatim from the Wi-Fi Simple Config spec as published in hostap's `src/wps/wps_defs.h`** (verified against that source, not recalled). The 0x1018 Encrypted-Settings attribute (AES under an unavailable session key) is reported present-but-encrypted rather than guessed; WSC v2 vendor-extension subelements (0x1049) are surfaced raw; unknown auth/encr flag bits are surfaced, never dropped — no confidently-wrong output. The same blob is decoded automatically when it appears as an `ndef_decode` MIME payload (closing the long-standing "MIME pass-through surfaces type + size only" gap in `internal/ndef`). Verified against hand-constructed WSC vectors (SSID/auth/encr/PSK/MAC TLVs, mixed-mode 0x0022 auth, unknown-bit handling, truncated TLV) + an NDEF-wrapped integration test; fuzz-clean (6.6M execs, 0 panics). Native — fixed TLV parsing, stdlib only. Offline, no hardware (`internal/wsc`).
- `nfc_iso14443b_decode` (ISO 14443 Type B ATQB identity) — ✅ shipped v0.460.0 — decodes the **Type B answer to REQB/WUPB**, the proximity air interface behind most **ePassports (ICAO 9303)**, several national eID cards, and some transit/payment cards — the Type B complement to the project's long-standing `nfc_iso14443a_identify` (it had Type A + ISO 15693 but no Type B). The 12-byte ATQB → 4-byte PUPI, 4-byte card-specific application data (surfaced raw — its meaning is issuer-defined), and the 3-byte protocol-info group decoded into documented ISO 14443-3/-4 fields: max frame size (FSCI → the same 16…256-byte table as Type A), ISO 14443-4 support, frame waiting time (FWI → `FWT = 0.302064·2^FWI` ms), the bit-rate capability byte (PICC↔PCD 212/424/848 kbit/s), and NAD/CID support. The **0x50 leading byte is the hard anchor** — a non-0x50 ATQB is flagged, not mis-decoded; a trailing CRC_B is tolerated. Verified against spec-anchored constructed vectors (FSCI/FWI/FO bit fields, bit-rate decode) + non-standard/short/non-hex cases; fuzz-clean (7.1M execs, 0 panics). Offline, no hardware (`internal/iso14443b`).
- `nfc_iso15693_decode` (ISO 15693 vicinity-card identity) — ✅ shipped v0.455 — decodes the **second major HF NFC standard** alongside ISO 14443 (the project had `iso14443a` but no ISO 15693): the 8-byte UID (0xE0 prefix **validated** as the hard anchor — a non-0xE0 UID is flagged, not mis-decoded; IC manufacturer from the ISO 7816-6 table **shared with `internal/iso14443a`**; 6-byte serial) plus the optional AFI application-family byte (documented ISO 15693-3 table). Seen on library / access / medical / industrial tags (NXP ICODE, TI Tag-it, ST LRI). DSFID and the flag-gated Get-System-Information response are deferred (manufacturer-specific / unverified-format). Verified against NXP/ST UID vectors + non-standard/unknown-manufacturer cases; fuzz-clean. Offline, no hardware (`internal/iso15693`).
- `jwk_to_pem` (JWK / JWKS → PEM) + `jwt_verify` JWK input — ✅ shipped v0.454 — converts a JSON Web Key or JWK Set (the form an issuer publishes at `/.well-known/jwks.json`, RFC 7517) into PKIX PEM public keys (RSA / ECDSA P-256/384/521 / Ed25519), closing the **capture-JWKS → verify-token** workflow that v0.452's all-algorithm `jwt_verify` left open (it accepted only PEM). `jwt_verify`'s `public_key` now also accepts a JWK/JWKS directly, selecting the key by the token's `kid`. Verified by round-tripping RSA/EC/Ed25519 keys against the Go stdlib (the authoritative reference) + an end-to-end RS256-token-via-JWKS test; `e="AQAB"` pinned to 65537; fuzz-tested (no panics). Native — base64url + crypto/x509 PKIX marshalling, stdlib only (`internal/jwtsig`).
- `magstripe_decode` (ISO 7813 Track 1/2 swipe parser) — ✅ shipped v0.453 — parses a **raw magnetic-stripe swipe** (the ASCII track data a card reader / MSR / skimmer emits) into structured fields: PAN (+ masked), cardholder name (Track 1 only — surname/given), expiry (MM/YY), the 3-digit service code with its decoded ISO 7813 meaning (chip-preferred, PIN-required, …), and discretionary data. The **offline half of magspoof (rank #3)** and the swipe-side complement to `nfc_emv_track2_decode` (which handles the EMV *chip's* tag-57 BCD Track-2-Equivalent — a different encoding, no cardholder name). The PAN's Luhn check digit is the verification anchor (a misframed swipe is flagged, never asserted as a real card); the bit-level LRC is surfaced raw but not validated (a wrong verdict is worse than none). Reuses `internal/emv`'s Luhn + ISO 7813 service-code table. Verified against Luhn-valid test PANs (Visa 4111…, Mastercard 5555…). Offline, no hardware (`internal/emv`).
- `argon2` (Argon2id/Argon2i compute + verify) — ✅ shipped v0.451 — the **OWASP-recommended modern password hash** (the Password Hashing Competition winner, bcrypt's successor), completing the modern-hash compute/verify coverage. `hash_identify` recognises `$argon2id/$argon2i/$argon2d` but nothing could generate/verify one. Compute (password + optional variant/memory/time/parallelism/salt; random salt via crypto/rand) or verify a candidate against a captured PHC hash (constant-time; params read from the hash). `hash_crack_dictionary` also gained the `argon2` algorithm (memory-hard → workers capped). **`Wrap-vs-native: wrap`** (the second documented exception, after bcrypt) — Argon2 is a memory-hard BLAKE2b KDF; the audited `golang.org/x/crypto/argon2` (the already-required x/crypto module) is used, with our own PHC string parse/encode around it, plus a 2 GiB memory-cost cap that rejects a hostile `m=` before it can OOM the host. Verified against real argon2id/argon2i hashes from the reference **argon2-cffi** library (an independent oracle, confirmed to match x/crypto byte-for-byte) plus a compute→verify round-trip. argon2d (data-dependent) is out of scope. Offline compute, no network/device (`internal/tools/argon2.go`).
- `hash_crack_dictionary` crypt(3) + MySQL coverage — ✅ v0.450 extended the dictionary cracker with the **`crypt` algorithm** (auto-detects `$1$` md5crypt / `$apr1$` / `$5$` sha256crypt / `$6$` sha512crypt from the hash prefix via the oracle-verified `unixcrypt.Verify`) and the **`mysql`** algorithm (mysql_native_password, SHA1∘SHA1). The cracker could already do md5/sha1/sha256/sha512/ntlm/bcrypt; this closes the **detect-but-can't-crack** gap for modern Linux `/etc/shadow` ($6$ is the default) and MySQL/MariaDB dumps — the hashes `hash_identify` already flags. Each crack path reuses primitives gated against independent oracles (OpenSSL `passwd`, the published MySQL vector). No new tool (`hash_crack_dictionary` enhanced); `internal/tools/security.go` + `internal/unixcrypt`.
- `bcrypt` ($2a/$2b/$2y compute + verify) — ✅ shipped v0.449 — the **dominant modern web-application password hash** (hashcat 3200), completing the credential cluster's compute/verify coverage: `hash_identify` recognises bcrypt and `hash_crack` runs a dictionary attack, but neither generates a hash nor does a single-shot verify. Compute (password + optional cost 4-31, default 10) or verify a candidate against a captured `$2…$` hash (constant-time, the bcrypt design); bcrypt's 72-byte limit is surfaced as an error. **The one deliberate `Wrap-vs-native: wrap` in the credential cluster** — bcrypt is Blowfish-based and a faithful native port would require vendoring the un-hand-verifiable 1024-entry S-box table (the hex digits of pi), so the audited `golang.org/x/crypto/bcrypt` (already a project dependency, used by `hash_crack`) is used instead; no new dependency, native genuinely infeasible. Verified against the canonical OpenBSD/jBCrypt published vectors plus a generate→verify round-trip. Offline compute, no network/device (`internal/tools/bcrypt.go`).
- `sha_crypt` (Unix $6$ sha512crypt / $5$ sha256crypt compute + verify) — ✅ shipped v0.448 — the **modern Linux `/etc/shadow`** credential primitive (`$6$` sha512crypt is the current default), the highest-frequency offline-crack target. `hash_identify` recognises these (hashcat 1800 sha512crypt / 7400 sha256crypt) and `hash_crack` attacks them; this computes/verifies them, alongside `md5crypt`'s older `$1$/$apr1$` family. Compute (password + optional salt/scheme/rounds; random salt via crypto/rand, default 5000 rounds, `rounds=N$` emitted when set) or verify a candidate against any crypt hash ($6$/$5$/$1$/$apr1$, constant-time). Ulrich Drepper's SHA-crypt (the dual-context digest mixing + the two final base64 permutation tables) is implemented natively over `crypto/sha256`+`crypto/sha512`. Strongest verification class — gated against the **OpenSSL `passwd -6` / `passwd -5` oracle** across password/salt lengths and the `rounds=` form, matching byte-for-byte. Offline compute, no network/device (`internal/unixcrypt`).
- `md5crypt` (Unix $1$ / Apache $apr1$ compute + verify) — ✅ shipped v0.447 — the compute/verify side of the crypt(3) MD5 family: `hash_identify` recognises these (hashcat 500 md5crypt / 1600 apr1) and `hash_crack` attacks them, but neither could produce or check one. The same `$1$` algorithm is **Cisco IOS "type 5"** (complementing `cisco_type7_decode` and the type-8/9 detection); `$apr1$` is the **Apache htpasswd** format. Compute (password + optional salt/scheme; random salt via crypto/rand if omitted) or verify a candidate against a captured hash (constant-time). md5crypt (Poul-Henning Kamp's MD5 scramble over 1000 rounds + the custom crypt base64) is implemented natively over `crypto/md5`. Strongest verification class — gated against the **OpenSSL `passwd -1` / `passwd -apr1` oracle** across several password and salt lengths (empty password, 16-char password, 2/4/8-char salts), matching byte-for-byte. The SHA-crypt family ($5$/$6$) is deferred (shares the structure; a clean follow-up). Offline compute, no network/device (`internal/unixcrypt`).
- `nt_hash` (Windows NT/NTLM hash compute) — ✅ shipped v0.445 — the compute side of the credential cluster: `hash_identify` recognises an NTLM hash and `hash_crack` attacks one, but neither produces one. Computing the NT hash of a known/candidate password confirms a cracked password, prepares a pass-the-hash value (the output includes the `blankLM:NT` pwdump / hashcat-1000 line), or builds test data. The NT hash is MD4(UTF-16LE(password)); MD4 (RFC 1320) is implemented natively in-tree rather than taken from the discouraged `x/crypto/md4`, consistent with the other owned crypto primitives. Strongest verification class — native MD4 gated against the **complete RFC 1320 Appendix A.5 suite** (7 vectors) and NTHash against the universal NTLM vector (`NTHash("password")=8846f7ea…`); no external oracle needed. **v0.446 — now also computes the legacy LM hash** (DES of "KGS!@#$%" under each 7-byte half of the uppercased 14-char password, via `crypto/des`), completing the full pwdump `LM:NT` line (hashcat -m 3000 LM / -m 1000 NT). LM is gated against three cross-confirming references (the universal empty-LM, the published `LM("password")=e52cac67…` pair, and the hashcat -m 3000 example `HASHCAT→299bd128c1101fd6`), every value independently reproduced via an OpenSSL DES oracle. LM is emitted only for ASCII passwords ≤ 14 chars (Windows stores no LM otherwise — the disabled-LM placeholder + a note are shown; non-ASCII is OEM-codepage dependent and rejected, not guessed). Offline compute, no network/device (`internal/nthash`).
- `wpa_pmk_derive` (WPA/WPA2-PSK PMK derivation) — ✅ shipped v0.444 — the offline Wi-Fi primitive that turns a candidate passphrase + target SSID into the 256-bit Pairwise Master Key: PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32) per IEEE 802.11i. That PMK is the value precomputed to test a guess against a captured 4-way handshake / PMKID (hashcat 22000 / 16800), so this supplies the derivation step that `wifi_pmkid_hc22000` (a hashcat-line formatter) and `internal/rsn` (a PMKID/beacon parser) do not. PBKDF2 is implemented natively in-tree (not pulled from x/crypto) to keep the crypto owned, consistent with `internal/otp` / `internal/hmacutil` / `internal/jwtsig`. Strongest verification class — gated against the RFC 6070 PBKDF2 vectors **and** the IEEE 802.11i WPA-PSK vectors (passphrase "password" / SSID "IEEE" → `f42c6fc5…`). Input validated to the spec (passphrase 8-63 printable ASCII, SSID 1-32 bytes). The 64-hex raw-PSK form and PMKID computation are deferred (PMKID held back until gated against a confidently-sourced vector — a wrong PMKID is worse than none). Offline compute, no network/device (`internal/wpa`).
- `hmac_compute` (HMAC compute / verify) — ✅ shipped v0.440 — the keyed-MAC tier and the webhook/API-auth analogue of `jwt_verify`: verify or forge an HMAC signature (GitHub X-Hub-Signature-256, Stripe-Signature, generic API request signing) with a known/leaked secret, or check a protocol HMAC auth tag. HMAC-SHA1/256/512, compute + verify, text/hex inputs. Strongest verification class — gated against the RFC 4231 published vectors. Complements `crc_compute` / `checksum_compute` (unkeyed). Offline (`internal/hmacutil`).
- `cisco_type7_decode` (Cisco IOS type-7 password) — ✅ shipped v0.439 — decode the weak reversible `service password-encryption` obfuscation (fixed-key XOR + salt index) straight to plaintext; ubiquitous in router/switch config loot. The reversible complement to hash_identify's Cisco type 8 ($8$, PBKDF2 → 9200) / type 9 ($9$, scrypt → 9300) detection (those are cracked; type 7 is decoded). Key pinned to published vectors (02050D480809 / 060506324F41 → "cisco"); offline (`internal/ciscopw`).
- `jwt_forge` (JWT forging) — ✅ shipped v0.438 — completes the JWT decode/verify/forge trio. Forge a token from operator-supplied claims for authorized web-pentest: claim escalation (`{"admin":true}`), `alg:none` crafting, and the RS→HS algorithm-confusion token (HS256 with the issuer's public-key bytes as the secret). HS256/384/512; offline payload builder (generation only, like pacs_encode/uds_encode); round-trip-verified against `jwt_verify` and reproduces the canonical jwt.io token (`internal/jwtsig`).
- `jwt_verify` (JWT signature verify) — ✅ shipped v0.437 — the verification counterpart to `jwt_decode` (decode-only by design). Verifies HS256/384/512 against a candidate secret or a list (the weak-secret test — a top web-pentest primitive), confirms the `alg:none` vulnerability, and (v0.441) verifies **RS256/384/512** against a PEM public key (Auth0/Okta/JWKS). **v0.452 — completes the asymmetric coverage**: now verifies **PS256/384/512** (RSA-PSS — Azure AD / Microsoft Entra), **ES256/384/512** (ECDSA P-256/384/521 — Apple and many IdPs; the raw r‖s JWS encoding, not DER), and **EdDSA** (Ed25519), so any captured signed JWT can be checked against the issuer's published key (`jwtsig.VerifyPublicKey` auto-parses RSA/ECDSA/Ed25519 PEM/cert). Every algorithm is round-trip-verified against the Go stdlib signer (the authoritative reference), plus the canonical jwt.io HS256 token; offline, no network/device (`internal/jwtsig`).
- `totp_generate` (RFC 6238 TOTP / RFC 4226 HOTP) — ✅ shipped v0.436 — offline OTP derivation: a 2FA seed recovered from captured loot (secrets file / config dump / otpauth:// payload) → the live codes, complementing the credential tooling (hash_identify / jwt_decode / kerberos_decode). SHA1/256/512, 6-8 digits, TOTP+HOTP. **v0.442 — also consumes a full `otpauth://` key URI** (the 2FA-enrolment QR / authenticator-export artifact) in the `secret` field: `ParseURI` takes the algorithm / digits / period / counter / mode straight from the URI, so the right parameters are applied automatically — feeding only the raw base32 from a SHA256/8-digit enrolment while the defaults stay SHA1/6 would otherwise yield valid-looking but wrong codes. Strongest verification class — gated in-tree against the RFC 4226/6238 published test vectors (HOTP counter 0 → 755224, TOTP SHA-1 T=59 → 94287082), and a URI carrying that seed reproduces the same vectors. **v0.443 — adds Steam Guard** (`mode=steam`): Steam's mobile authenticator is RFC 6238 over HMAC-SHA1 / 30s but maps the 31-bit truncated value to a fixed 5-character alphabet (`23456789BCDFGHJKMNPQRTVWXY`) instead of decimal digits, from a base64 `shared_secret` (the maFile / loot form — `encoding=base64`). Verifiable without an external vector: the truncation is anchored to the RFC value 1284755224 (the RFC publishes HOTP=755224 for counter 0, and 1284755224 % 1e6 = 755224), which maps to `GG5F5` — gated in-tree. A general `encoding` (base32/base64) param was added alongside. Offline compute from an operator-supplied seed, no network/device (`internal/otp`).
- `checksum_compute` (non-CRC checksums) — ✅ shipped v0.433 — the companion to `crc_compute` for frame trailers that aren't CRCs (common on cheap RF remotes / sensors / serial devices): SUM-8/16, XOR-8 (LRC), Modbus LRC, Fletcher-16/32, with compute + identify modes. Fletcher verified in-tree against its published reference vectors; sum/XOR/LRC are definitional. Identify makes no guesses (empty = no match → try `crc_compute`). Offline (`internal/checksum`).
- `manchester_decode` (line-code RE) — ✅ shipped v0.431 — decode a raw '0'/'1' bitstream as standard Manchester: the reverse-engineering layer between a raw OOK/FSK/RFID capture and the protocol decoders. Tries both bit alignments and returns both conventions (IEEE 802.3 / G.E. Thomas), gated on the 01/10-pairs validity rule (illegal 00/11 pairs flagged, not mis-decoded); the convention ambiguity is surfaced (both shown), never guessed. Complements `crc_compute` as protocol-RE tooling (`internal/linecode`).
- `crc_compute` (CRC compute / identify) — ✅ shipped v0.430 — a protocol reverse-engineering aid over the standard reveng catalogue (CRC-8/16/24/32 models; v0.432 added CRC-24 for Bluetooth LE PDU / OpenPGP / FlexRay). Computes a frame's CRC under any/all models, and the identify mode reports which model(s) reproduce an observed CRC over the data (reveng's fingerprinting trick) — the constant question when bringing up a decoder for a new RF/wired protocol. Every model verified in-tree against its published check value (CRC of "123456789"); identify makes no guesses (empty = no match). Offline (`internal/crc`).
- `iso7816_apdu_decode` (smart-card APDU) — ✅ shipped v0.427 — offline ISO 7816-4 APDU decoder: response SW1SW2 status word (9000 / 61XX more-data / 6CXX wrong-Le / 63CX PIN-retries-remaining / 69xx security / 6A82 file-not-found, plus the parameterised families) and command CLA/INS/P1/P2 length-case parsing with interindustry INS naming. v0.428 added the DESFire wrapping-mode status family (SW1 0x91 + SW2 → NXP DESFire status: ADDITIONAL_FRAME / AUTHENTICATION_ERROR / PERMISSION_DENIED / FILE_NOT_FOUND / …), since most DESFire exchanges are ISO 7816 wrapped. v0.429 added the DESFire command side too (CLA 0x90 → INS named as the DESFire command: SELECT_APPLICATION / AUTHENTICATE_AES / READ_DATA / GET_VERSION / …), completing DESFire APDU decoding in both directions. The analysis complement to `nfc_apdu` (which sends one); status words are the headline for smart-card interaction triage. Bounded tables, raw always surfaced (`internal/iso7816`).
- `imei_decode` (GSM device identity) — ✅ shipped v0.422 — IMEI (15-digit, Luhn-validated) / IMEISV (16-digit) decoder + TAC/RBI/serial breakdown. The cellular-identity complement to `gsmtap_decode` (an IMEI is disclosed in a GSM/LTE Identity Response, the message an IMSI-catcher forces). Luhn check digit is the anchor (advisory note on mismatch); TAC-to-manufacturer/model deliberately not guessed (proprietary GSMA registry). Offline read, no hardware (`internal/imei`).
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
