---
title: Companion hardware catalog
type: reference
created: 2026-04-25
tags: [catalog, hardware, backends, v0.8]
related: [[v0.8-team-audit]]
---

# Companion hardware catalog

Hardware platforms adjacent to (or complementary to) the Flipper Zero, surveyed
for v0.8 backend planning. Each entry lists URL, price tier, status, connectivity,
Go-ecosystem availability, whether PromptZero already wraps it, and a structural
hint for adding a new backend that mirrors the existing
`internal/{flipper,marauder,bruce,faultier,buspirate}/` shape.

**Price tiers**: `$` < $50 · `$$` $50–200 · `$$$` > $200
**Status**: `active` (vendor-supported, current SKU) · `community` (vendor stale,
fork active) · `EOL` (officially retired, no replacement firmware path)
**Backend hint**: which existing `internal/<name>/` package the new backend
would most resemble. Most new backends fit one of three patterns:

- **Bruce-shape** — CDC-ACM serial menu, line-oriented commands, banner parsing
  for capabilities. (`internal/bruce`, `internal/marauder`)
- **Faultier-shape** — strict request/response binary framing over CDC-ACM,
  not concurrency-safe. (`internal/faultier`)
- **Bus Pirate-shape** — interactive serial REPL with mode prompts.
  (`internal/buspirate`)
- **Flipper-shape** — dual transport (USB-CDC + BLE) with capability
  introspection. (`internal/flipper`)
- **Containerbridge-shape** — shell-out to a vendor CLI, parse stdout, no
  direct hardware ownership. (`internal/containerbridge`)

Cross-references the v0.8 team audit: see
[`docs/refactor/v0.8-team-audit.md` §2c](../refactor/v0.8-team-audit.md) for the
five backends already prioritised; this catalog extends that list.

---

## 1. ESP32-class platforms

ESP32 boards running offensive-security firmware. Marauder and Bruce are the
two existing PromptZero backends; this section lists alternatives and
complements.

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| ESP32 Marauder (justcallmekoko) | https://github.com/justcallmekoko/ESP32Marauder | $$ | active | USB-CDC, BLE | `go.bug.st/serial` (uart) | **yes** (`internal/marauder/`) | Bruce-shape (already wired) | — |
| Bruce firmware | https://github.com/BruceDevices/firmware / https://bruce.computer | $$ | active (repo moved from `pr3y/Bruce`) | USB-CDC | `go.bug.st/serial` | **yes** (`internal/bruce/`) | Bruce-shape (already wired) | — |
| GhostESP-Revival | https://github.com/GhostESP-Revival/GhostESP | $$ | community (original archived 2025-04-22) | USB-CDC, BLE | `go.bug.st/serial` | no | Bruce-shape (CDC-ACM menu) | `ghostesp_evil_portal`, `ghostesp_ble_spam_apple`, `ghostesp_pwnagotchi_friend`, `ghostesp_wardrive`, `ghostesp_rgb_status` |
| M5Stack Cardputer | https://shop.m5stack.com/products/m5stack-cardputer-kit-w-m5stamps3 | $$ | active | USB-CDC, BLE, Wi-Fi 4 | n/a (runs Bruce) | partial (via Bruce) | Bruce-shape | (covered by Bruce backend) |
| M5StickC PLUS2 | https://shop.m5stack.com/products/m5stickc-plus2-esp32-mini-iot-development-kit | $$ | active (vendor labels EOL on listing — fw active) | USB-CDC, BLE, Wi-Fi 4 | n/a (runs Bruce) | partial (via Bruce) | Bruce-shape | (covered by Bruce backend) |
| ESP32 Bus Pirate (geo-tp) | https://github.com/geo-tp/ESP32-Bus-Pirate | $$ | active | USB-CDC | `go.bug.st/serial` | no | Bus Pirate-shape | `esp32bp_i2c_scan`, `esp32bp_spi_dump`, `esp32bp_1wire_search`, `esp32bp_ir_replay`, `esp32bp_ble_recon` |
| M5MonsterC5 (ESP32-C5 hacking module) | https://www.cnx-software.com/2026/01/21/m5monsterc5-hacking-tool-adds-esp32-c5-and-5-ghz-wi-fi-6-support-to-m5stack-cardputer-adv-and-tab5/ | $$ | active (Jan 2026 release) | USB-CDC | n/a (runs Bruce/Marauder forks) | partial (via Bruce when has_5ghz set) | Bruce-shape | (capability-extended Bruce; `wifi_5ghz_scan`, `wifi6_he_recon`) |

**Notes.** GhostESP-Revival is a different feature set than Bruce — strong on
animated UI, RGB status, AppleJuice-style BLE spam, and a structured menu rather
than Bruce's freeform CLI; net-new capability rather than a duplicate. The
original Spooks4576 `Ghost_ESP` repo was archived 2025-04-22; do not target it.

---

## 2. HF / NFC platforms

13.56 MHz emulators and the LF/HF general-purpose Proxmark3 family. The Flipper
covers Mifare Classic 1K and basic ISO14443A, but lacks live emulation under
adversarial readers and high-speed nested-attack performance.

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| ChameleonUltra | https://github.com/RfidResearchGroup/ChameleonUltra | $$ ($120) | active | USB-CDC, BLE | none — Python `chameleon-cli` only | no | Flipper-shape (USB+BLE dual transport) | `chameleon_emulate_classic`, `chameleon_fm11rf08_backdoor`, `chameleon_relay_iso14443a`, `chameleon_dump_8slot`, `chameleon_clone_uid_block0` |
| ChameleonMini RevG | https://github.com/emsec/ChameleonMini | $$ | community (RFID Research Group fork active) | USB-CDC | none | no | Bruce-shape (CDC menu) | `chameleon_mini_emulate`, `chameleon_mini_dump`, `chameleon_mini_log_replay` |
| ChameleonTiny Pro | https://github.com/RfidResearchGroup/ChameleonMini | $$ | community (RRG fork) | USB-CDC, BLE | none | no | Flipper-shape | (subset of ChameleonMini Specs; portable form factor) |
| Proxmark3 RDV4 | https://github.com/RfidResearchGroup/proxmark3 | $$$ ($350+) | active (Iceman fork canonical) | USB-CDC | none — `pm3` CLI is the contract | no (federation only today) | Containerbridge-shape (shell out to `pm3` like mfoc/mfcuk) | `pm3_hf_search`, `pm3_lf_em4x_clone`, `pm3_iclass_loclass`, `pm3_fido_attack`, `pm3_hardnested_native` |
| Proxmark3 Easy | https://www.proxmarkbuilds.org / https://dangerousthings.com/product/proxmark3-easy/ | $$ ($60) | community | USB-CDC | same Iceman CLI | no | Containerbridge-shape (same `pm3` binary) | (Same Specs as RDV4 minus FPGA-heavy LF; flagged at runtime) |

**Notes.** The ChameleonUltra is the only platform that turns the FM11RF08S
backdoor key recovery (Quarkslab Aug 2024) into a one-shot operation —
synergistic with the `mifare_fm11rf08_backdoor` Spec already on the v0.8
roadmap. The Proxmark3 path is best treated as a containerbridge target; the
`pm3` CLI is the de-facto API and reimplementing its USB protocol in Go is
multi-month work.

---

## 3. Software-defined radio (SDR)

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| HackRF One | https://greatscottgadgets.com/hackrf/one/ | $$$ ($300) | active | USB 2.0 (libusb) | **`hz.tools/sdr/hackrf`**, `samuel/go-hackrf` | no | Faultier-shape (libusb bulk + state machine) | `hackrf_capture_iq`, `hackrf_replay_iq`, `hackrf_droneid_recv`, `hackrf_tetra_recv`, `hackrf_gsm_arfcn_scan` |
| PortaPack H4M (+ HackRF) | https://opensourcesdrlab.com/products/h4m-receiver-and-spectrum-analyzer | $$ ($152 bundle) | active (OpenSourceSDRLab; not GSG) | USB-CDC (Mayhem control) | none for Mayhem control yet | no | Bruce-shape (Mayhem CLI over CDC) | `mayhem_replay_sub`, `mayhem_pocsag_decode`, `mayhem_apt_decode`, `mayhem_aprs_decode`, `mayhem_ert_meter_read` |
| RTL-SDR Blog v4 | https://www.rtl-sdr.com/buy-rtl-sdr-dvb-t-dongles/ | $ ($30–40) | active | USB 2.0 (libusb) | **`jpoirier/gortlsdr`**, `hz.tools/sdr/rtl` | no | Faultier-shape (libusb async stream) | `rtlsdr_ads_b_scan`, `rtlsdr_acars_decode`, `rtlsdr_pocsag_decode`, `rtlsdr_lora_recv`, `rtlsdr_baseband_capture` (RX-only) |
| LimeSDR Mini 2.0 | https://www.crowdsupply.com/lime-micro/limesdr-mini-2 | $$$ ($399) | active (crowdfunded relaunch) | USB 3.0 | `LimeSuite` C-API; no native Go bindings | no | Containerbridge-shape (shell out to `LimeSuite` / SoapySDR) | `limesdr_full_duplex_capture`, `limesdr_lora_gw_recv` (lower priority — diminishing return vs HackRF) |
| BladeRF 2.0 micro xA4 | https://www.nuand.com/product/bladerf-xa4/ | $$$ ($540) | active | USB 3.0 | `libbladeRF` C-API; no Go bindings | no | Containerbridge-shape | (covers same band as HackRF with 56 MHz BW; deprioritise — niche over HackRF) |
| Ubertooth One | https://greatscottgadgets.com/ubertoothone/ | $$ | **EOL** (GSG, no manufacture plan) | USB-CDC | `libubertooth`; Python only | no | — (do not implement; superseded) | — |
| CatSniffer V3 | https://github.com/ElectronicCats/CatSniffer | $$ ($95) | active | USB-CDC (RP2040 bridge) | none — Python `cat_sniffer.py` + Sniffle | no | Bruce-shape (CDC + line proto) | `catsniffer_zigbee_capture`, `catsniffer_thread_capture`, `catsniffer_lora_sniff`, `catsniffer_ble5_sniffle`, `catsniffer_wmbus_decode` |

**Notes.** HackRF is the highest-leverage SDR add for v0.8: native Go bindings
exist (`hz.tools/sdr/hackrf`), DroneID/TPMS/GSM-ARFCN unlock follows directly,
and the OpenSourceSDRLab H4M makes a battery-portable variant available for
$152. PortaPack's Mayhem firmware can be controlled out-of-band over its
built-in CDC bridge — that's a separate Bruce-shape backend in front of the
HackRF binary backend, not a replacement.

Ubertooth is included **only** to mark it as EOL — Sniffle (TI CC1352) is the
2026 replacement and lives in §4 below.

---

## 4. BLE-focused sniffers

Pure-BLE platforms; lower-effort than full SDR, narrower capability.

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| Sniffle (TI CC1352 dongle) | https://github.com/nccgroup/Sniffle | $$ ($40 dongle + flash) | active | USB-CDC | none — Python `sniff_receiver.py` | no | Containerbridge-shape (shell to `sniff_receiver` + pcap pipe) | `sniffle_ble5_capture`, `sniffle_aux_pdu_decode`, `sniffle_findmy_observe`, `sniffle_extended_adv_dump` |
| nRF52840 Dongle (Nordic) | https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle | $ ($10) | active | USB-CDC | `tinygo.org/x/bluetooth` (host-side BLE central; runs on nRF firmware) | partial — used for Flipper BLE central transport | Flipper-shape (already wired in `internal/flipper` BLE) | `nrf_sniff_advertising`, `nrf_central_pair_attack`, `nrf_replay_4ghz` (with custom firmware) |
| Adafruit Bluefruit LE Friend | https://www.adafruit.com/product/2267 | $$ | active | USB-CDC | none | no | Bruce-shape | `bluefruit_passive_scan`, `bluefruit_pair_audit` (low priority — superseded by Sniffle) |

**Notes.** Sniffle is the modern Ubertooth replacement and the only commodity
sniffer that follows BLE 5 connections through PHY/CSA changes. Wrapping it as
a containerbridge backend (parsing the pcap stream) is faster than
reimplementing the Sniffle protocol in Go.

---

## 5. Glitching / fault injection

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| Faultier (Hextree) | https://hextree.io/shop/faultier | $$$ ($350) | active | USB-CDC (binary framing) | none — `internal/faultier` is the Go contract | **yes** (`internal/faultier/`) | Faultier-shape (already wired) | — |
| ChipSHOUTER | https://store.newae.com/chipshouter/ | $$$ ($3500+) | active | USB-CDC | NewAE Python `chipshouter` lib only | no | Faultier-shape (binary CDC) | `chipshouter_emfi_pulse`, `chipshouter_voltage_sweep`, `chipshouter_arm_pulse_disarm` |
| ChipSHOUTER PicoEMP | https://store.newae.com/chipshouter-picoemp / https://github.com/newaetech/chipshouter-picoemp | $$ ($133) | active | USB-CDC (MicroPython REPL) | none | no | Bus Pirate-shape (interactive REPL prompts) | `picoemp_emfi_pulse`, `picoemp_charge_discharge`, `picoemp_field_strength_test` |
| Riscure Spider / Inspector | https://www.riscure.com/security-tools/inspector | $$$$ (commercial, NDA) | active (commercial only) | USB / proprietary | closed source | no | **do not implement** — closed firmware, no public bring-up | — |

**Notes.** PicoEMP is the obvious complement to Faultier — different physics
(EM vs voltage rail) and complementary attack surface, low BOM cost. Riscure is
listed only to mark it as out-of-scope per the brief (closed firmware, no
public bring-up).

---

## 6. Bus / protocol analysers

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| Bus Pirate 5 / 5XL / 6 | https://buspirate.com / https://github.com/DangerousPrototypes/BusPirate5-firmware | $$ ($75–150) | active | USB-CDC | `go.bug.st/serial` (used today) | **yes** (`internal/buspirate/`) | Bus Pirate-shape (already wired) | — |
| GoodFET | https://github.com/travisgoodspeed/goodfet | $ | community (low maintenance, 2014-era) | USB-CDC, FTDI | Python `goodfet.py` | no | Bus Pirate-shape | (low priority — eclipsed by Bus Pirate 5 / Glasgow) |
| Glasgow Interface Explorer | https://github.com/GlasgowEmbedded/glasgow / https://www.crowdsupply.com/1bitsquared/glasgow | $$$ ($250) | active | USB-CDC | none — Python `glasgow` CLI | no | Containerbridge-shape (shell to `glasgow` applets) | `glasgow_jtag_scan`, `glasgow_swd_dump`, `glasgow_spi_flash_dump`, `glasgow_uart_passthrough`, `glasgow_i2c_arbitrary` |
| Saleae Logic Pro 16 | https://www.saleae.com/logic | $$$ ($1500) | active | USB 3.0 (libusb) | none — Saleae Logic 2 desktop only | no | — (capture-only; not a control surface) | (deprioritise — passive analyser, doesn't fit our backend abstraction) |
| BeagleBone Black + cape | https://beagleboard.org/black | $$ | active (community FW) | USB-CDC, Wi-Fi (variants) | n/a — full Linux SBC | no | Containerbridge-shape (SSH + remote exec) | (general-purpose host — not a backend per se; treat as federated MCP target) |

**Notes.** Glasgow is the most interesting net-new bus tool — its applet
architecture (JTAG, SWD, SPI flash, UART, I2C, 1-wire, USB) gives roughly the
union of Bus Pirate + GoodFET + cheap JTAG, with substantially better Python
tooling. Wrapping it as a containerbridge backend is straightforward.

---

## 7. Wi-Fi auditing

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| WiFi Pineapple Mark VII | https://shop.hak5.org/products/wifi-pineapple | $$$ ($110+) | active | Wi-Fi (REST), USB-CDC (recovery) | none — REST is JSON HTTP | no | Bruce-shape **but over HTTP** (REST client, not serial) — closest to `internal/web` shape | `pineapple_recon_scan`, `pineapple_pineap_evil_twin`, `pineapple_ssid_confusion`, `pineapple_pmkid_capture`, `pineapple_handshake_capture` |
| WiFi Pineapple Enterprise | https://shop.hak5.org/products/wifi-pineapple-enterprise | $$$$ ($2400) | active | Wi-Fi (REST), Eth, USB | identical REST contract | no | Same as Mark VII (capability-flag for high client count) | (capability-extended Mark VII — `pineapple_ent_100_clients`, `pineapple_ent_5ghz_audit`) |
| WiFi Coconut | https://shop.hak5.org/products/wifi-coconut | $$ ($150) | active | USB 3.0 (rt2800usb radios) | none — `hak5/hak5-wifi-coconut` C tool, Kismet datasource | no | Containerbridge-shape (shell to `wifi-coconut` → pcap) | `coconut_full_band_capture`, `coconut_kismet_passive`, `coconut_pmkid_harvest`, `coconut_ble_overlay_audit` |
| ALFA AWUS036ACM | https://www.alfa.com.tw/products/awus036acm | $$ ($45) | active | USB-A (mt7612u) | n/a — kernel driver | no | n/a — host adapter, not a separate backend | (Indirectly enables `internal/marauder`-class evil-twin from a Linux host) |
| ALFA AWUS1900 | https://www.alfa.com.tw/products/awus1900 | $$ ($65) | active | USB-A (rtl88xxau) | n/a — kernel driver | no | n/a — host adapter | (Same — host-side adapter for monitor mode/injection) |

**Notes.** WiFi Pineapple is the only REST-native target in this catalog — the
backend is a thin authenticated HTTP client over the Mark VII's documented
`/api/` surface, no serial code at all. Rough estimate: a dozen Specs ride on
`<10` HTTP endpoints.

ALFA cards are listed for completeness — they're host USB Wi-Fi adapters, not
controllable peripherals; their monitor-mode capability is consumed by Marauder
or Coconut workflows.

---

## 8. USB-HID / "drop-in" implants

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| USB Rubber Ducky (Mark II) | https://shop.hak5.org/products/usb-rubber-ducky | $$ ($80) | active | mass storage (DuckyScript 3.0 binary) | none — `hak5/usbrubberducky-payloads` is the script library | no | **Compile-only** — no live transport. Resembles `internal/fileformat` (build artefact + drop) | `ducky_compile_payload`, `ducky_payload_template_render`, `ducky_storage_attack_compile` |
| O.MG Cable | https://shop.hak5.org/products/omg-cable | $$$ ($180) | active | Wi-Fi (Web UI) | none — Web UI HTTP | no | Bruce-shape over HTTP (similar to Pineapple) | `omg_payload_push`, `omg_keystroke_reflect_capture`, `omg_geofence_arm`, `omg_self_destruct` |
| O.MG Plug | https://hak5.org/collections/mischief-gadgets/products/omg-plug | $$$ ($120) | active | Wi-Fi (Web UI) | identical to Cable | no | Same as O.MG Cable | (subset — power-strip form factor) |
| Hak5 Bash Bunny Mark II | https://shop.hak5.org/products/bash-bunny | $$$ ($120) | active | mass-storage (Linux+payload) | none — Bash payload library | no | Compile + drop, similar to Ducky | `bashbunny_compile_payload`, `bashbunny_geofence_arm`, `bashbunny_qmk_layout_attack` |
| Hak5 Shark Jack | https://shop.hak5.org/products/shark-jack | $$$ ($140) | active | Eth + Wi-Fi C2 | none — Bash + ICMP triggers | no | Containerbridge-shape (SSH C2) | `sharkjack_recon_run`, `sharkjack_dns_exfil_arm` |
| Hak5 Plunder Bug | https://shop.hak5.org/products/plunder-bug-lan-tap | $$ ($85) | active | USB-Eth (passive tap) | n/a — kernel sees as USB Eth | no | Host adapter (not a separate backend) | (capture-only — feed into existing pcap Specs) |

**Notes.** The Ducky pattern is unique: it's not a *transport* backend — there's
no live bidirectional channel to the Ducky from PromptZero. The "backend" is
the DuckyScript compiler and payload library. Same for Bash Bunny. O.MG and
Shark Jack do have live C2 surfaces (Wi-Fi WebUI / SSH respectively) and fit
HTTP-client / containerbridge patterns.

---

## 9. Hospitality / physical-access locks

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| Wiegotcha (HID R90 / Maxiprox 5375) | https://github.com/lixmk/Wiegotcha | $$ (RPi 3 + reader BOM) | community (last updated 2018; design stable) | Wi-Fi (RPi web UI) | none — Python + log file | no | Containerbridge-shape (SSH/HTTP + tail badge log) | `wiegotcha_capture_badge`, `wiegotcha_replay_badge_iclass`, `wiegotcha_replay_badge_prox` |
| ESPKey / ESP-RFID-Tool | https://github.com/rfidtool/ESP-RFID-Tool | $ ($25 BOM) | community | Wi-Fi (Web UI), serial | none — Web UI | no | Bruce-shape over HTTP (small REST surface) | `esprfid_capture_wiegand`, `esprfid_replay_wiegand`, `esprfid_clone_to_t5577` |
| HID Picopass / iClass reader | https://www.hidglobal.com/products/iclass-se-readers | $$$ (commercial) | active (vendor) | Wiegand only (no host control) | n/a — used as the *target* of an attack, not a backend | no | n/a (target, not backend) | — |

**Notes.** This category is mostly DIY captures — the reader itself isn't a
"backend" in our sense; the *capture host* (Pi or ESP32) is. Both Wiegotcha and
ESPKey are interesting Spec generators because they sit between Flipper's HF
read and the Proxmark3's sniff depth — a portable Wiegand recorder.

---

## 10. Automotive / CAN-bus

| Name | URL | Tier | Status | Connectivity | Go ecosystem | Existing backend? | Backend hint | Distinctive Specs unlocked |
|---|---|---|---|---|---|---|---|---|
| CANable v2.0 | https://canable.io | $ ($35) | active | USB-CDC (slcan) **or** native SocketCAN (candleLight FW) | **`go.einride.tech/can`**, `brutella/can` (SocketCAN) | partial — used by `internal/tools/canbus` shell-out | Bus Pirate-shape (slcan REPL) **or** SocketCAN containerbridge | `canable_passive_capture`, `canable_replay_frame`, `canable_uds_dtc_read`, `canable_iso_tp_dump`, `canable_canfd_capture` |
| CANtact Pro | https://linklayer.github.io/cantact-pro/ | $$ ($170) | active | USB-CDC | `linklayer/cantact-app` (Java); SocketCAN compatible | no (federation/host today) | Same as CANable | (CAN FD; superset of CANable Specs) |
| Macchina M2 | https://www.macchina.cc/m2-introduction | $$ ($130) | active | USB-CDC, OBD-II | Arduino + SavvyCAN; SocketCAN with `cantact` firmware | no | Bruce-shape (Arduino REPL) | `m2_obd2_dtc_read`, `m2_lin_capture`, `m2_j1850_decode`, `m2_swcan_replay`, `m2_dual_can_bridge` |

**Notes.** A SocketCAN-driven backend (CANable v2 + candleLight FW) is the
cheapest unlock for a real automotive Spec set; the native Go SocketCAN
bindings (`go.einride.tech/can`) are mature. Macchina M2 adds LIN/J1850/SWCAN
which CANable can't do — worth a second backend if automotive becomes a
priority area.

---

## Top-7 backends to add in v0.8

Ranked by `(capability unlock × developer-effort inverse × ecosystem
prevalence)`. Effort labels: **S** ≤ 1 week, **M** 1–3 weeks, **L** 3+ weeks.
Five of these were already flagged in
[`v0.8-team-audit.md` §2c](../refactor/v0.8-team-audit.md); two are net-new
from this deeper pass (marked **NEW**).

### 1. HackRF One + PortaPack H4M — **M**

**Why.** Highest single capability unlock in the catalog. Native Go bindings
exist (`hz.tools/sdr/hackrf`, `samuel/go-hackrf`). DroneID, TETRA, Tesla TPMS,
GSM-ARFCN sweep, ADS-B injection — none reachable from the Flipper's CC1101
alone. PortaPack H4M makes the same hardware battery-portable and adds a
Mayhem-CLI control surface for ~$152 bundled with the radio. The audit ranked
this #1 in §2c — confirmed.

**Resembles.** `internal/faultier/` for the libusb bulk-transfer + state
machine; an *additional* `internal/portapack/` would be Bruce-shape (CDC menu
to Mayhem). Two cooperating sub-backends.

### 2. ChameleonUltra — **M**

**Why.** Closes the HF emulation gap (Flipper can read but is unreliable as a
live emulator under adversarial readers) and is the natural carrier for the
`mifare_fm11rf08_backdoor` Spec already on the v0.8 roadmap (Quarkslab
Aug 2024). 8-slot card storage, BLE control via `chameleon-cli`. Audit ranked
this #2 — confirmed.

**Resembles.** `internal/flipper/` — same dual USB-CDC + BLE transport pattern,
including capability negotiation over the BLE GATT service.

### 3. Proxmark3 (Iceman) **NEW** — **S**

**Why.** Not in audit §2c, but on second look the gap is large: ChameleonUltra
emulates HF but doesn't sniff/decrypt LF EM4x or iClass to the depth Iceman
firmware does. The `pm3` CLI is a stable, scriptable contract; we can land it
as a containerbridge target in days. Pairs with the audit's
`workflow_iclass_pickup` (Picopass → Seader → loclass → emulate) — Proxmark3 is
the sniff-and-loclass leg.

**Resembles.** `internal/containerbridge/` — shell out to `pm3` exactly the way
mfoc/mfcuk are shelled out today, parsing structured stdout.

### 4. WiFi Pineapple Mark VII — **S**

**Why.** REST-native — every Spec is essentially a JSON HTTP POST. No serial
state machine, no parsing brittleness. Synergy with the SSID-Confusion attack
(Vanhoef WiSec'24) the audit highlights. Fastest "lots of Specs for not much
code" backend in the catalog. Audit ranked this #3 — confirmed.

**Resembles.** Closer to `internal/webhook/` or `internal/web/` (HTTP client
with auth) than any of the serial backends. Backend interface is identical;
transport is `*http.Client`, not `serial.Port`.

### 5. GhostESP-Revival — **S**

**Why.** Lowest-effort additional ESP32 firmware; mirrors Bruce structurally
and gives a different attack-feature set (animated Evil Portal, AppleJuice-style
BLE spam, Pwnagotchi handshake-friend mode, RGB status). Cheap to land
*because* Bruce already exists — it's a parser swap, not a new transport.
Audit ranked this #4 — confirmed.

**Resembles.** `internal/bruce/` ~80% verbatim. Strong candidate to seed the
deferred `internal/esp32backend/` shared core (audit cross-cut decision #4).

### 6. CatSniffer V3 / Sniffle dongle **NEW** — **M**

**Why.** Not in audit §2c. Fills the BLE-sniffing and Zigbee/Thread/LoRa gap
— Sniffle (TI CC1352) is the modern Ubertooth replacement and the *only*
commodity tool that follows BLE 5 connections through PHY/CSA hops. CatSniffer
V3 packages Sniffle + LoRa + Zigbee in one $95 USB stick. With BLE attacks
(FindMy emulation, AirTag tracking, KeyTrap) accelerating in 2025–26, the lack
of a sniffer backend is a real gap.

**Resembles.** `internal/buspirate/` for the CDC-ACM REPL bridge; alternately
containerbridge to `sniff_receiver.py` if we don't want to reimplement the
Sniffle command protocol in Go.

### 7. USB Rubber Ducky (Mark II) — **S**

**Why.** Trivial, but enables a whole class of host-side attack Specs. The
"backend" is a DuckyScript 3.0 compiler + payload-library lookup, not a
transport — no runtime hardware coupling. Useful as a workflow leaf
(post-physical-access drop). Audit ranked this #5 — confirmed.

**Resembles.** `internal/fileformat/` — produces a build artefact, doesn't own
hardware. Doesn't need the `Backend` interface from Phase 1; it's a tool
generator.

---

## Out of scope (deliberately omitted)

- **Ubertooth One** — EOL, Sniffle replaces it.
- **Original Spooks4576 GhostESP** — archived 2025-04-22; use the Revival fork.
- **SubSpectra** — archived 2026-01-04 (per audit).
- **Riscure Inspector / Spider** — closed firmware, NDA tooling, no public
  bring-up path.
- **Saleae Logic** — passive capture only, doesn't fit the active-control
  backend abstraction; handle via pcap import if ever needed.
- **HID Picopass / iClass reader (vendor)** — these are *targets*, not
  backends; only the capture host is.
- **BeagleBone + capes** — full Linux SBC; treat as a federated MCP target
  rather than a hardware backend (it's a host, not a peripheral).
- **5G test gear (5Ghoul / SNI5GECT)** — out per audit.
- **Mifare Plus EV2 SL3 / DESFire EV2/EV3** — no public PoC, AES-128 holds
  (per audit).
