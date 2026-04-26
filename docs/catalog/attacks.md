# Catalog: Attack PoCs (2024-01-01 → 2026-04-25)

Public attack research and proof-of-concept code published in the
2024-2026 window relevant to PromptZero's tool surface (Flipper Zero,
adjacent SDR, NFC/RFID, BLE, 802.11, Sub-GHz, automotive radio).
Audience: red-team / pentesters / researchers using PromptZero for
authorized testing under AGPL-3.0.

**Date strictness.** Entries are dated by primary publication of the
attack (paper, talk, or PoC repo first push) within
2024-01-01 → 2026-04-25. A small number of pre-2024 entries are kept
where the published PoC code or new disclosed CVEs landed in-window.
Each entry calls out the publication date explicitly.

**Cross-reference with `docs/refactor/v0.8-team-audit.md` §2a.** The
prior team audit ranked five attacks for early implementation:
`mifare_fm11rf08_backdoor`, `nfc_unsaflok_forge`,
`subghz_rollback_detect`, `wifi_ssid_confusion`, `dronid_receive`.
This catalog **confirms all five** as real, in-window, with public
PoCs — they remain solid picks. It adds breadth (TPMS family, BLE
proximity-tracking, 2TETRA:2BURST, Pwn2Own Auto chains, BadUSB
forensics, Apple Continuity tooling, Vanhoef Fragile-Frames follow-up,
nRootTag) that the §2a list missed. The Top-15 ranking at the end
**re-prioritises**: it puts `subghz_tpms_decode` (rtl_433 port,
trivial) above the original §2a #5 (`dronid_receive`, blocked on
HackRF backend), and adds `nroottag_emulate`,
`apple_continuity_classify`, `wifi_pmkid_capture` ahead of slower
research-grade items.

**Constraints honoured.** No links to dark-web/criminal forums. No
fabricated CVE numbers — every CVE cited was verified on NVD/MITRE or
the vendor advisory. Malware-only "research" without defensive context
(e.g. the Telegram/dark-web "DarkWeb"/"Private-Unleashed 2.0" custom
firmwares) is *not* catalogued; the academic RollBack paper that they
derive from *is*.

---

## Mifare Classic / Plus / DESFire

### MIFARE Classic: exposing the static encrypted nonce variant... and a few hardware backdoors
- **Year/venue**: 2024-08-13, IACR ePrint 2024/1275 + Quarkslab blog;
  presented at hardwear.io NL Oct 2024 and CESAR 2024.
- **Author/team**: Philippe Teuwen (Quarkslab).
- **Paper URL**:
  https://eprint.iacr.org/2024/1275 ·
  https://blog.quarkslab.com/mifare-classic-static-encrypted-nonce-and-backdoors.html
- **PoC repo**: Tooling merged into Iceman Proxmark3 (`hf mf` family)
  and Flipper Unleashed/Momentum nfc apps; reference C in the paper
  annexes.
- **Required hardware**: Proxmark3 / ChameleonUltra / Flipper Zero
  (the latter with custom firmware able to send the magic auth).
- **Implementability**: **Native-Go**. Static-encrypted-nonce is a
  pure-cryptanalysis attack over Crypto1 — already partly modelled in
  `internal/crypto1/`. The hardware backdoor key is a single AUTH-with-
  fixed-key probe.
- **Primitive**: Read-only key recovery on
  Fudan FM11RF08S/FM11RF08/FM11RF32 and similar
  NXP/Infineon "Mifare-compatible" silicon, **without** needing a
  known sector key. Confirmed §2a entry; should remain top priority.

### Hardnested attack consolidation (revision tracking 2024-2025)
- **Year/venue**: ongoing — the Quarkslab paper above also serves as
  a current SoK on Crypto1 attacks (darkside / nested / hardnested /
  static-nested).
- **Paper URL**: same as above.
- **PoC repo**: https://github.com/RfidResearchGroup/proxmark3 (Iceman)
  ; https://github.com/nfc-tools/miLazyCracker (libnfc front-end).
- **Required hardware**: Any libnfc reader (ACR122/PN532) or PM3.
- **Implementability**: **Container-bridge** today (we ship hardnested
  via container). A native Go port is ~2 kloc bitslice — see §2 of
  v0.8 audit for the explicit decision to *not* port.
- **Primitive**: Existing — keep documented, do not duplicate.

---

## iCLASS / Picopass / SEOS / Seader

### Picopass / iCLASS legacy emulation with dummy-MAC
- **Year/venue**: 2024 community write-ups + Flipper app development.
- **Author/team**: bettse + Flipper community; HID Global has issued
  iCLASS SE CP1000 advisories in the same window (NVD does not list a
  CVE under the cited "CVE-2024-41566" identifier at write time —
  reference removed pending verification).
- **PoC repo**: https://github.com/flipperdevices/flipperzero-good-faps
  (`picopass` app) ; PM3 `hf iclass` family.
- **Required hardware**: Flipper Zero or Proxmark3 + iCLASS-compatible
  reader.
- **Implementability**: **Native-Go**. The dummy-MAC behaviour is a
  small change in the existing `internal/iclass/` emulation path.
- **Primitive**: Emulate iCLASS legacy credential to a reader without
  knowing the reader's MAC keys — opens lab / red-team workflows that
  today require PM3.

### iCLASS SE / SEOS downgrade research
- **Year/venue**: 2024-2025, gist + community write-ups;
  no peer-reviewed paper.
- **Author/team**: kitsunehunter + RfidResearchGroup contributors.
- **Reference**:
  https://gist.github.com/kitsunehunter/c75294bdbd0533eca298d122c39fb1bd
  · https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/hid_downgrade.md
- **Required hardware**: Proxmark3 RDV4 (recommended) + SE/SEOS card +
  reader allowing legacy fallback.
- **Implementability**: **Federation-only** (proxmark3 specialist
  surface). PromptZero plumbs PM3 via the federation prefix.
- **Primitive**: Read PACS payload from a SIO and re-encode as legacy
  iCLASS or H10301 Wiegand — bypasses SE/SEOS upgrade if reader has
  legacy enabled.

### loclass on Elite — historical, kept for completeness
- **Year/venue**: pre-2024 algorithm; PM3 implementation actively
  maintained 2024-2025.
- **Implementability**: **Container-bridge** — already covered by
  v0.7 native loclass port (`internal/iclass/loclass.go`).
- **Primitive**: Existing.

---

## HID Prox / Wiegand

### ESP-RFID-Tool / ESPKey passive Wiegand sniffing
- **Year/venue**: tool maintained 2024-2025 (no academic venue).
- **Author/team**: rfidtool (ESPKey) ; Hak5 (Tastic) ; Bishop Fox.
- **PoC repo**: https://github.com/rfidtool/ESP-RFID-Tool
- **Required hardware**: ESP8266/ESP32 module wired in-line with the
  reader's Wiegand DATA0/DATA1 lines.
- **Implementability**: **Container-bridge** (ESP-RFID-Tool ships its
  own web UI) **+ Native-Go** Wiegand parser (`internal/iclass/`
  cousin). Replay is bit-exact and format-agnostic.
- **Primitive**: `gpio_wiegand_capture` + `gpio_wiegand_replay` Specs
  — already in §2b roadmap. Confirms that direction.

---

## BLE — Continuity, Find My, AirTag/SmartTag/Tile, AirDrop

### nRootTag — turning any BLE device into an AirTag
- **Year/venue**: 2025-02-26 disclosure → USENIX Security 2025 +
  DEF CON 33 Demo Labs 2025-08.
- **Author/team**: Junming Chen, Qiben Yan et al. (George Mason
  University).
- **Paper URL**:
  https://cs.gmu.edu/~zeng/papers/2025-security-nrootgag.pdf
- **PoC repo**: https://github.com/Chapoly1305/nroottag
- **Required hardware**: Any BLE-capable device (ESP32 / nRF52 /
  Linux + BlueZ); GPU recommended for the key-search step.
- **Implementability**: **Native-Go** for the advertise/key-search
  primitive (Marauder/Bruce can advertise; key search is a small
  brute-force loop). The OpenHaystack key derivation is well
  documented.
- **Primitive**: Spoof a Bluetooth device into the global Find-My
  network with 90 % success — `ble_findmy_emulate` Spec, already
  named in §2b. nRootTag is the strongest 2024-2026 PoC backing it.

### Stealtooth — silent automatic-pairing abuse
- **Year/venue**: 2025-07, arXiv 2507.00847.
- **Author/team**: Y. Sasaki et al.
- **Paper URL**: https://arxiv.org/abs/2507.00847
- **PoC repo**: not public at write time.
- **Required hardware**: BLE-capable host with raw HCI
  (BlueZ on Linux).
- **Implementability**: **Research-only** until the authors release
  code. Mark for tracking; do not invest yet.
- **Primitive**: Forced-pairing without any user interaction on
  affected target stacks.

### A Thorough Security Analysis of BLE Proximity Tracking Protocols
- **Year/venue**: USENIX Security 2025 (Aug 2025).
- **Author/team**: Xiaofeng Liu et al.
- **Paper URL**:
  https://www.usenix.org/system/files/usenixsecurity25-liu-xiaofeng.pdf
- **PoC repo**: not public; Samsung fixed five issues with author
  assistance.
- **Required hardware**: BLE host capable of passive sniffing
  (Sniffle / nRF52 / Ubertooth replacement).
- **Implementability**: **Research-only**. Defensive primitive is
  worthwhile: a long-running passive-sniff classifier that flags
  Find-My / Find-My-Mobile abuse patterns.
- **Primitive**: `ble_proximity_audit` (defensive).

### Apple BLE-spam / "AppleJuice" lockup
- **Year/venue**: PoC pushed 2023-09 → 2024-Q1 patches; CVE pre-dates
  window but the **Flipper Zero apple_ble_spam_ofw** port was first
  released 2024-02 by `noproto`.
- **CVE**: CVE-2023-42941 (verified on NVD; iOS 17.2 fix).
- **PoC repo**: https://github.com/noproto/apple_ble_spam_ofw ;
  https://ecto-1a.github.io/AppleJuice_CVE/ (writeup).
- **Required hardware**: Flipper Zero (OFW) or any BLE host that
  can edit advertisement payloads.
- **Implementability**: **Native-Go** advertiser via Bruce/Marauder
  backend. We **explicitly do not** add this offensively per project
  scope; defensive classifier (detect pattern, alert) is appropriate.
- **Primitive**: `ble_continuity_classify` defensive — pairs with
  audit's "apple_continuity_audit" workflow §2d.

### furiousMAC continuity dissector — ongoing 2024-2025 maintenance
- **Year/venue**: continuous; latest commits 2025.
- **Author/team**: US Naval Academy FuriousMAC group.
- **PoC repo**: https://github.com/furiousMAC/continuity
- **Required hardware**: any BLE sniffer (Sniffle, nRF52 dongle,
  Ubertooth, Marauder).
- **Implementability**: **Native-Go** packet parser (port the
  Wireshark dissector to Go). Drop-in for Marauder pcap output.
- **Primitive**: Decode Apple Continuity messages (Handoff, AirDrop,
  Nearby, AirPods) — feeds the defensive classifier above.

---

## 802.11

### SSID Confusion — making clients connect to the wrong network
- **Year/venue**: ACM WiSec 2024 (best paper award).
- **Author/team**: Héloïse Gollier, Mathy Vanhoef (KU Leuven /
  DistriNet).
- **CVE**: CVE-2023-52424 (verified on NVD).
- **Paper URL**: https://papers.mathyvanhoef.com/wisec2024.pdf
- **PoC repo**: https://github.com/vanhoefm/ssid-confusion-hostap
- **Required hardware**: Linux + hostap fork; any 802.11 NIC with
  monitor/AP support; Pineapple or Marauder where ESP can run a
  rogue AP.
- **Implementability**: **Native-Go** orchestration over a Pineapple
  REST backend (§2c #3) or a Bruce/Marauder evil-twin extension. The
  attack is essentially "spin up an AP with the victim SSID to bait
  the same credential set."
- **Primitive**: Confirmed §2a entry. Full surface is
  `wifi_ssid_confusion` Spec.

### Fragile Frames — Wi-Fi's fraught fight against FragAttacks
- **Year/venue**: ACM WiSec 2025.
- **Author/team**: Siebe Devroe, Héloïse Gollier, Mathy Vanhoef.
- **Paper URL**: https://papers.mathyvanhoef.com/wisec2025.pdf
- **PoC repo**: framework lives at
  https://github.com/vanhoefm/fragattacks (extended through 2025).
- **Required hardware**: Linux box + 802.11 adapter able to inject;
  the original FragAttacks suite.
- **Implementability**: **Container-bridge** (the test framework is
  Python + raw injection — wrap as a containerised Spec).
- **Primitive**: `wifi_fragattacks_audit` — measures whether a
  surveyed AP/client is still vulnerable to frame-fragmentation /
  A-MSDU mixed-key issues four years later.

### CVE-2023-52160 — wpa_supplicant PEAP phase-2 bypass
- **Year/venue**: NVD published 2024-02-22; advisory by Top10VPN
  + Mathy Vanhoef.
- **CVE**: CVE-2023-52160 (verified on NVD).
- **Reference**: https://nvd.nist.gov/vuln/detail/CVE-2023-52160 ·
  https://www.top10vpn.com/research/wifi-vulnerability-ssid/ (vendor
  advisory) · fix in hostap 2.11
  (https://lists.infradead.org/pipermail/hostap/2024-July/042847.html).
- **PoC repo**: no canonical public PoC — the bypass is a single
  malformed EAP-TLV Success packet; reproducible with patched
  hostapd from the original advisory.
- **Required hardware**: Linux + hostapd to host the rogue Enterprise
  network; victim is any wpa_supplicant ≤ 2.10 client without
  `ca_cert` configured.
- **Implementability**: **Container-bridge** (rogue-AP setup is
  hostapd-driven); a Pineapple backend will expose this directly.
- **Primitive**: `wifi_peap_downgrade_audit` — adjacent to SSID
  Confusion in target audience and tooling.

### PMKID + EAPOL-M2 capture pipeline (hcxdumptool / hashcat 22000)
- **Year/venue**: tooling continually updated 2024-2026; hashcat
  mode 22000 is the unified target format since 2021. Notable
  hcxdumptool modernisation 2024.
- **Author/team**: ZerBea (hcxdumptool) ; Hashcat Team.
- **PoC repo**: https://github.com/ZerBea/hcxdumptool ;
  https://github.com/hashcat/hashcat
- **Required hardware**: Linux + monitor-mode adapter; or any rogue
  AP backend that can deauth + capture.
- **Implementability**: **Container-bridge**. Today's Marauder PMKID
  capture covers the over-the-air half; hashcat lives in a container.
- **Primitive**: `wifi_pmkid_capture` + `crack_wpa_22000` (federated).

---

## Sub-GHz RKE

### RollBack — time-agnostic replay against rolling-code RKE
- **Year/venue**: ACM Trans. Cyber-Phys. Syst., published 2024-01-30
  (final journal version); first BlackHat USA 2022 talk.
- **Author/team**: L. Csikor, H. Lim, J. W. Yoon, et al.
- **Paper URL**: https://dl.acm.org/doi/10.1145/3627827 ·
  preprint https://arxiv.org/abs/2210.11923
- **PoC repo**: tools for the original talk are referenced in the
  BlackHat materials
  (https://i.blackhat.com/USA-22/Thursday/US-22-Csikor-RollBack-A-New-Time-Agnostic-Replay-Attack.pdf)
  ; a generic Flipper Sub-GHz capture+ordered-replay implementation
  is community-grade.
- **Required hardware**: Flipper Zero or HackRF for capture; Flipper
  for replay.
- **Implementability**: **Native-Go** capture-only detection
  (`subghz_rollback_detect`) is the right call (per §2a). Offensive
  replay is intentionally *not* implemented per project policy.
- **Primitive**: Confirmed §2a entry.

### Grand Theft Auto — RF Locks Hacking, Flipper Zero Edition Part 2
- **Year/venue**: Chaos-Security-Lab blog, 2024-09-07.
- **Author/team**: Kevin2600 (independent).
- **Paper/blog URL**:
  https://kevin2600-cmd.github.io/2024/09/07/Grand-Theft-Auto-RF-Locks-Hacking-Flipper-Zero-Edition-Part2.html
- **PoC repo**: see linked Flipper apps in the post.
- **Required hardware**: Flipper Zero + (optional) HackRF for
  jamming.
- **Implementability**: **Container-bridge** — the actual rolljam
  workflow is already in PromptZero scenarios; the post catalogues
  per-vendor protocol fingerprints.
- **Primitive**: per-vendor RKE classifier — feeds protocol
  attribution into the existing rolljam lab demo.

### SoK: Stealing Cars Since RKE Introduction (and how to defend)
- **Year/venue**: USENIX VehicleSec 2025-08.
- **Author/team**: Tommaso Bianchi, Alessandro Brighente, Mauro Conti,
  Edoardo Pavan (Univ. Padova).
- **Paper URL**:
  https://www.usenix.org/system/files/vehiclesec25-bianchi.pdf ·
  preprint https://arxiv.org/abs/2505.02713
- **PoC repo**: SoK; references a published taxonomy, not a single
  exploit.
- **Required hardware**: per-attack varies (HackRF, Flipper, BLE
  hosts).
- **Implementability**: **Research-only** as a single artifact, but
  it's the best 2024-2026 defensive map of the entire RKE/PKES
  surface — useful as a roadmap for which workflows to build next.
- **Primitive**: documentation; influence the priorities below.

### Pwn2Own Automotive 2024 / 2025 / 2026 — modem, infotainment, EV chargers
- **Year/venue**: ZDI Pwn2Own Automotive — Tokyo Jan 2024,
  Jan 2025, Jan 2026.
- **Notable winners / disclosures**:
  - 2024: Synacktiv 3-bug Tesla modem chain ($100 k); Tesla VCSEC
    integer-overflow chain (later CVE-2025-2082, see TPMS section).
  - 2025: 49 zero-days; ChargePoint, Ubiquiti Connect EV stations.
  - 2026: 76 zero-days; Autel & Phoenix Contact EV chargers; Tesla
    interfaces.
- **Reference URLs**:
  https://www.zerodayinitiative.com/Pwn2OwnAuto2026Rules.html ·
  https://vicone.com/blog/pwn2own-automotive-2026-uncovering-37-unique-zero-days
- **Implementability**: **Federation-only**. These are individual ECU
  firmware exploit chains; the right surface for PromptZero is to
  *consume* the resulting CVEs (e.g. CVE-2025-2082 below) when they
  have radio reach.
- **Primitive**: ingest disclosed CVEs into the recon prompts.

---

## Sub-GHz TPMS

### Tesla VCSEC TPMS RCE — CVE-2025-2082
- **Year/venue**: discovered Pwn2Own Automotive 2024-01; ZDI advisory
  2025-04-30; fixed in Tesla firmware 2024.14.
- **Author/team**: Synacktiv (David Berard, Vincent Dehors, Tanguy
  Dubroca).
- **CVE**: CVE-2025-2082 (verified on NVD; CVSS 7.5).
- **Reference**:
  https://nvd.nist.gov/vuln/detail/CVE-2025-2082 ·
  https://vicone.com/blog/under-pressure-exploring-a-zero-click-rce-vulnerability-in-teslas-tpms
- **Required hardware**: BLE-capable adjacent attacker — Tesla TPMS
  uses BLE for Model 3 newer trims, not the legacy 315/433 MHz ASK.
- **Implementability**: **Research-only** for the RCE itself
  (firmware-specific). **Native-Go** for a defensive
  `tpms_anomaly_detect` Spec that flags malformed VCSEC certificate
  exchanges.
- **Primitive**: detection only — re-confirms §2a TPMS direction
  and the v0.8 audit's cross-referenced "TPMS decode/synth"
  priority.

### rtl_433 TPMS decoder family — Schrader / Citroën / Renault / Toyota / Ford
- **Year/venue**: rtl_433 project; in-window decoder additions
  through 2024-2025 (e.g. Toyota TPMS, Schrader PA66GF35 tests).
- **Author/team**: merbanan + many community contributors.
- **PoC repo**: https://github.com/merbanan/rtl_433
  - https://github.com/merbanan/rtl_433/blob/master/src/devices/schraeder.c
  - https://github.com/merbanan/rtl_433/blob/master/src/devices/tpms_renault.c
  - https://github.com/merbanan/rtl_433/blob/master/src/devices/tpms_citroen.c
  - https://github.com/merbanan/rtl_433/blob/master/src/devices/tpms_toyota.c
  - https://github.com/merbanan/rtl_433/blob/master/src/devices/tpms_ford.c
- **Required hardware**: any RTL-SDR, HackRF, or PortaPack (315 /
  433.92 MHz).
- **Implementability**: **Native-Go**. Each decoder is ~150 lines of
  C operating on a Manchester / differential-Manchester bitstream —
  trivial to port. Synth (TX) is the reverse and equally small.
- **Primitive**: `subghz_tpms_decode` + `subghz_tpms_synth` Specs
  named in §2b — confirmed direction; this is the highest-ROI single
  unit of work we still owe.

---

## KeeLoq

The 2024-2026 window did **not** produce a new manufacturer-key
recovery in the literature. The actively-traded "DarkWeb" /
"Private-Unleashed 2.0" Flipper firmwares appear to combine the
2008 Bochum power-analysis manufacturer keys with the 2024
RollBack resync, applied across vendor lookup tables. We **do not
catalogue** the criminal firmware itself; the underlying academic
basis is already covered by the RollBack entry.

The right defensive primitive remains a per-vendor KeeLoq
classifier feeding the existing `subghz_rollback_detect` workflow.

---

## DroneID / Remote ID

### Drone Security and the Mysterious Case of DJI's DroneID
- **Year/venue**: NDSS 2023 — primary paper sits one year *before*
  the catalog window, but the **public PoC release on GitHub** and
  downstream tooling (AntSDR E200 port, dronescout receivers)
  landed in 2024.
- **Author/team**: N. Schiller, M. Chlosta, M. Schloegel, et al.
  (RUB-SysSec).
- **Paper URL**:
  https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f217_paper.pdf
- **PoC repo**: https://github.com/RUB-SysSec/DroneSecurity ·
  https://github.com/RUB-SysSec/DroneSecurity-Fuzzer
- **Required hardware**: HackRF (or AntSDR / USRP) — receiver-only;
  no transmit needed for the catalog primitive.
- **Implementability**: **Native-Go** orchestration around HackRF
  capture → DroneID decoder. Decoder itself can be either ported or
  exec'd as a thin container.
- **Primitive**: Confirmed §2a `dronid_receive` entry. Blocked on
  HackRF backend (§2c #1) — that's the right sequencing.

### Selective Authenticated Pilot Location Disclosure for Remote ID
- **Year/venue**: PoPETs / PETS 2024.
- **Author/team**: Pietro Tedeschi et al.
- **Paper URL**:
  https://crysp.petsymposium.org/popets/2024/popets-2024-0091.pdf
- **PoC repo**: defensive protocol design — no direct exploit code.
- **Required hardware**: receiver-side same as DroneID.
- **Implementability**: **Research-only** (a defensive protocol
  proposal, not an attack).
- **Primitive**: informs design of `dronid_decode` defensive policy.

### droneRemoteIDSpoofer — ASTM F3411 / EN 4709-002 spoofer
- **Year/venue**: PoC public 2024 (cyber-defence-campus / armasuisse).
- **PoC repo**: https://github.com/cyber-defence-campus/droneRemoteIDSpoofer
- **Required hardware**: Linux + Wi-Fi NIC with monitor/inject and
  a BLE adapter; or ESP32.
- **Implementability**: **Container-bridge** (Python + scapy raw
  802.11 + BLE). A Marauder/Bruce wrapper could synth the BLE
  variant natively.
- **Primitive**: TX side of `dronid_*` — explicitly *not* in scope
  for v0.8 per the project's defensive posture; surface as a
  detection-pattern feed only.

---

## TETRA

### 2TETRA:2BURST — follow-up TETRA disclosures
- **Year/venue**: BlackHat USA 2025-08 disclosure ; Midnight Blue.
- **Author/team**: Carlo Meijer, Wouter Bokslag, Jos Wetzels
  (Midnight Blue).
- **CVEs (verified)**:
  - CVE-2025-52941 — TETRA E2EE AlgoID 135 entropy reduction
    128 → 56 bits.
  - CVE-2025-52943 — multi-AIE-cipher network key-recovery.
  - CVE-2025-52944 — packet-injection on TETRA networks.
  - MBPH-2025-001 — ETSI's CVE-2022-24401 fix is incomplete
    (no CVE assigned at write time).
- **Reference**: https://www.midnightblue.nl/research/2tetra2burst ·
  https://www.midnightblue.nl/research/retetra
- **Existing PoC**: https://github.com/MidnightBlueLabs/TETRA_burst
  · https://github.com/MidnightBlueLabs/TETRA_crypto
- **Required hardware**: SDR (USRP / HackRF) + Motorola/Sepura
  baseband knowledge.
- **Implementability**: **Research-only** (matches the v0.8 audit's
  explicit "researchable, not implementable today" tagging).
- **Primitive**: track for future federation; do not port.

---

## Automotive CAN / UDS / DoIP

### UDS-on-DoIP fuzzing-discovered attacks (DEF CON 32 Car Hacking
Village)
- **Year/venue**: DEF CON 32 / 2024-08.
- **Author/team**: multiple (Red Balloon, independents).
- **Reference**: https://redballoonsecurity.com/dc32-car-hacking-ctf/ ·
  village schedule https://www.carhackingvillage.com/defcon-32-talks
- **Required hardware**: OBD-II adapter or DoIP-capable Ethernet
  ECU access.
- **Implementability**: **Container-bridge** (existing `canbus_*`
  Specs + `cantools` / `python-uds` containers).
- **Primitive**: extend the existing `canbus_replay` workflow with
  a UDS-attack catalogue (negative SecurityAccess, denial-of-service
  diagnostic states).

### ISO 15118 EVCC research — DEF CON 32 + IEEE
- **Year/venue**: DEF CON 32 2024-08.
- **Reference**: same village schedule above.
- **Required hardware**: PLC (powerline-communication) modem +
  CCS-capable test rig.
- **Implementability**: **Federation-only** (PLC is out of the
  Flipper / Marauder / HackRF surface).
- **Primitive**: documentation entry only.

---

## USB attack class (BadUSB / Rubber Ducky)

### Wireshark BadUSB dissector + DuckyScript reconstructor
- **Year/venue**: tooling update 2024.
- **Author/team**: agentzex.
- **PoC repo**: https://github.com/agentzex/FlipperZero-BadUSB-Wireshark
- **Required hardware**: Linux host + Wireshark with USB capture
  (usbmon).
- **Implementability**: **Native-Go** — port the dissector logic
  for forensic post-mortem of captured USB streams. Pairs well with
  the existing Flipper BadUSB Specs.
- **Primitive**: `usb_badusb_classify` defensive — given a usbmon
  pcap, reconstruct DuckyScript and flag indicators.

### Forensic analysis of BadUSB attacks
- **Year/venue**: 2024 academic article (Learning Gate journal).
- **Reference**:
  https://learning-gate.com/index.php/2576-8484/article/download/1809/650/3116
- **Implementability**: **Research-only** (forensic methodology).

---

## Smart-lock / hospitality

### Unsaflok — Saflok / dormakaba RFID hotel lock chain
- **Year/venue**: Disclosed 2024-03; talks at DEF CON 32 (2024-08).
- **Author/team**: Lennert Wouters, Ian Carroll, rqu, BusesCanFly,
  Sam Curry, sshell, Will Caruana.
- **Reference**: https://unsaflok.com/ ·
  https://cybersecurity-research.be/unsaflok-how-researchers-unlocked-millions-of-hotel-doors-with-two-taps/
  · DEF CON 32 talk: "Unsaflok: Hacking millions of hotel locks".
- **Public technical details**: the team has *not* released a
  step-by-step PoC repo (deliberately, while remediation is at ~36 %).
- **Required hardware**: any Mifare-Classic-capable writer
  (Flipper, ChameleonUltra, Proxmark3).
- **Implementability**: **Native-Go** — Mifare Classic write surface
  already exists in `internal/crypto1/` + Flipper write paths; the
  Saflok-specific KDF is documented in published talk materials.
- **Primitive**: Confirmed §2a `nfc_unsaflok_forge` entry. Should
  ship gated behind `lab_consent=true` and `ethics_acknowledged=true`.

---

## 5G — researchable, not implementable

### 5G-SPECTOR — L3 protocol exploit detection on O-RAN
- **Year/venue**: NDSS 2024.
- **Reference**: paper available via NDSS proceedings (2024 program).
- **Implementability**: **Research-only** — needs O-RAN gNB hardware
  out of scope.

### 5Ghoul / SNI5GECT (continued, pre-window)
- Out of date window for primary publication; v0.8 audit explicitly
  marks "do not pursue."

---

## Top-15 implementable ranking

Effort tags: **S** = days, **M** = 1-2 weeks, **L** = 3+ weeks.
"Pkg extends" names the existing `internal/<pkg>/` the work would
ride on.

| # | Spec name | Source attack | Effort | Pkg extends | Notes |
|---|---|---|---|---|---|
| 1 | `subghz_tpms_decode` (+ `_synth`) | rtl_433 TPMS family | **S** | `subghz` | Per-vendor decoders are ~150 LoC each; full Schrader/Citroën/Renault/Toyota/Ford set fits in one M-week. Highest ROI — re-prioritised above §2a #5. |
| 2 | `mifare_fm11rf08_backdoor` | Quarkslab eprint 2024/1275 | **S** | `crypto1` | Single fixed-key auth probe + static-encrypted-nonce path. Confirms §2a #1. |
| 3 | `nfc_unsaflok_forge` | Wouters et al., Mar 2024 | **M** | `crypto1`, `flipper` | KDF is published; Mifare write path exists. Gate strictly on `lab_consent`. Confirms §2a #2. |
| 4 | `wifi_ssid_confusion` | Vanhoef WiSec'24 | **M** | `marauder`, `bruce` (or future `pineapple`) | Pineapple backend (§2c #3) makes this near-free. Confirms §2a #4. |
| 5 | `subghz_rollback_detect` | RollBack Jan 2024 | **S** | `subghz` | Capture-only detector; no transmit. Confirms §2a #3. |
| 6 | `gpio_wiegand_capture` + `_replay` | ESP-RFID-Tool | **S** | `iclass` (parser), new `wiegand` package | Bit-exact replay; format-agnostic. Mentioned in §2b. |
| 7 | `wifi_pmkid_capture` (native) | hcxdumptool / hashcat 22000 | **M** | `marauder`, future `pineapple` | Marauder already does deauth+capture; native `.hc22000` writer + federated hashcat call. |
| 8 | `ble_continuity_classify` | furiousMAC + AppleJuice CVE-2023-42941 | **M** | `marauder` | Defensive classifier on Marauder BT pcap; pairs with §2d apple-continuity workflow. New entry vs §2a. |
| 9 | `iclass_dummy_mac_emulate` | bettse / Flipper picopass app (2024) | **S** | `iclass` | Small change to existing emulation path. New entry vs §2a. |
| 10 | `ble_findmy_emulate` | nRootTag (USENIX'25) | **M** | `marauder`, future `chameleon`/`bruce` | OpenHaystack-style key derivation + BLE advertise. Strongest 2025 PoC; new entry vs §2a (which named the Spec but cited weaker source). |
| 11 | `usb_badusb_classify` | agentzex Wireshark dissector | **M** | new `usbforensic` package | Defensive — port DuckyScript reconstruction from usbmon pcaps. New entry vs §2a. |
| 12 | `dronid_receive` | RUB-SysSec NDSS'23 / 2024 PoC release | **L** | future `hackrf` | Blocked on HackRF backend (§2c #1); de-prioritised vs §2a sequencing because of that gating. Confirms §2a #5 but ranks lower. |
| 13 | `wifi_peap_downgrade_audit` | CVE-2023-52160 | **M** | future `pineapple` | hostapd-rogue + Enterprise-client check. New entry. |
| 14 | `wifi_fragattacks_audit` | Vanhoef WiSec'25 | **L** | future `pineapple` | Container-bridge to the FragAttacks framework; long because of test matrix. New entry. |
| 15 | `tpms_anomaly_detect` (Tesla VCSEC) | CVE-2025-2082 | **M** | `subghz`, BLE | Defensive — flags malformed VCSEC certificate exchanges in BLE TPMS captures. New entry. |

### Reprioritisation summary

- **Confirmed five §2a entries** all remain in the Top-15:
  - §2a #1 → row 2 (here ranked #2 vs §2a #1 — both are S effort).
  - §2a #2 → row 3.
  - §2a #3 → row 5.
  - §2a #4 → row 4.
  - §2a #5 → row 12 (de-prioritised because of HackRF backend
    dependency; the §2a list ranked it inside the top five but it
    has no immediate hardware path).
- **Re-prioritised up**: `subghz_tpms_decode` to #1 — trivial port,
  highest unit ROI, no new hardware.
- **New high-confidence additions** vs §2a: `gpio_wiegand_*`,
  `wifi_pmkid_capture`, `ble_continuity_classify`,
  `iclass_dummy_mac_emulate`, `ble_findmy_emulate` (with stronger
  PoC backing), `usb_badusb_classify`, `wifi_peap_downgrade_audit`,
  `wifi_fragattacks_audit`, `tpms_anomaly_detect`.

### Items intentionally not in the Top-15

- **2TETRA:2BURST** — research-only, requires SDR + radio expertise
  out of scope (matches v0.8 audit verdict).
- **Stealtooth** — no public PoC at write time.
- **Pwn2Own Auto chains** — federation-only; ingest CVEs but do not
  port chains.
- **5G-SPECTOR** — research-only, O-RAN hardware not in scope.
- **DroneID transmit / Remote-ID spoofing** — explicit policy: no
  offensive RID transmit, only receive/classify.
- **Apple BLE-spam** — explicit policy: defensive classifier only,
  no offensive surface.
- **iCLASS SE/SEOS downgrade** — federation-only via Proxmark3.
- **KeeLoq manufacturer-key replays** — no new in-window academic
  break; defensive classifier already covered by RollBack detector.
