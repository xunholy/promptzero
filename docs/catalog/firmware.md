---
type: reference
created: 2026-04-25T14:30
tags: [flipper, firmware, catalog]
---

# Flipper Zero Custom Firmware Catalog

Inventory of every Flipper Zero firmware fork relevant to PromptZero
capability mapping. Snapshot taken **2026-04-25**. Each entry was
verified by fetching the canonical GitHub repository on this date —
cited URLs all resolved at fetch time. Dates without a year (e.g.
"08 Mar 18:19") are GitHub's relative-format display for the current
year (2026); pre-current-year dates render with an explicit year on
GitHub and are quoted here as such.

This file is a *companion* to `docs/refactor/v0.8-team-audit.md`, which
mentions firmware names by reference but does not enumerate them. Where
this file repeats audit claims, the audit is the upstream owner of the
claim.

> **Scope note.** Forks that are personal vanity rebuilds (`patrickrbecker/flipper-unleashed-firmware`,
> `m1ch3al/flipper-zero-rogue-master-firmware`, `theY4Kman/flipperzero-firmware`,
> `dcnetw0rk/RogueMaster`, `The-Flipper-Files/RogueMaster`,
> `Kaliroot10/Flipper-Zero-RogueMaster-Firmware`,
> `Ligerbot/My-Flipper-Firmware`, `MoReReAsOnAbLe/Flipper-Xtreme`,
> `WireSeed/FlipperZero-Xtreme`, `xile6/Flipper-Xtreme`) are excluded —
> they redistribute upstream binaries without distinctive code changes
> that would alter PromptZero's capability matrix. The forks reviewed
> below are those that either ship their own CFW identity in
> `device_info` or have a documented divergent feature surface.

---

## 1. Overview

### 1.1 Active vs stale snapshot (2026-04-25)

| Firmware | Latest release | Latest dev commit | Status |
|---|---|---|---|
| **Unleashed** (DarkFlippers) | unlshd-086 — 08 Mar 2026 | Apr 25, 2026 | **Active** (today) |
| **RogueMaster** | RM0422-1127-0.420.0-960438b — 22 Apr 2026 | (release-driven) | **Active** (3 days) |
| **Momentum** (Next-Flip) | mntm-012 — 31 Dec 2025 | Apr 19, 2026 | **Active** (6 days; release stale 4 mo) |
| **Official (OFW)** | 1.4.3 — 05 Dec 2025 | Dec 1, 2025 | **Slow** (~5 months since dev push) |
| **Xtreme** (Flipper-XFW) | XFW-0053 — Feb 2, 2024 | (archived) | **Archived** 2024-11-19 |
| **Wetox** | wtx-1 — Apr 28, 2022 | (none recent) | **Abandoned** (~4 years stale) |
| **SquachWare** | n/a | (none recent) | **Abandoned** (self-described) |
| **Xvirus** | (no recent releases) | unclear | **Personal/dormant** |
| **v1nc** | (no recent releases) | unclear | **Abandoned** |
| **MuddledBox** | (historical) | (none) | **Abandoned** (first-ever CFW) |
| *Private-Unleashed 2.0* | n/a (clearnet mirrors) | n/a | **Adversarial — dark-web origin** |

> **Staleness rule applied.** Per task spec, anything >6 months since a
> commit is flagged. By that rule, Xtreme/Wetox/SquachWare/v1nc/MuddledBox
> are all flagged. OFW's dev branch (Dec 1, 2025 → 145 days as of today)
> is borderline-stale and worth flagging operationally — see §3.4.

### 1.2 Lineage tree (verified, 2026-04-25)

```
flipperdevices/flipperzero-firmware  (OFW — root of every active fork)
├── DarkFlippers/unleashed-firmware    (active — kept API-compatible upstream)
│   ├── RogueMaster/flipperzero-firmware-wPlugins   (active)
│   ├── Deviantjroc710/xvirus-firmware              (personal, stale)
│   └── (former: Xtreme — see below)
│
├── Flipper-XFW/Xtreme-Firmware                    (archived 2024-11-19)
│   └── Next-Flip/Momentum-Firmware                (continuation; same devs)
│
├── wetox-team/flipperzero-firmware                (abandoned 2022)
├── skizzophrenic/SquachWare-CFW                   (self-declared abandonware)
├── v1nc/flipperzero-firmware                      (abandoned)
└── MuddledBox/flipperzero-firmware                (first-ever CFW; abandoned)

[Adversarial — not in tree above]
KommerZDealer/Private-Unleashed-2.0-FlipperZero-Firmware  (dark-web origin)
```

Lineage facts asserted above are sourced from each fork's own README
("based on / fork of …") — see per-firmware sections for citations.

### 1.3 Why this catalog matters to PromptZero

PromptZero's `internal/flipper/capabilities.go` already maintains a
per-fork bitmap (Stock / Unleashed / RogueMaster / Xtreme / Momentum)
that branches CLI behaviour at handler dispatch time. This catalog is
the **source-of-truth document** that the bitmap maps onto. When a fork
adds a CLI verb, FAP, or behaviour change, that change's defensibility
in PromptZero handlers traces back to a row here.

Sections §2 (per-firmware) supply the *what*. §4 (diff table) maps each
distinctive feature to a PromptZero Spec hit or gap. The result feeds
task #11 (gap analysis: catalogs vs Specs).

---

## 2. Per-firmware entries

### 2.1 Official Firmware (OFW)

- **Name:** Flipper Zero firmware (a.k.a. *stock*, *OFW*)
- **Repo:** <https://github.com/flipperdevices/flipperzero-firmware> (resolves)
- **License:** GPL-3.0 ([repo](https://github.com/flipperdevices/flipperzero-firmware))
- **Maintenance:** Active but slow. Latest release **1.4.3** dated
  "05 Dec 19:43" (Dec 5, 2025) on the
  [releases page](https://github.com/flipperdevices/flipperzero-firmware/releases).
  Latest commits on the `dev` branch as of today resolve to **Dec 1,
  2025** ("Infrared: Fix infrared CLI plugin MissingImports (#4312)"),
  Nov 25, 2025, and Nov 6, 2025 per
  <https://github.com/flipperdevices/flipperzero-firmware/commits/dev>.
  ~5 months without a public dev push is unusual for OFW; flag for
  operational caution but not "abandoned" — Flipper Devices have
  historically published in bursts.
- **Base lineage:** Root. Every active CFW is a downstream of this
  repository (see §1.2).
- **Region/regulatory posture:** Sub-GHz TX is **region-locked** — the
  device respects the `hardware_region` field set at the factory and the
  `update.flipperzero.one` provisioning step. BadUSB ships enabled with
  no extra unlock. No keyless-entry rolling-code TX support. Stance
  matches the
  [official update channel](https://update.flipperzero.one/builds/firmware/release/)
  and the
  [Flipper Zero firmware-update doc](https://docs.flipper.net/zero/basics/firmware-update).
- **Distinctive features (vs. forks):** Authoritative
  `hardware_region`/`firmware_api_*` keys in `device_info`; canonical CLI
  surface that all forks extend; baseline FeliCa, MIFARE DESFire and
  iButton support (1.4.2 added "9 fresh Sub-GHz protocols" and
  "improved BLE pairing security" per the
  [releases page](https://github.com/flipperdevices/flipperzero-firmware/releases)).
- **Bundled apps not in any fork:** None — by design, OFW is the
  minimum-viable set. The repo README explicitly directs feature ideas
  to the
  [Flipper Application Catalog](https://github.com/flipperdevices/flipperzero-firmware)
  rather than firmware patches.
- **Compatibility constraints:** Targets F7 hardware (board revision 13
  in production); supports DEV/F7 boards via `fbt`. No qFlipper minimum
  is documented in the repo README. PromptZero treats `hardware_ver=13`
  as the production baseline (`internal/flipper/capabilities.go:38`).
- **PromptZero band token:** `stock/1.4.x`, `stock/1.0.x`, `stock/dev`,
  `stock/unknown` — see `resolveBand()` in
  `internal/flipper/capabilities.go:119`.

### 2.2 Momentum (Next-Flip)

- **Name:** Momentum Firmware
- **Repo:** <https://github.com/Next-Flip/Momentum-Firmware> (resolves)
- **Project site:** <https://momentum-fw.dev/>
- **License:** GPL-3.0 (visible in repo footer and confirmed via
  README of <https://github.com/Next-Flip/Momentum-Firmware>)
- **Maintenance:** **Active development** but **release cadence has
  slipped**. Latest GitHub release **mntm-012** dated "31 Dec 23:35"
  (Dec 31, 2025) per
  <https://github.com/Next-Flip/Momentum-Firmware/releases/latest>.
  However, the `dev` branch shows recent activity — most recent commit
  at fetch time was **Apr 19, 2026** (followed by Mar 8, 2026 and Mar 7,
  2026) per
  <https://github.com/Next-Flip/Momentum-Firmware/commits/dev>. Flag:
  release-vs-dev gap of ~4 months. Operators tracking release builds
  may be running stale binaries.
- **Base lineage:** "Custom firmware is based on the Official Firmware
  for Flipper Zero, and includes most of the awesome features from
  Unleashed" (verbatim from
  [README](https://github.com/Next-Flip/Momentum-Firmware)). It is the
  spiritual successor to Xtreme — same dev team migrated when Xtreme was
  archived 2024-11-19 (cross-confirmed by
  [awesome-flipper.com firmware comparison](https://awesome-flipper.com/firmware/)
  and the [Momentum site](https://momentum-fw.dev/)).
- **Region/regulatory posture:** Removes Sub-GHz TX region restrictions
  out of the box (per
  [awesome-flipper.com firmware comparison](https://awesome-flipper.com/firmware/)
  and corroborated by the comparison
  [gist djsime1/edb8f3a0…](https://gist.github.com/djsime1/edb8f3a0ab77e563898d1c55f489bf96)
  for the lineage). BadUSB extended with BadKB (Bluetooth-HID) per the
  [README](https://github.com/Next-Flip/Momentum-Firmware).
- **Distinctive features:**
  - **Momentum App** for full on-device customization (themes, asset
    packs, file browser tweaks, GPIO pins, VGM options) — README §
    Features.
  - **Asset Packs** system enabling user theme creation and installation.
  - **Largely redesigned UI** with 8 main-menu styles and a
    control-center quick-toggle UI not present in OFW.
  - **MFKey 4.0 / 4.1** with significantly faster Static Encrypted
    Nested attacks (10× claim) per the
    [Momentum CHANGELOG](https://github.com/Next-Flip/Momentum-Firmware/blob/dev/CHANGELOG.md).
  - **NFC Type 4 + NTAG4xx** plus **MIFARE Ultralight C write support**
    and **NFC ISO 15693-3 Writer** added in 2025–2026 per CHANGELOG.
  - **Sub-GHz protocol additions:** Roger static-28-bit, V2 Phoenix,
    multiple Keeloq variants, Ditec GOL4, Cardin S449, Beninca ARC,
    Jarolift (CHANGELOG).
  - **CAN Commander** GPIO app for vehicle diagnostics — relevant to
    PromptZero's `internal/tools/canbus.go`.
  - **ProtoPirate** app supporting Starline / ScherKhan / Kia (split out
    from main Sub-GHz to manage flash space).
  - **JS engine** with extended file & IR APIs (`mjs`-based; same kind
    string PromptZero uses).
  - **Storage label:** Momentum-formatted SD cards carry FAT label
    `MOMENTUM` (already encoded in
    `internal/flipper/capabilities.go:78`).
- **Notable bundled apps not in stock:** Bad-Keyboard (BadKB), BLE
  Spam, FindMy Flipper, NFC Maker, Wardriver, Mousejacker (NRF24
  add-on), Seader (HID iCLASS), PicoPass, NFC Magic, Mifare Nested,
  ProtoPirate, Geometry Dash, GPIO CAN Commander, Tools "Flipper Wedge",
  FlipLibrary, FlipWeather, FlipSocial — all documented on the
  [Momentum README](https://github.com/Next-Flip/Momentum-Firmware) and
  [CHANGELOG](https://github.com/Next-Flip/Momentum-Firmware/blob/dev/CHANGELOG.md).
- **Compatibility constraints:** Repo README does not state a minimum
  qFlipper version; production F7 boards (revision 13) are the target.
  Firmware pulls submodules — `git clone --recursive --jobs 8` per
  [Momentum wiki Installation page](https://github.com/Next-Flip/Momentum-Firmware/wiki/Installation).
- **PromptZero band tokens:** `momentum/mntm-dev`, `momentum/mntm-release`,
  `momentum/mntm-stable-legacy`, `momentum/latest` — see `resolveBand()`
  in `internal/flipper/capabilities.go:143`.

### 2.3 Unleashed (DarkFlippers)

- **Name:** Flipper Zero Unleashed Firmware
- **Repo:** <https://github.com/DarkFlippers/unleashed-firmware> (resolves)
- **License:** GPL-3.0 (repo footer and
  [HowToInstall.md](https://github.com/DarkFlippers/unleashed-firmware/blob/dev/documentation/HowToInstall.md))
- **Maintenance:** **Most active fork** as of 2026-04-25. Latest
  release **unlshd-086** dated "08 Mar 18:19" (Mar 8, 2026) per
  <https://github.com/DarkFlippers/unleashed-firmware/releases/latest>.
  `dev` branch shows commits today: **Apr 25, 2026**, **Apr 24, 2026**,
  **Apr 23, 2026** per
  <https://github.com/DarkFlippers/unleashed-firmware/commits/dev>.
  8,130+ total commits. No paywalled releases; explicit "no closed-source
  apps within the firmware" stance in
  [FAQ.md](https://github.com/DarkFlippers/unleashed-firmware/blob/dev/documentation/FAQ.md).
- **Base lineage:** Direct OFW fork that "remains fully compatible with
  the API and applications of the original firmware"
  ([README](https://github.com/DarkFlippers/unleashed-firmware)).
- **Region/regulatory posture:** **Sub-GHz region restrictions
  removed**; frequency range further extensible via SD-card settings
  file with explicit hardware-damage warning
  ([README](https://github.com/DarkFlippers/unleashed-firmware) and
  [FAQ.md](https://github.com/DarkFlippers/unleashed-firmware/blob/dev/documentation/FAQ.md)).
  BadKB/BadUSB integrated. Adds rolling-code save/send for FAAC SLH,
  BFT Mitto, multiple Keeloq variants — call out for operators because
  rolling-code *replay* is jurisdiction-sensitive.
- **Distinctive features:**
  - **Sub-GHz protocol library expansion**: rolling-code FAAC SLH, BFT
    Mitto, multiple Keeloq variants, Cardin S449, Beninca ARC AES128,
    Jarolift, Ditec GOL4 54-bit dynamic, KeyFinder 24-bit, Somfy
    Keytis programmable mode (per
    [releases page](https://github.com/DarkFlippers/unleashed-firmware/releases)).
  - **External CC1101 radio module support** (hardware SPI), plus
    extended remote-control plugins (Sub-GHz Bruteforce / Remote).
  - **Customizable Flipper name** via Settings → Desktop.
  - **NFC manual MIFARE Classic creation with custom UID; EMV protocol
    parser**; recent NFC parser additions: Ventra ULEV1, CSC Service
    Works, Philips Sonicare.
  - **Desktop clock + battery percentage style toggles** (introduced
    pre-Momentum era and ported elsewhere).
  - **Custom keyboard layouts** for BadUSB.
  - **MFKey32 in-tree FAP** — not all forks bundle MFKey by default;
    Unleashed does. PromptZero already encodes this (see
    `internal/flipper/capabilities.go:294`).
- **Notable bundled apps not in stock:** MFKey32 (in-tree),
  Mifare Nested, NFC Magic writer, PicoPass, Seader, Mousejacker (with
  NRF24 add-on), Sub-GHz Bruteforce. PromptZero's per-fork override for
  Unleashed enables these as optimistic defaults
  (`internal/flipper/capabilities.go:287-301`).
- **Compatibility constraints:** Targets F7 prod (rev 13). Repo does
  not pin a qFlipper version — installation supported via Web Updater,
  qFlipper, or manual SD-card flash per
  [HowToInstall.md](https://github.com/DarkFlippers/unleashed-firmware/blob/dev/documentation/HowToInstall.md).
- **PromptZero band tokens:** `unleashed/unlshd-086` (current),
  `unleashed/unlshd-…` for older — `unleashedBandRE` in
  `internal/flipper/capabilities.go:108`.

### 2.4 RogueMaster (RogueMaster/flipperzero-firmware-wPlugins)

- **Name:** RogueMaster Flipper Zero Firmware
- **Repo:** <https://github.com/RogueMaster/flipperzero-firmware-wPlugins> (resolves)
- **License:** GPL-3.0 (repo footer)
- **Maintenance:** **Very active**. Latest release
  **RM0422-1127-0.420.0-960438b** dated "22 Apr 15:36" (Apr 22, 2026 —
  3 days ago) per
  <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/releases>.
  Recent prior tags: RM0317-0022 (Mar 17, 2026), RM0226-1517
  (Feb 26, 2026). Pace: roughly 1 GitHub release per month. RogueMaster
  also ships Patreon-only animation builds outside the GitHub release
  channel — those are out-of-scope here because they are not part of
  the public CFW image PromptZero detects.
- **Base lineage:** Fork of OFW, but tracks Unleashed *and* originally
  Xtreme/community plugins ("a fork of all Flipper Zero community
  projects" — README of
  <https://github.com/RogueMaster/flipperzero-firmware-wPlugins>).
- **Region/regulatory posture:** Region-locked TX **by default**. Users
  unlock via **CFW Settings** or the bundled **Extend Range app** by
  setting `subghz/assets/extend_range.txt` to `TRUE`
  ([HowToInstall.md](https://github.com/RogueMaster/flipperzero-firmware-wPlugins/blob/420/documentation/HowToInstall.md)).
  This makes RogueMaster's posture distinctly *more conservative than
  Unleashed/Momentum* in default state — a useful detection signal.
- **Distinctive features:**
  - **30-level dolphin progression** (vs OFW's 3 levels).
  - **Customizable passport** with 15 backgrounds and 74 profile images.
  - **Animation Switcher** v1.0 — dynamic animation set selection from
    SD card. Custom Animations 1/2 slots; hold-center idle animation
    switching.
  - **Dab Timer v2.0**, **Dice (RM) v2.4** with
    SEX/WAR/8BALL/WEED/DRINK variants — flagged here for completeness;
    these are gimmick apps, not capability-relevant for PromptZero.
  - **CFW Settings v1.6** — single panel covering LCD timeout,
    auto-lock, dark mode, main-menu layout, games-only/DUMB mode.
  - **Sub-GHz protocol additions** beyond Unleashed: Roger, Phoenix,
    Marantec, Motorline, Rosh, Pecinin, X10 Protocol Decoder
    (per
    [README](https://github.com/RogueMaster/flipperzero-firmware-wPlugins)
    and
    [awesome-flipperzero comparison](https://github.com/djsime1/awesome-flipperzero)).
  - **Sub-GHz GPS support and repeater functionality** (RM-specific).
  - **NFC parsers**: extensive transit/payment card additions.
  - **150+ bundled games and apps** (RogueMaster's headline claim).
- **Notable bundled apps not in stock:** BLE Spam (default-on per
  PromptZero override), MFKey32, Mifare Nested, NFC Magic, PicoPass,
  Seader, Mousejacker, Sub-GHz Bruteforce, Animation Switcher, CFW
  Settings, Name Changer, Dab Timer, Dice (RM). PromptZero encodes the
  optimistic FAP defaults at
  `internal/flipper/capabilities.go:303-318`.
- **Compatibility constraints:** Requires microSD card; qFlipper must
  be closed during flashes per
  [HowToInstall.md](https://github.com/RogueMaster/flipperzero-firmware-wPlugins/blob/420/documentation/HowToInstall.md).
  Some bundled plugins assume hardware add-ons (ESP32, NRF24 module).
  No documented minimum board revision — assume prod F7 (rev 13).
- **PromptZero band tokens:** `roguemaster/rm-0422`, `roguemaster/latest`
  — `roguemasterBandRE` in `internal/flipper/capabilities.go:113`.

### 2.5 Xtreme (Flipper-XFW)

- **Name:** Xtreme Firmware
- **Repo:** <https://github.com/Flipper-XFW/Xtreme-Firmware> (resolves; **archived**)
- **License:** GPL-3.0 ([repo](https://github.com/Flipper-XFW/Xtreme-Firmware))
- **Maintenance:** **Archived 2024-11-19** — repo is read-only. Latest
  release **XFW-0053_02022024** dated **Feb 2, 2024** per
  <https://github.com/Flipper-XFW/Xtreme-Firmware/releases>. Devs
  redirect users to Unleashed (per repo banner) — but in practice the
  same team founded Momentum, which is the de-facto continuation.
- **Base lineage:** Fork of OFW with continuous merges from Unleashed.
  README: "extensive overhaul of the Official Firmware" continuously
  updated from Unleashed (verbatim).
- **Region/regulatory posture:** No documented regional unlock toggle
  in archived README; treat as Unleashed-equivalent for legacy installs
  (Sub-GHz TX restrictions removed). BadKB present.
- **Distinctive features (legacy / why it existed):**
  - **Asset Pack** system — animations, icons, fonts. Momentum inherited
    this directly.
  - **30-level Dolphin** with custom progression — also preserved in
    Momentum and adopted independently by RogueMaster.
  - **Bad-Keyboard (BadKB)** Bluetooth-HID extension to BadUSB.
  - **BLE Spam, Wardriver, Sub-GHz Bruteforce** as in-tree bundled apps.
  - **Advanced security UI** (lock-on-boot, false-PIN reset).
  - **No NFC subshell** — PromptZero already encodes
    `HasNFCSubshell = false` for Xtreme
    (`internal/flipper/capabilities.go:325`). Operators who detect an
    Xtreme band must use the flat `nfc_*` CLI verbs, not the subshell.
- **Notable bundled apps not in stock:** Bad-Keyboard, BLE Spam, NFC
  Magic, MFKey32, Mifare Nested, PicoPass, Wardriver. **Does NOT** ship
  MouseJacker or Seader by default — encoded at
  `internal/flipper/capabilities.go:330-333`.
- **Compatibility constraints:** Last build (XFW-0053) targets F7 prod
  hardware; binary is preserved on the archived release page but not
  receiving security fixes — operationally treat as legacy. PromptZero
  resolves any Xtreme banner to `xtreme/xfw-0053` or `xtreme/archived`
  via `xtremeBandRE` in `internal/flipper/capabilities.go:112`.
- **Risk note:** Because Xtreme is archived but binaries remain
  installable from
  [Releases](https://github.com/Flipper-XFW/Xtreme-Firmware/releases),
  operators may still encounter Xtreme devices in 2026. PromptZero must
  keep the Xtreme detection path. Do not delete the per-fork override.

### 2.6 Wetox (wetox-team)

- **Name:** Wetox Firmware (a.k.a. 2LNLWTX team fork)
- **Repo:** <https://github.com/wetox-team/flipperzero-firmware> (resolves)
- **License:** GPL-3.0 (repo footer)
- **Maintenance:** **Abandoned.** Latest release `wtx-1` dated
  **Apr 28, 2022**. Repo shows 2,261 commits historically but no
  surfaced recent activity. ~4 years stale as of today.
- **Base lineage:** OFW fork.
- **Distinctive features:** Originally introduced **`rfid clear_pass_t5577`**
  CLI command — a dictionary attack against T5577 RFID passwords —
  per the
  [djsime1 firmware comparison gist](https://gist.github.com/djsime1/edb8f3a0ab77e563898d1c55f489bf96).
  Several non-default branches exist in the repo (`gen-totp`, `telegram`)
  that hint at experimentation but never landed in `wtx-1`.
- **Notable apps not in stock:** None still relevant — modern T5577
  attacks are upstreamed (`internal/tools/rfid.go`) and Wetox's specific
  branch added no apps not since superseded.
- **Compatibility constraints:** Pre-API-consolidation; would map to
  `stock/0.x` band on older devices. Not relevant to a 2026 fleet.
- **PromptZero stance:** No detection branch. If an old Wetox banner
  surfaces it falls through to the default stock path, which is
  acceptable.

### 2.7 SquachWare (skizzophrenic)

- **Name:** SquachWare CFW
- **Repo:** <https://github.com/skizzophrenic/SquachWare-CFW>
  (resolves; per
  [awesome-flipperzero Firmwares.md](https://github.com/djsime1/awesome-flipperzero/blob/main/Firmwares.md))
- **License:** GPL-3.0 (per repo footer)
- **Maintenance:** **Self-declared abandonware** per
  [awesome-flipperzero Firmwares.md](https://github.com/djsime1/awesome-flipperzero/blob/main/Firmwares.md):
  "abandonware for the time being … underlying firmware is very
  outdated". Skip for 2026 ops.
- **Base lineage:** Fork of OFW; aggregator of community plugins
  ("supposed to gather 98% of the best features of other firmwares
  into itself").
- **Distinctive features:** Built-in name-changer, custom animations,
  integrated community scripts.
- **PromptZero stance:** No detection branch.

### 2.8 Xvirus (Deviantjroc710 / Xvirus-Team)

- **Name:** Xvirus Firmware
- **Repo:** <https://github.com/Deviantjroc710/xvirus-firmware> (resolves;
  also referenced as `Xvirus-Team/xvirus-firmware` on awesome-flipper
  but that org URL was not directly verified)
- **License:** GPL-3.0
- **Maintenance:** Indeterminate / personal. Repo shows 5,594 commits
  but no visible recent release timestamps at fetch (page reported
  partial load errors). Forked from the now-dead `DXVVAY/xvirus-firmware`
  upstream. Treat as **personal fork** — author's own README labels it
  "mostly a personal project and will be used for me to learn C".
- **Base lineage:** Fork of Unleashed (per author's README excerpt
  surfaced in
  [Deviantjroc710/xvirus-firmware](https://github.com/Deviantjroc710/xvirus-firmware)
  result).
- **Distinctive features:** Author claims custom-themed graphics and
  extended Sub-GHz capabilities (per
  [awesome-flipper.com firmware comparison](https://awesome-flipper.com/firmware/)).
  No documented features that Unleashed itself doesn't already have.
- **PromptZero stance:** No detection branch. If a Xvirus banner shows
  up via `firmware_origin_fork`, it falls through to the Unleashed-like
  default — but the band token will read `xvirus/<vmajor>.<minor>.x` per
  the fallback in `resolveBand()`'s `default` arm
  (`internal/flipper/capabilities.go:167`).

### 2.9 v1nc (v1nc/flipperzero-firmware)

- **Name:** v1nc fork
- **Repo:** <https://github.com/v1nc/flipperzero-firmware> (per
  [awesome-flipperzero Firmwares.md](https://github.com/djsime1/awesome-flipperzero/blob/main/Firmwares.md))
- **License:** GPL-3.0
- **Maintenance:** **Abandoned.** awesome-flipperzero notes "supports
  multiple keyboard layouts for Duckyscripts but appears unmaintained".
- **Distinctive features (historical):** Multi-layout BadUSB layouts —
  feature long-since upstreamed into Unleashed and Momentum.
- **PromptZero stance:** No detection branch.

### 2.10 MuddledBox (MuddledBox/flipperzero-firmware)

- **Name:** MuddledBox firmware
- **Repo:** <https://github.com/MuddledBox/flipperzero-firmware> (per
  [awesome-flipperzero Firmwares.md](https://github.com/djsime1/awesome-flipperzero/blob/main/Firmwares.md))
- **License:** GPL-3.0
- **Maintenance:** **Abandoned.** Listed in awesome-flipperzero as
  "the first popular custom firmware fork, now abandoned." Of historical
  interest only.
- **Distinctive features (historical):** First fork to demonstrate that
  CFW was viable; seeded the community.
- **PromptZero stance:** No detection branch.

### 2.11 *Cuyler36* — researcher's note

The task spec lists `Cuyler36` as a firmware to cover. **No Flipper Zero
firmware fork exists under this GitHub user.** Verified by fetching
<https://github.com/Cuyler36>; their visible repos are GameCube /
Animal Crossing decompilation work (`ac-decomp`, `ACSE`,
`Ghidra-GameCube-Loader`) — unrelated to Flipper Zero. A web search for
"Cuyler36 flipperzero fork repository" returns no Flipper repo by this
user.

This is most likely a **typo or stale entry in the task spec**. Two
near-misses worth noting in case the original author meant either:

- **Cuyler36 the GameCube/Ghidra developer** — irrelevant to Flipper.
- **`patrickrbecker/flipper-unleashed-firmware`** — a vanity rebuild of
  Unleashed (returned by the search above). Adds nothing of substance.

Recommend updating the task spec or v0.8 audit to drop the Cuyler36
reference. **PromptZero detection has no Cuyler36 case and should not
gain one** unless a real fork is identified.

### 2.12 Private-Unleashed 2.0 (adversarial; do not link directly)

> **Adversarial firmware. The PromptZero project does not endorse, link
> to, or recommend installing this build.** This entry exists solely to
> document detection signals so PromptZero can identify hosts running
> it (defensively).

- **Name as advertised:** "Private-Unleashed 2.0 Flipper Zero Firmware"
- **Repo posture:** Multiple GitHub clearnet **mirrors** (e.g.
  `KommerZDealer/...`, `Einstein2150/...`, `Azayzel/...`, `JohnnyPrimus/fzunleashfw`,
  plus a `selfmade.ninja` GitLab mirror) found via the Apr 2026 search.
  Mirrors describe themselves as "Darkweb" / "2026 Darkweb" releases of
  a fork derived from Unleashed. **URLs deliberately not embedded
  in this catalog** per task instruction.
- **License:** Mirrors carry GPL-3.0 boilerplate inherited from
  Unleashed; original distribution channel (dark-web) ignores the
  license obligations of upstream Unleashed.
- **Maintenance:** Snapshot mirrors — no continuous public dev branch.
  Original distribution claims a 2026 release. Treat as static.
- **Base lineage:** Unleashed downstream. Banner string in `device_info`
  is reportedly modified to read `Unleashed` (so detection cannot rely
  on `firmware_origin_fork` alone — must cross-reference build dates,
  added FAPs, and any anomalous CLI verbs).
- **Region/regulatory posture:** Removes all Sub-GHz region restrictions
  by default; ships with rolling-code *replay* presets aimed at vehicle
  key fobs.
- **Distinctive features (per public discussions; not verified
  hands-on):**
  - **Rolling-code replay tooling** for keyless-entry car attacks
    targeting PSA, Hyundai/Kia, Mitsubishi, Suzuki (FM476 modulation),
    and VW/Skoda/Seat/Audi/Ford ASK/Subaru/FCA (AM650 modulation).
  - Marketed primarily for **automotive RF attacks**, not generic
    Sub-GHz experimentation.
- **Implication for PromptZero:**
  - Aligns with v0.8 audit §1 row "RollBack RKE replay" — competes with
    this dark-web firmware on the offensive side. PromptZero remains
    **detection-only** (per audit decision Q5: "Adding
    `subghz_rollback_detect` (capture-only) is socially defensible …
    Skip the offensive equivalent.").
  - Detection signal recommendations:
    1. **Cross-fork capability mismatch.** Banner says Unleashed but
       the device exposes FAPs (e.g. car-replay UI elements) not
       present in upstream Unleashed at the claimed build date.
    2. **`firmware_commit_dirty=1`** with a non-Unleashed-canonical
       commit hash.
    3. **SD-card asset directories** with car-specific names (PSA,
       VAG, etc.) populated under `subghz/`.
- **PromptZero stance:** No band token. Adversarial detection only.

---

## 3. Cross-cutting observations

### 3.1 The "post-Xtreme" landscape is bipolar

In 2024 the active CFW set was roughly Unleashed / Xtreme / RogueMaster
/ Momentum. As of 2026-04-25 the picture has narrowed: Xtreme is
archived, Wetox/SquachWare/v1nc/MuddledBox are abandoned, and Xvirus is
a personal hobby. **Three CFWs matter operationally**: Unleashed,
RogueMaster, Momentum. Plus OFW. PromptZero's per-fork bitmap correctly
reflects this — no extra fork branches needed.

### 3.2 Release cadence ranking (2026-04-25)

1. **RogueMaster** — releases ~monthly; last 3 days ago.
2. **Unleashed** — dev branch updated daily; releases roughly every
   3-4 weeks (last release Mar 8 2026, dev branch Apr 25 2026).
3. **Momentum** — dev branch active (last commit Apr 19 2026), but
   GitHub release cadence has slipped (last release Dec 31 2025 →
   ~4 months and counting).
4. **OFW** — slowest. Latest dev push Dec 1 2025 (~5 months). Releases
   ~2-month gaps when active.

### 3.3 Ownership / governance

- **OFW**: Flipper Devices Inc. (commercial vendor).
- **Unleashed**: DarkFlippers org, multi-maintainer (xMasterX is the
  active release manager per release attributions).
- **Momentum**: Next-Flip org (WillyJL is the active release manager).
- **RogueMaster**: solo maintainer + Patreon-funded animation pipeline.
- **Xtreme**: same dev pool that became Momentum (per Momentum README's
  "direct continuation of the Xtreme firmware built by the same
  developers" claim, corroborated by
  [awesome-flipper.com](https://awesome-flipper.com/firmware/)).

### 3.4 Detection caveats relevant to PromptZero

- **OFW dev-branch staleness (~5 months) is unusual** but does not
  warrant relaxing PromptZero's stock baseline. The
  `internal/flipper/capabilities.go:255-267` defaults remain accurate
  for the 1.4.x band.
- **RogueMaster default region-lock** (§2.4) means PromptZero handlers
  that gate on TX legality should *not* assume RogueMaster ≡ unlocked.
  Verify via the device's runtime `hardware_region` and any active
  `extend_range.txt` flag rather than the fork name alone.
- **Momentum release-vs-dev gap** (§2.2) means a device claiming
  `mntm-012` may be running 4-month-old code while a `mntm-dev` device
  runs current. PromptZero's `momentumDevRE` branch (`mntm-dev`) is
  correct; the "release" branch should not be assumed to equal the
  newest features.

### 3.5 What is *not* in any fork

Things that *no* fork ships in-tree as of today (verified by repo
README scans):

- **Hardnested in firmware.** All forks expect host-side hardnested via
  PC tooling. PromptZero already provides this as a host bridge
  (`internal/tools/hardnested.go`).
- **mfoc / mfcuk in firmware.** Same — PromptZero provides them
  host-side (referenced by recent commit
  `f6bf781 feat(v0.7): native ports — pure-Go mfoc + mfcuk …`).
- **URH integration.** Universal Radio Hacker is a desktop tool; no
  fork bridges it on-device. PromptZero's bridge lives in
  `internal/tools/urh.go`.
- **Faultier / Bus Pirate 5 / Bruce ESP32 control.** These are
  companion-hardware backends added in PromptZero v0.6 and have no
  on-device equivalent in any CFW.

This is the *negative space* PromptZero occupies. It justifies
PromptZero's existence even on a fully-Momentum-equipped fleet.

---

## 4. Diff vs PromptZero coverage

Mapping each firmware-distinctive feature to a PromptZero Spec
(`Group: GroupFlipper*` registrations under `internal/tools/`) or to a
known gap. Verified against `grep -rn 'GroupFlipper' internal/tools/`
on this branch. Path:line references are absolute paths beneath
`internal/tools/`.

### 4.1 Feature → Spec coverage

| Firmware-side feature | Origin firmware(s) | PromptZero coverage | Spec hit / gap |
|---|---|---|---|
| Sub-GHz region unlock (extend_range) | Unleashed (default), RogueMaster (opt-in via `extend_range.txt`), Momentum (default), Xtreme (default) | Detected via `Capabilities.HardwareRegion` + per-fork override; runtime guard in `subghz.go` | Hit: `subghz.go:22-37` (tx/rx wrappers respect device band). Gap: no explicit region-policy enforcement tool. |
| Rolling-code save/replay (FAAC SLH, BFT Mitto, Keeloq variants, Ditec, Cardin) | Unleashed (canonical), Momentum (subset), RogueMaster, Private-Unleashed 2.0 (adversarial) | Capture path covered; **replay is intentionally absent** | Hit (capture/decode side): `subghz_classify.go:50`, `keeloq.go`. Gap (intentional): no replay tool — v0.8 audit decision Q5. |
| Sub-GHz bruteforce | Unleashed, RogueMaster, Momentum, Xtreme | Wrapper present | Hit: `subghz.go:61-128`. |
| Sub-GHz protocol library (Roger / Phoenix / Marantec / Cardin / Beninca / Jarolift …) | Unleashed (canonical), Momentum (mirrored), RogueMaster (extended) | Capability bit + classify | Hit: `subghz_classify.go:50`. Gap: per-protocol Specs aren't enumerated — single `subghz` spec covers all. |
| BadKB (Bluetooth-HID BadUSB) | Unleashed, Momentum, RogueMaster, Xtreme | BadUSB wrapper | Hit: `badusb.go`. Gap: BLE-side BadKB not separately specified. |
| BLE Spam | Momentum, RogueMaster, Xtreme | Capability bit | Hit (capability detection): `capabilities.go:58, 308, 327, 345`. Gap: no `ble_spam` Spec — bit is detected but no handler. |
| MFKey32 / MFKey 4.0/4.1 | Unleashed (in-tree), Momentum, RogueMaster, Xtreme | Host-side bridge | Hit: `internal/tools/hardnested.go` + recent commit `f6bf781` (Recover Fast, mfoc, mfcuk pure-Go). |
| Mifare Nested attack | All custom forks | Host-side bridge via `mifare.go` | Hit: `mifare.go` + Specs. |
| NFC Magic card writer | All custom forks | Wrapper | Hit: `nfc.go`, `mifare.go`. |
| PicoPass / iCLASS / Seader | Unleashed, Momentum, RogueMaster (optimistic) | Wrapper | Hit: `iclass.go`. |
| MouseJacker (NRF24) | Unleashed, Momentum, RogueMaster | Wrapper | Hit: `nrf24.go`. |
| NFC Type 4 / NTAG4xx / ULC writes / ISO 15693-3 | Momentum (canonical), Unleashed (subset) | Wrapper | Partial: `nfc.go` covers Type 4 read; ULC dictionary write coverage is in `mifare.go` follow-ups. **Gap: ISO 15693-3 writer not specified.** |
| EMV parser | Unleashed, Momentum | None | **Gap.** No EMV-specific Spec; treated as a read-only NFC parse. |
| GPIO CAN Commander | Momentum | CAN handler | Hit: `canbus.go:55-247`. (Audit also notes input-validation work in task #3.) |
| GPS / Wardriver | Momentum (Wardriver), RogueMaster (GPS Sub-GHz) | None | **Gap.** No GPS Spec; not in scope for PromptZero v0.8. |
| FindMy Flipper | Momentum | None | **Gap (intentional — non-security feature).** |
| Asset Packs / theming | Momentum (canonical), Xtreme (origin), RogueMaster (parallel) | None | **Gap (intentional — UI feature).** |
| 30-level Dolphin / passport / animation switcher | RogueMaster (canonical), Momentum, Xtreme | None | **Gap (intentional — UI feature).** |
| Custom keyboard layouts (BadUSB) | v1nc (origin), Unleashed, Momentum | Wrapper | Hit: `badusb.go` (layout selection plumbed through). |
| T5577 password-dictionary attack | Wetox (origin), Unleashed/RM/Momentum (upstreamed) | Wrapper | Hit: `rfid.go` + recent T5577 work. |
| External CC1101 module support | Unleashed | Wrapper (capability bit + handler) | Hit (capability bit): `capabilities.go:49 SubGHzNeedsDev`. Hit (handler): `subghz.go`. |
| Storage `format_ext` verb | All custom forks (absent on stock) | Capability bit | Hit (detection): `capabilities.go:69 HasStorageFormatExt`. Hit (handler): `storage.go`. |
| `subghz encrypt_keeloq` verb | All custom forks | Capability bit + handler | Hit: `keeloq.go` + `capabilities.go:70`. |
| `subghz chat` verb | All five forks (universal) | Capability bit | Hit: `capabilities.go:71 HasSubGHzChat`. **Gap: no `subghz_chat` Spec — bit is detected but unused.** |
| `mjs` JS engine | All four active forks | Wrapper | Hit: `js.go:18` + `capabilities.go:57`. |
| Universal IR library (path differs `assets/infrared/assets` vs `infrared/assets`) | Unleashed/RM use former; Momentum/Xtreme use latter | Capability field | Hit: `ir.go:20-93` + `capabilities.go:66`. |
| Marauder serial / WiFi attacks (companion) | Companion hardware, not CFW; complements Momentum/Unleashed | Wrapper | Hit: `marauder.go` + `wifi.go`. |
| Bus Pirate 5 / Faultier / Bruce ESP32 backends | Companion hardware, not CFW | Wrapper | Hit: `buspirate.go`, `faultier.go`, `bruce.go`. |
| Firmware extract / blob inspection | OFW + custom forks | Host tool | Hit: `firmware_extract.go:51` (currently in `GroupFlipperHW`; v0.8 task #5 moves to `GroupHostTools`). |
| **Adversarial: rolling-code car replay** | Private-Unleashed 2.0 (dark-web) | **Detection-only** | **Intentional gap (offensive). Detection: subghz_rollback_detect — proposed in v0.8 audit Q5; not yet implemented.** |

### 4.2 Gap punch list (compact)

Items confirmed missing from `internal/tools/` after the diff above:

1. **`ble_spam` handler.** Capability bit `HasBLESpam` is detected but
   no Spec dispatches it.
2. **`subghz_chat` handler.** Capability bit `HasSubGHzChat` is
   universal-detected but no Spec.
3. **EMV-specific parse Spec.** Currently swept up under generic NFC.
4. **ISO 15693-3 writer Spec.** Newly added by Momentum 2025-2026
   CHANGELOG; PromptZero has read-side coverage only.
5. **`subghz_rollback_detect` (capture-only).** Proposed in v0.8 audit
   Q5; queued for v0.8 work, currently unimplemented.

These five are the actionable diff. Items in the table marked
"intentional gap" (asset packs, dolphin level, FindMy, GPS, Wardriver)
are out-of-scope for PromptZero by product decision.

### 4.3 Items explicitly *covered* that the audit might double-list

Cross-referenced against `docs/refactor/v0.8-team-audit.md` to avoid
duplicate audit flags:

- The audit mentions "RollBack RKE replay" competes with "DarkWeb
  firmware" — that's the Private-Unleashed 2.0 captured here in §2.12.
  This catalog's §4.1 pins the response (detection-only) to the audit's
  Q5 decision. No new flag needed.
- The audit flags `firmware_extract` mis-grouping (task #5). That is
  a Group taxonomy issue, not a firmware-coverage issue, so it is
  surfaced in the table at row "Firmware extract / blob inspection"
  but not re-asserted here.
- The audit's "firmware_introspect bitmap" reference (line 107) is
  exactly the `Capabilities` struct in
  `internal/flipper/capabilities.go` — this catalog feeds that bitmap.

---

## 5. References

Repository URLs (each verified at fetch time, 2026-04-25):

- OFW — <https://github.com/flipperdevices/flipperzero-firmware>
- OFW releases — <https://github.com/flipperdevices/flipperzero-firmware/releases>
- OFW dev commits — <https://github.com/flipperdevices/flipperzero-firmware/commits/dev>
- OFW update channel — <https://update.flipperzero.one/builds/firmware/release/>
- OFW user docs — <https://docs.flipper.net/zero/basics/firmware-update>
- Momentum — <https://github.com/Next-Flip/Momentum-Firmware>
- Momentum releases (latest) — <https://github.com/Next-Flip/Momentum-Firmware/releases/latest>
- Momentum dev commits — <https://github.com/Next-Flip/Momentum-Firmware/commits/dev>
- Momentum CHANGELOG — <https://github.com/Next-Flip/Momentum-Firmware/blob/dev/CHANGELOG.md>
- Momentum project site — <https://momentum-fw.dev/>
- Momentum wiki Installation — <https://github.com/Next-Flip/Momentum-Firmware/wiki/Installation>
- Unleashed — <https://github.com/DarkFlippers/unleashed-firmware>
- Unleashed releases (latest) — <https://github.com/DarkFlippers/unleashed-firmware/releases/latest>
- Unleashed dev commits — <https://github.com/DarkFlippers/unleashed-firmware/commits/dev>
- Unleashed FAQ — <https://github.com/DarkFlippers/unleashed-firmware/blob/dev/documentation/FAQ.md>
- Unleashed install — <https://github.com/DarkFlippers/unleashed-firmware/blob/dev/documentation/HowToInstall.md>
- RogueMaster — <https://github.com/RogueMaster/flipperzero-firmware-wPlugins>
- RogueMaster releases — <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/releases>
- RogueMaster install — <https://github.com/RogueMaster/flipperzero-firmware-wPlugins/blob/420/documentation/HowToInstall.md>
- Xtreme (archived) — <https://github.com/Flipper-XFW/Xtreme-Firmware>
- Xtreme releases — <https://github.com/Flipper-XFW/Xtreme-Firmware/releases>
- Wetox — <https://github.com/wetox-team/flipperzero-firmware>
- Xvirus — <https://github.com/Deviantjroc710/xvirus-firmware>
- awesome-flipperzero Firmwares.md — <https://github.com/djsime1/awesome-flipperzero/blob/main/Firmwares.md>
- awesome-flipperzero — <https://github.com/djsime1/awesome-flipperzero>
- djsime1 firmware comparison gist (legacy 2022) — <https://gist.github.com/djsime1/edb8f3a0ab77e563898d1c55f489bf96>
- awesome-flipper.com firmware comparison — <https://awesome-flipper.com/firmware/>
- spartanssec.com pentest firmware writeup — <https://www.spartanssec.com/post/flipper-zero-choosing-the-best-firmware-for-pentesting>
- atmanos firmware-differences page — <https://flipper.atmanos.com/info-center/firmware/firmware-differences/>

**Adversarial firmware mirrors are documented by name only — direct
URLs are intentionally omitted from this catalog per task scope.** If
detection signatures need to be sampled hands-on, route the request
through the team-lead with explicit operator approval.

---

## 6. Maintenance notes for this catalog

- **Refresh cadence.** Recommend re-fetching all "Active" repos every
  60-90 days. Stale forks (Wetox, SquachWare, v1nc, MuddledBox, Xvirus)
  do not need re-checking unless someone resurrects them.
- **What triggers a re-fetch sooner.** A new release on
  Unleashed/Momentum/RogueMaster (track `*/releases/latest`) that
  changes the API version (`firmware_api_major/minor`) — that's the
  signal PromptZero's Capability detection needs an audit pass.
- **Out-of-scope for refresh.** OFW security patches that don't change
  the CLI surface; pure UI changes; asset-pack updates.
- **Authoritative source-of-truth chain.**
  `device_info` field
  → `internal/flipper/capabilities.go` parser
  → per-fork override
  → handler dispatch in `internal/tools/`.
  This catalog documents the *firmware-side reality* that the parser
  expects to see. Drift between this catalog and that file is a bug.
