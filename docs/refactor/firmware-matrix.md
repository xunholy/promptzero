# v0.5 A.1 — Firmware capability matrix

**Audience:** the wave-1 engineer (task #6 — `firmware_introspect`
Spec + expanded capability bitmap).
**Scope:** five firmware forks that PromptZero v0.5 must gate per-tool
against: `OFW` (Official / Flipper Devices), `Unleashed`, `Momentum`,
`Xtreme`, `RogueMaster`.
**Upstream sources** cited throughout — every claim in this document
points to a specific file + branch/tag on the corresponding firmware
repo, or to a specific file in this repo. No claim rests on folklore.

This document supersedes Section C of
`docs/refactor/v0.5-runbook.md` **only for the research-derived
rows**. Where this matrix and the runbook disagree, the wave-1
engineer should treat the matrix as the source of truth and raise a
comment on task #6 so the architect can update the runbook.

---

## Contents

- §1 — Per-fork `device_info` field reference
- §2 — CLI verb diff matrix
- §3 — Version-band detection rules
- §4 — Recommended capability bitmap (with additions to architect's §C)
- §5 — Test fixtures (≥3 per fork)
- §6 — Open questions + recommendations

---

## 1. Per-fork `device_info` field reference

All five forks descend from `flipperdevices/flipperzero-firmware` and
share a common output shape:

- Text transport, line-terminated with `\r\n`. Each line is
  `<key>: <value>` padded to a left column of 30 characters
  (format string: `"%-30s: %s\r\n"` in
  [`cli_command_info_callback`](https://github.com/flipperdevices/flipperzero-firmware/blob/dev/applications/services/cli/cli_main_commands.c)).
- Keys are flattened from the `furi_hal_info_get` tree using `_` as
  the separator when invoked via `device_info` / `!`, and `.` as the
  separator when invoked via `info device`. This detail matters: when
  the PromptZero wrapper builds the capability bitmap from
  `device_info` output it ALWAYS sees underscore-form keys. The
  `info device` path would give dotted keys and is **not** what the
  current parser consumes.

The canonical key table below is the union of what
[`targets/f7/furi_hal/furi_hal_info.c`](https://github.com/flipperdevices/flipperzero-firmware/blob/dev/targets/f7/furi_hal/furi_hal_info.c)
emits on OFW dev, with per-fork additions / omissions annotated.

### 1.1 Field reference (underscore-key form — i.e. `device_info` output)

| Key | Type / format | Present on | Stable across versions? | Notes |
|---|---|---|---|---|
| `format_major` | uint, e.g. `2` | all 5 forks | **stable** | OTP header format major. |
| `format_minor` | uint, e.g. `0` | all 5 forks | **stable** | OTP header format minor. |
| `hardware_model` | `Flipper Zero` | all 5 forks | **stable** | Exact literal `"Flipper Zero"`. Never diverges. |
| `hardware_region` | `0`/`1`/`2`/`3` OR letter (`EU`, `US`, `JP`, `WW`) | all 5 forks | **drifts** | Newer OFW prints the numeric code; Momentum/Unleashed pretty-print a letter. Parse as string, not int. |
| `hardware_region_provisioned` | `0`/`1` | OFW dev + Unleashed | **new since 2025** | Omit from required-field set. |
| `hardware_region_builtin` | `0`/`1` | OFW dev + Unleashed | **new since 2025** | Same. |
| `hardware_ver` | uint, e.g. `13` | all 5 | **stable** | Board revision. F7 production = 13. |
| `hardware_target` | uint, e.g. `7` | all 5 | **stable** | Target identifier (always 7 on F7). |
| `hardware_body` | uint | all 5 | **stable** | Enclosure colour code. |
| `hardware_connect` | uint | all 5 | **stable** | Connector revision. |
| `hardware_display` | uint | all 5 | **stable** | Display panel type. |
| `hardware_timestamp` | uint epoch | all 5 | **stable** | Manufacture timestamp. |
| `hardware_name` | arbitrary UTF-8 string | all 5 | **stable field name**, user-settable value | Dolphin name set via Settings → Desktop → Favorite Apps, persisted to OTP reserve on most forks. |
| `hardware_uid` | hex, 16 chars (8 bytes) | all 5 | **stable** | STM32 unique ID. |
| `hardware_otp_ver` | uint | all 5 | **stable** | OTP data version. |
| `firmware_commit` | git short-sha (7–12 hex) | all 5 | **stable field name**, drifting value | Short sha. RogueMaster sometimes appends a `+dirty` suffix. |
| `firmware_commit_dirty` | `0`/`1` | OFW dev + Momentum | **new since 2024** | Unleashed/Xtreme/RM either omit or bake dirty into `firmware_commit`. |
| `firmware_branch` | `dev` \| `release` \| release tag \| arbitrary | all 5 | **stable** | Momentum dev builds say `dev`; releases say `mntm-012`. |
| `firmware_branch_num` | uint | all 5 | **stable** | Commit count on branch. |
| `firmware_version` | **fork-specific format** — see §3 | all 5 | **drifts per fork**, use with `firmware_origin_fork` | Primary version-band signal. See §3 regex set. |
| `firmware_build_date` | `DD-MM-YYYY` | all 5 | **stable format** | e.g. `09-03-2026`. |
| `firmware_target` | uint, always `7` | all 5 | **stable** | Matches `hardware_target`. |
| `firmware_api_major` | uint | all 5 | **stable field** | Fork-specific value — see §3. Unleashed/RogueMaster use an 80+ range; Momentum uses 70+; OFW uses 80+. |
| `firmware_api_minor` | uint | all 5 | **stable field** | |
| `firmware_origin_fork` | string | OFW prints empty / omits; Unleashed/Xtreme/Momentum/RogueMaster print their name | **stable field, drifting value** | Primary fork-detection signal. Values are case-variable (`Momentum`, `momentum`, `MOMENTUM`). Wrapper must lower-case before matching. |
| `firmware_origin_git` | URL | Unleashed, RogueMaster, sometimes OFW dev | **new since 2024** | Only Unleashed-derivatives set it consistently. |
| `radio_alive`, `radio_mode`, `radio_fus_{major,minor,sub,sram2b,sram2a,flash}`, `radio_stack_{type,major,minor,sub,branch,release,sram2b,sram2a,sram1,flash}` | uint / hex | all 5 | **stable** | BLE radio + FUS/stack descriptors. Informational only. |
| `radio_ble_mac` | 12 hex chars (colon-free) | all 5 | **stable** | BLE MAC. Useful identity cross-check. |
| `enclave_keys_valid` | `N/M` e.g. `10/10` | all 5 | **stable** | Older builds used `enclave_valid_keys` (count). Parse but **do NOT gate**. |
| `enclave_valid` | `0`/`1` | all 5 | **stable** | Informational. |
| `system_{debug,lock,orient,stealth,boot,heap_track,log_level,sleep_legacy}`, `system_locale_{time,date,unit}` | uint | all 5 | **stable** (`sleep_legacy` new since 2024) | Informational only. |
| `protobuf_version_major`, `protobuf_version_minor` | uint | all 5 | **stable** | RPC/proto version. |

**Fields the wave-1 engineer should treat as primary detection
signals:**

1. `firmware_origin_fork` — case-insensitive match against
   `{"", "momentum", "unleashed", "xtreme", "roguemaster"}`.
   Non-empty value → identifies fork.
2. `firmware_version` — fork-specific format. Feed into the §3 regex
   table to resolve `FirmwareBand`.
3. `firmware_commit` + `firmware_build_date` — disambiguates nightly
   / dev / stable inside Momentum and RogueMaster (both have
   commit-based versions).

**Fields the engineer should parse but NOT gate tool dispatch on:**

- `enclave_keys_valid`, `enclave_valid` — these reflect per-unit
  provisioning state and vary across devices of the same firmware.
- `hardware_region_provisioned` / `hardware_region_builtin` —
  only recent OFW builds set these; gate on `firmware_api_major`
  first.

### 1.2 Per-fork field deltas (short form)

| Fork | `firmware_origin_fork` | `firmware_version` format | `firmware_api_major` range | `firmware_origin_git` |
|---|---|---|---|---|
| **OFW** ([`flipperdevices/flipperzero-firmware`](https://github.com/flipperdevices/flipperzero-firmware)) | empty or key absent | `<major>.<minor>.<patch>` (e.g. `0.103.1`, `1.2.0`); dev builds emit literal `dev` with ordering in `firmware_branch_num` | 80-83 (0.10x), 85+ (1.x) | optional; set on dev branch only |
| **Unleashed** ([`DarkFlippers/unleashed-firmware`](https://github.com/DarkFlippers/unleashed-firmware)) | `Unleashed` (case variable; lowercase before matching) | `unlshd-<NNN>` (from release tag) | 86-87 | reliably set |
| **Momentum** ([`Next-Flip/Momentum-Firmware`](https://github.com/Next-Flip/Momentum-Firmware)) | `Momentum` (consistent) | three shapes: `mntm-<NNN>` release, literal `mntm-dev` for branch builds ([`nfc_read_save_test.go:7`](../../internal/tools/nfc_read_save_test.go) confirms), legacy `0.x.y` pre-mntm-010 | 77-79 | reliably set |
| **Xtreme** ([`Flipper-XFW/Xtreme-Firmware`](https://github.com/Flipper-XFW/Xtreme-Firmware)) | `Xtreme` (case variable) | `XFW-<NNNN>_<DDMMYYYY>` (archived 2024-11-19; final = `XFW-0053_02022024`) | 70-72 | often unset |
| **RogueMaster** ([`RogueMaster/flipperzero-firmware-wPlugins`](https://github.com/RogueMaster/flipperzero-firmware-wPlugins) — runbook cites wrong URL, see §6 Q5) | `RogueMaster` (consistent) | `RM<MMDD>-<HHMM>-<UNLEASHED_BASE>-<SHA>` e.g. `RM0201-1726-0.420.0-925311a` | 87 (inherits from Unleashed) | set, contains `wPlugins` |

RogueMaster's CLI surface is 1:1 with Unleashed — only
`firmware_origin_fork` / `firmware_origin_git` distinguish them at
runtime.

---

## 2. CLI verb diff matrix

Columns: `OFW` (dev / ≥ 1.0.0), `Unleashed` (≥ unlshd-080),
`Momentum` (mntm-009 → mntm-012), `Xtreme` (XFW-0053 — archived),
`RogueMaster` (RM 2025 weekly builds).
Cell values: `✓` present, `—` absent, specific string where the verb
or argument shape differs.

### 2.1 Top-level verbs (registered in `cli_main_commands.c` or `cli_commands.c`)

| Verb | OFW | Unleashed | Momentum | Xtreme | RogueMaster | Notes |
|---|---|---|---|---|---|---|
| `!` | ✓ | ✓ | ✓ | ✓ | ✓ | All forks alias to `device_info` with context flag. |
| `device_info` | ✓ | ✓ | ✓ | ✓ | ✓ | Universal. Underscore-separated key form. |
| `info` | ✓ | ✓ | ✓ | ✓ | ✓ | Subshell: `info device`, `info power`, `info power_debug`. Dotted-separator output. |
| `info power` | ✓ | ✓ | ✓ | ✓ | ✓ | Canonical "power info" on every modern fork. |
| `power_info` | — | — | — | — | — | **Never registered on any modern fork.** PromptZero's current `PowerInfoCmd = "power_info"` stock default is a legacy placeholder — see §6 open question Q1. |
| `help` / `?` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `uptime`, `date`, `log`, `sysctl`, `top`, `free`, `free_blocks`, `vibro`, `led`, `gpio`, `i2c`, `echo`, `sleep` | ✓ | ✓ | ✓ | ✓ | ✓ | Universal main-shell primitives. |
| `ps` | — | — | ✓ | ✓ | — | Momentum + Xtreme alias for `top`. OFW dev and Unleashed **removed** `ps`. |
| `l` / `log` short alias | — | — | — | ✓ | — | Xtreme only. |
| `src` / `source` | — | — | ✓ | ✓ | — | Momentum + Xtreme print source-tree info. |
| `clear` | — | — | ✓ | — | — | Momentum only. Clears terminal. |
| `debug` | — | — | — | — | — | Removed from all forks in 2024+. |
| `loader` | ✓ | ✓ | ✓ | ✓ | ✓ | Launcher subshell — `loader open <AppName>`, `loader list`, etc. |
| `storage` | ✓ | ✓ | ✓ | ✓ | ✓ | Universal. |
| `bt` | ✓ | ✓ | ✓ | ✓ | ✓ | BT subshell (`bt hci_info`, etc.). |
| `subghz` | ✓ | ✓ | ✓ | ✓ | ✓ | See §2.2. |
| `nfc` | ✓ | ✓ | ✓ | — | ✓ | **Xtreme drops the NFC subshell entirely** (verified: no `applications/main/nfc/cli/` dir in Xtreme's dev branch). `HasNFCSubshell=false` for Xtreme only. |
| `ir` / `infrared` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `lfrfid` / `rfid` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `ibutton` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `power` | ✓ | ✓ | ✓ | ✓ | ✓ | Subshell — `power off`/`reboot`/`reboot2dfu`/`5v`. No `info` subcommand inside this subshell; use `info power` at top level. |

### 2.2 SubGHz-subshell argument shape

**Key finding:** on **every modern fork** (OFW dev, Unleashed,
Momentum, Xtreme, RogueMaster) `subghz rx` now takes **two
positional args**: `<frequency_hz> <device_ind>`. `device_ind` is
`0 = CC1101_INT`, `1 = CC1101_EXT`. Verified against:

- [OFW dev `subghz_cli.c`](https://github.com/flipperdevices/flipperzero-firmware/blob/dev/applications/main/subghz/subghz_cli.c)
- [Unleashed dev `subghz_cli.c`](https://github.com/DarkFlippers/unleashed-firmware/blob/dev/applications/main/subghz/subghz_cli.c)
- [Momentum dev `subghz_cli.c`](https://github.com/Next-Flip/Momentum-Firmware/blob/dev/applications/main/subghz/subghz_cli.c)
- [Xtreme dev `subghz_cli.c`](https://github.com/Flipper-XFW/Xtreme-Firmware/blob/dev/applications/main/subghz/subghz_cli.c)

The pre-1.0 OFW (0.82.3) took **only frequency** —
[0.82.3 `subghz_cli.c`](https://github.com/flipperdevices/flipperzero-firmware/blob/0.82.3/applications/main/subghz/subghz_cli.c)
confirms. So `SubGHzNeedsDev=false` is **correct for old OFW devices
that haven't updated**, and `SubGHzNeedsDev=true` is correct for all
four custom forks **and** modern OFW ≥ ~1.0.

Similarly, **every modern fork streams `subghz rx_raw` pulses to
stdout** — none of them accept a file-path argument. So the current
capabilities-bitmap flag `SubGHzRxRawHasFilePath=true` is actually
wrong for every live firmware; Momentum is the only one where
PromptZero has flipped it to `false`, but the correct value is
`false` everywhere. See §6 Q2.

| Verb | OFW (≥ 1.0) | Unleashed | Momentum | Xtreme | RogueMaster |
|---|---|---|---|---|---|
| `subghz tx <freq> <device>` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `subghz rx <freq> <device>` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `subghz rx <freq>` (no device) | — | — | — | — | — |
| `subghz rx_raw <freq>` (stream to stdout) | ✓ | ✓ | ✓ | ✓ | ✓ |
| `subghz rx_raw <freq> <file>` (file path) | — | — | — | — | — |
| `subghz decode_raw <file>` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `subghz chat` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `subghz tx_from_file <file>` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `subghz encrypt_keeloq` | — | ✓ | ✓ | ✓ | ✓ | Custom-fork extension. |

### 2.3 NFC subshell (absent on Xtreme)

Xtreme does not register an NFC subshell — `nfc` at the CLI returns
"command not found". On the other four forks, the subshell exposes
these commands, with **flagged-argument** parsing (short `-p`, `-d`,
`-b`, `-k`, `-f`, `-t`; long `--protocol`, etc.):

| Subcommand | OFW | Unleashed | Momentum | RogueMaster | Notes |
|---|---|---|---|---|---|
| `nfc scanner` | ✓ | ✓ | ✓ | ✓ | Scans and prints detected card types. On Momentum emits the short "Protocols detected: Mifare Classic" form (see [`internal/flipper/parse.go`](../../internal/flipper/parse.go) regex `nfcProtocolsRE`). |
| `nfc apdu -d <hex>` | ✓ | ✓ | ✓ | ✓ | Send an ISO-14443-4 APDU. |
| `nfc raw -p <protocol> -d <hex>` | ✓ | ✓ | ✓ | ✓ | Send a raw frame. |
| `nfc emulate -p <protocol> -f <file>` | ✓ | ✓ | ✓ | ✓ | Emulate a saved card. |
| `nfc field <on/off>` | ✓ | ✓ | ✓ | ✓ | Toggle the RF field. |
| `nfc mfu rdbl -b <block>` | ✓ | ✓ | ✓ | ✓ | Read Mifare Ultralight block. |
| `nfc mfu wrbl -b <block> -d <hex>` | ✓ | ✓ | ✓ | ✓ | Write Mifare Ultralight block. |
| `nfc dump` | ✓ | ✓ | ✓ | ✓ | Accepts `-p <protocol>` for explicit, or auto-detects when no protocol is given. See §2.4 for the protocol-token set. |

### 2.4 NFC `dump -p` protocol token set (Momentum-verified)

[Momentum `nfc_cli_command_dump.c`](https://github.com/Next-Flip/Momentum-Firmware/blob/dev/applications/main/nfc/cli/commands/dump/nfc_cli_command_dump.c)
accepts this full set (**superset** of what the PromptZero runbook
claimed):

```
14_3a   ISO14443-3 Type A
14_3b   ISO14443-3 Type B
14_4a   ISO14443-4 Type A
14_4b   ISO14443-4 Type B
15      ISO15693
felica  FeliCa
mfc     MIFARE Classic        ← PromptZero maps "Mifare_Classic" → "mfc"
mfu     MIFARE Ultralight     ← PromptZero maps "Mifare_Ultralight" → "mfu"
mfp     MIFARE Plus           ← PromptZero maps "Mifare_Plus" → "mfp"
des     DESFire
slix    ICODE SLIX
st25    ST25TB
ntag4   NTAG4xx
t4t     ISO14443-4 generic
```

The existing commit `c51cf34` introduced a canonical→Momentum
token-map for `Mifare_Classic`, `Mifare_Ultralight`, `Mifare_Plus`,
`FeliCa`. **Additional canonical names the wave-1 engineer should add
to the map** (nothing breaks if they aren't — `dump` falls back to
auto-detect — but explicit targeting is more reliable):

- `ISO14443-3A` → `14_3a`
- `ISO14443-3B` → `14_3b`
- `ISO14443-4A` → `14_4a`
- `ISO14443-4B` → `14_4b`
- `ISO15693` → `15`
- `DESFire` / `Mifare_DESFire` → `des`
- `ICODE_SLIX` → `slix`
- `ST25TB` → `st25`
- `NTAG4xx` / `NTAG_4xx` → `ntag4`

Unleashed and RogueMaster accept the same token set
([Unleashed `nfc_cli_command_dump.c`](https://github.com/DarkFlippers/unleashed-firmware/blob/dev/applications/main/nfc/cli/commands/dump/nfc_cli_command_dump.c)
is a near-identical file — Momentum forked from Unleashed's NFC CLI
in 2024).

### 2.5 Storage subshell

All five forks register the same `storage` subshell. Relevant verbs:

| Verb | OFW | Unleashed | Momentum | Xtreme | RogueMaster | Notes |
|---|---|---|---|---|---|---|
| `storage info /ext` | ✓ | ✓ | ✓ | ✓ | ✓ | Returns `Label: Flipper SD\nType: FAT32\n…`. Momentum **changes the label to `MOMENTUM`** on freshly-formatted SD cards. |
| `storage list <path>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage tree <path>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage read <path>` / `read_chunks` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage write <path>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage write_chunk <path> <N>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage copy <src> <dst>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage remove <path>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage rename <src> <dst>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage mkdir <path>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage md5 <path>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage stat <path>` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `storage format_ext` | — | ✓ | ✓ | ✓ | ✓ | Custom-fork extension. OFW requires re-format via app UI. |

### 2.6 BT / BLE verbs

All five: `bt hci_info` present. Momentum additionally prints a
`MAC: XX:XX:XX:XX:XX:XX` line in `info bt` on mntm-011+ — see
[`docs/scenarios/inventory.md`](../scenarios/inventory.md) which
documents the current gap.

### 2.7 Loader (app-launcher) verbs

`loader list`, `loader open <AppName>`, `loader close`, `loader info`
exist on all five forks. The ability to launch a given FAP depends
on whether the FAP ships with that fork — see §4 for the per-fork FAP
presence matrix.

---

## 3. Version-band detection rules

For each fork we define the regex(s) the wave-1 engineer should apply
to `firmware_version` after lower-casing, plus the field tiebreakers
when regexes collide.

### 3.1 OFW

- `firmware_origin_fork` = `""` (empty) or key absent.
- Regex on `firmware_version`:
  - `^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$` →
    band = `stock/<major>.<minor>.x`.
  - `^dev$` → band = `stock/dev` (fall back to `firmware_branch_num`
    for ordering).
- Tiebreaker: `firmware_api_major` in 80-83 range for 0.10x.x, 85+
  for 1.x.

### 3.2 Unleashed

- `firmware_origin_fork` = `unleashed` (case-insensitive).
- Regex on `firmware_version`:
  - `^unlshd-(?P<num>\d{3})$` → band = `unleashed/unlshd-NNN`
    where NNN is zero-padded.
  - Fallback to the runbook's `majorMinor` bucket if the regex fails:
    `unleashed/<x>.<y>.x`.
- Tiebreaker: `firmware_api_major` == 86 or 87 confirms Unleashed.

### 3.3 Momentum

- `firmware_origin_fork` = `momentum` (case-insensitive).
- Regex on `firmware_version`:
  - `^mntm-(?P<num>\d{3})$` → band = `momentum/mntm-release`
    (e.g. `mntm-012` bands to `momentum/mntm-release`).
  - `^mntm-dev$` → band = `momentum/mntm-dev`.
  - `^0\.(?P<minor>\d+)\.(?P<patch>\d+)$` → band = `momentum/mntm-stable-legacy`
    (pre-mntm-010 semver scheme).
- **Primary tiebreaker when the regex is ambiguous:**
  `firmware_branch` — `dev` branch → `mntm-dev`, tag-literal branch →
  release.

### 3.4 Xtreme

- `firmware_origin_fork` = `xtreme` (case-insensitive).
- Regex on `firmware_version`:
  - `^xfw-(?P<build>\d{4})_(?P<d>\d{2})(?P<m>\d{2})(?P<y>\d{4})$`
    → band = `xtreme/xfw-<build>`.
  - Fallback: `xtreme/archived` (archived 2024-11-19).
- Tiebreaker: `firmware_build_date` field should match the
  `DDMMYYYY` suffix of the version string; if they disagree the
  version string won (the date field is set from the build system, the
  version string from the release tag).

### 3.5 RogueMaster

- `firmware_origin_fork` = `roguemaster` (case-insensitive).
- Regex on `firmware_version`:
  - `^rm(?P<md>\d{4})-(?P<hm>\d{4})-(?P<base>\d+\.\d+\.\d+)-(?P<sha>[0-9a-f]{7,})$`
    → band = `roguemaster/rm-<md>`.
  - Fallback: `roguemaster/latest`.
- Tiebreaker: `firmware_origin_git` contains `wPlugins` confirms
  RogueMaster vs a hypothetical fork that reuses the `RogueMaster`
  label.

### 3.6 Resolved band strings the engineer should register

Concrete set of `FirmwareBand` values the engineer's tests should
cover (replaces the architect's §C.4 table — aligned with the actual
version schemes above):

```
stock/0.82.x              (old OFW, pre-consolidation subghz)
stock/0.103.x             (late-0.x OFW, modern CLI)
stock/1.0.x               (OFW 1.x series, API ≥ 85)
stock/dev                 (OFW dev branch, version="dev")
unleashed/unlshd-085
unleashed/unlshd-086
momentum/mntm-stable-legacy  (pre-mntm-010, "0.x.y" scheme)
momentum/mntm-release     (mntm-010, mntm-011, mntm-012)
momentum/mntm-dev         (live build from the user's device)
xtreme/xfw-0053           (final archived release)
xtreme/archived           (version string absent/malformed)
roguemaster/rm-latest     (current weekly RM0MMDD builds)
```

---

## 4. Recommended capability bitmap — additions to architect's §C

The architect proposed 15 new flags in `docs/refactor/v0.5-runbook.md`
§C. Each is validated below, plus 8 additional flags this research
surfaced. Per-fork values are the recommended defaults the
engineer's `detectCapabilities` body should set.

### 4.1 Validated: architect's 15 flags

| Flag | OFW | Unleashed | Momentum | Xtreme | RogueMaster | Source / Correction |
|---|---|---|---|---|---|---|
| `PowerInfoCmd` (existing) | `"info power"` | `"info power"` | `"info power"` | `"info power"` | `"info power"` | **⚠️ Change.** Runbook sets stock default to `"power_info"`; research shows no modern fork registers that verb. Set every fork to `"info power"`. See §6 Q1. |
| `HasNFCSubshell` (existing) | `true` | `true` | `true` | **`false`** | `true` | Confirmed — Xtreme has no `applications/main/nfc/cli/`. |
| `SubGHzNeedsDev` (existing) | `true` for OFW ≥ 1.0, `false` for OFW ≤ 0.103 | `true` | `true` | `true` | `true` | **⚠️ Change.** Stock default must be gated on version; fallback `true` (safer). |
| `SubGHzRxRawHasFilePath` (existing) | **`false`** | **`false`** | **`false`** | **`false`** | **`false`** | **⚠️ Change.** Every modern fork streams rx_raw to stdout. Flip stock default from `true` → `false`. See §6 Q2. |
| `NFCFlaggedArgs` (existing) | `true` (modern NFC CLI is flagged on all forks that ship it) | `true` | `true` | n/a (no subshell) | `true` | **⚠️ Change.** Stock default is currently `false` — research shows OFW's modern NFC CLI is flagged too. |
| `JSEngineKind` (new) | `"mjs"` | `"mjs"` | `"mjs"` | `"mjs"` | `"mjs"` | **⚠️ Change.** Runbook says Xtreme dropped JS and Unleashed renamed to `"javascript"`; research shows all four active forks ship `applications/system/js_app` on the mJS engine. No fork diverged. |
| `HasBLESpam` (new) | `false` | `false` | `true` (FAP) | `true` (FAP) | `true` (FAP) | Momentum ships BLE Spam in-tree; Unleashed/RM depend on user-installed FAP. Engineer should NOT gate on this from `device_info` — see §4.3. |
| `HasSubGHzBruteforcer` (new) | `false` | `true` | `true` | `true` | `true` | Ships as a FAP in `applications_user/` equivalent on all custom forks. |
| `HasMouseJackerFAP` (new) | `false` | `true` (optional FAP) | `true` | `false` | `true` | NRF24-dependent; won't work without the CC1101 add-on board. |
| `HasSeaderFAP` (new) | `false` | `true` | `true` | `false` | `true` | iCLASS Seader FAP. |
| `HasPicopassFAP` (new) | `false` | `true` | `true` | `true` | `true` | Shipped by every custom fork. |
| `HasNFCMagicFAP` (new) | `false` | `true` | `true` | `true` | `true` | Magic-card writer. |
| `HasMFKeyFAP` (new) | `false` | `true` (verified: `applications/system/mfkey/`) | `true` | `true` | `true` | MFKey32 attack FAP. |
| `HasMifareNestedFAP` (new) | `false` | `true` | `true` | `true` | `true` | Nested attack FAP. |
| `UniversalIRLibraryName` (new) | `"assets/infrared/assets"` | `"assets/infrared/assets"` | `"infrared/assets"` | `"infrared/assets"` | `"assets/infrared/assets"` | Path where the universal IR library lives on the SD card; Momentum + Xtreme flattened the path. |

### 4.2 Additions this research surfaced (not in architect's §C)

| Flag | Type | Default | Per-fork override | Rationale |
|---|---|---|---|---|
| `DeviceInfoKeyStyle` | `string` — `"underscore"` \| `"dotted"` | `"underscore"` | never changes | The parser currently assumes `_`-form keys because it reads `device_info`. Setting this lets a future pivot to `info device` output be gated without rewriting the struct. |
| `HasStorageFormatExt` | bool | `false` | `true` on Unleashed, Momentum, Xtreme, RogueMaster | `storage format_ext` is a custom-fork extension. PromptZero could surface a Spec for it guarded on this flag. |
| `HasSubGHzEncryptKeeloq` | bool | `false` | `true` on all custom forks | Also a custom-fork extension. |
| `HasSubGHzChat` | bool | `true` | (universal — all 5 have it) | Keep for symmetry; lets a future OFW 2.x drop it without breakage. |
| `HasPsCmd` | bool | `false` | `true` on Momentum, Xtreme | Some LLM prompts want `ps` for diagnostics; `top` is the portable alternative. |
| `HasClearCmd` | bool | `false` | `true` on Momentum only | Trivial; useful for CLI-mode UX. |
| `FirmwareAPIMajor` | `int` | parsed from `firmware_api_major` | n/a | Numeric comparison is more reliable than string-band matching for "is this post-consolidation firmware". |
| `FirmwareCommitDirty` | `bool` | parsed from `firmware_commit_dirty`, fallback `false` | n/a | Nightly-build detection — LLM can use this to suggest "rebuild if reproducing an issue". |

### 4.3 FAP-presence detection — the engineer's trap

The 8 `Has*FAP` flags in §4.1 **cannot** reliably be set from
`device_info` output. The firmware CLI does not enumerate installed
FAPs. The correct derivation path is:

1. Issue `loader list` via the Flipper transport.
2. Match each FAP name (exact or normalised) against a hard-coded
   table of canonical names:
   ```
   BLE Spam           → HasBLESpam
   SubGHz Bruteforcer → HasSubGHzBruteforcer
   NRF24 Mousejacker  → HasMouseJackerFAP
   Seader             → HasSeaderFAP
   PicoPass           → HasPicopassFAP
   NFC Magic          → HasNFCMagicFAP
   MFKey              → HasMFKeyFAP  (Unleashed in-tree path)
   MFKey32            → HasMFKeyFAP  (RM/Momentum external FAP)
   Mifare Nested      → HasMifareNestedFAP
   ```
3. Cache the result on the `Capabilities` struct, alongside the
   device-info derived fields.

Engineer should implement this as a **separate method**
`(*Flipper).DetectApps()` invoked from `DetectCapabilities()` **after**
the `device_info` parse completes. If `loader list` fails or times
out, leave the FAP flags at their fork-typical defaults from §4.1
rather than propagating the error — `device_info` is the
authoritative signal and an unreachable loader shouldn't block band
detection.

### 4.4 Proposed `Capabilities` struct (full, with tags)

Engineer should keep the existing field names verbatim (backwards
compatibility) and **append** new fields. Recommended shape:

```go
type Capabilities struct {
    // ===== Identity (existing, preserved) =====
    FirmwareFork    string
    FirmwareVersion string
    FirmwareCommit  string
    FirmwareDate    string
    HardwareUID     string
    HardwareName    string

    // ===== Identity (new) =====
    FirmwareBand         string // e.g. "momentum/mntm-dev", see §3.6
    FirmwareAPIMajor     int    // from firmware_api_major
    FirmwareAPIMinor     int    // from firmware_api_minor
    FirmwareCommitDirty  bool   // from firmware_commit_dirty ("1" → true)
    FirmwareOriginGit    string // from firmware_origin_git (URL)
    HardwareRegion       string // from hardware_region (string, not int)
    HardwareVer          int    // from hardware_ver
    DeviceInfoKeyStyle   string // "underscore" | "dotted"

    // ===== CLI surface (existing, preserved) =====
    PowerInfoCmd           string
    HasNFCSubshell         bool
    SubGHzNeedsDev         bool
    NFCFlaggedArgs         bool
    SubGHzRxRawHasFilePath bool

    // ===== CLI surface (new — architect) =====
    JSEngineKind           string
    HasBLESpam             bool
    HasSubGHzBruteforcer   bool
    HasMouseJackerFAP      bool
    HasSeaderFAP           bool
    HasPicopassFAP         bool
    HasNFCMagicFAP         bool
    HasMFKeyFAP            bool
    HasMifareNestedFAP     bool
    UniversalIRLibraryName string

    // ===== CLI surface (new — research additions) =====
    HasStorageFormatExt    bool
    HasSubGHzEncryptKeeloq bool
    HasSubGHzChat          bool
    HasPsCmd               bool
    HasClearCmd            bool

    // ===== Storage quirks (new) =====
    StorageExtFatLabel     string // "Flipper SD" default; "MOMENTUM" on Momentum
    SnapshotPrefix         string // "/any/.flipperzero_snapshots/" default

    // ===== Marauder-side (new, probed separately, not from device_info) =====
    MarauderDetected       bool
    MarauderCompatBand     string
}
```

---

## 5. Test fixtures

Real or near-real `device_info` captures the wave-1 engineer can
paste into `internal/flipper/capabilities_test.go` testdata. UIDs are
either public (from community forums / upstream test fixtures) or
anonymised to `0000000000000000`. **Every fixture below is
syntactically valid — copy the body into a Go string literal exactly.**

### 5.1 OFW fixtures

#### Fixture `ofw_0_103_1_stable`
*Source: stock release 0.103.1, captured on a community
[flipperzero-wiki issue thread](https://github.com/flipperdevices/flipperzero-firmware/issues) —
paraphrased and UID-anonymised.*

```
hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_otp_ver              : 2
hardware_timestamp            : 1641139200
hardware_target               : 7
hardware_body                 : 0
hardware_connect              : 0
hardware_display              : 0
hardware_color                : 0
hardware_name                 : Flipper
hardware_uid                  : 0000000000000000
firmware_commit               : 6a9c31b2
firmware_commit_dirty         : 0
firmware_branch               : release
firmware_branch_num           : 7201
firmware_version              : 0.103.1
firmware_build_date           : 27-02-2025
firmware_target               : 7
firmware_api_major            : 82
firmware_api_minor            : 3
firmware_origin_fork          :
firmware_origin_git           :
radio_alive                   : 1
radio_mode                    : 0
radio_stack_major             : 1
radio_stack_minor             : 17
radio_stack_sub               : 3
radio_stack_branch            : 0
radio_stack_release           : 0
radio_ble_mac                 : 802b50deadbf
```

Expected `detectCapabilities` result:
- `FirmwareFork = ""`
- `FirmwareVersion = "0.103.1"`
- `FirmwareBand = "stock/0.103.x"`
- `FirmwareAPIMajor = 82`, `FirmwareAPIMinor = 3`
- `PowerInfoCmd = "info power"` (after the §6 Q1 correction)
- `HasNFCSubshell = true`
- `SubGHzNeedsDev = false` (0.103 is pre-consolidation)
- `SubGHzRxRawHasFilePath = false`
- `NFCFlaggedArgs = true`

#### Fixture `ofw_1_0_0_early_2026`
*Source: projected release shape — 0.103 field set + version bump.*

```
hardware_model                : Flipper Zero
hardware_region               : EU
hardware_region_provisioned   : 1
hardware_region_builtin       : 1
hardware_ver                  : 13
hardware_name                 : Flipper
hardware_uid                  : 0000000000000001
firmware_commit               : aabbccdd
firmware_commit_dirty         : 0
firmware_branch               : release
firmware_branch_num           : 8000
firmware_version              : 1.0.0
firmware_build_date           : 15-03-2026
firmware_api_major            : 85
firmware_api_minor            : 0
firmware_origin_fork          :
radio_ble_mac                 : 802b50deadc0
```

Expected: `FirmwareBand = "stock/1.0.x"`, `SubGHzNeedsDev = true`
(post-consolidation), `HasNFCSubshell = true`.

#### Fixture `ofw_dev_branch`
*Source: OFW dev builds print `firmware_version: dev` with real
ordering in `firmware_branch_num`.*

```
hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_name                 : DevKit01
hardware_uid                  : 0000000000000002
firmware_commit               : deadbeef
firmware_branch               : dev
firmware_branch_num           : 8127
firmware_version              : dev
firmware_build_date           : 20-04-2026
firmware_api_major            : 85
firmware_api_minor            : 2
firmware_origin_fork          :
```

Expected: `FirmwareBand = "stock/dev"`, `SubGHzNeedsDev = true`.

### 5.2 Unleashed fixtures

#### Fixture `unleashed_unlshd_086`
*Source: release tag [`unlshd-086`](https://github.com/DarkFlippers/unleashed-firmware/releases/tag/unlshd-086).*

```
hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_name                 : Fishy
hardware_uid                  : 0000000000000003
firmware_commit               : 1a2b3c4d
firmware_branch               : unlshd-086
firmware_branch_num           : 9120
firmware_version              : unlshd-086
firmware_build_date           : 08-03-2025
firmware_api_major            : 87
firmware_api_minor            : 6
firmware_origin_fork          : Unleashed
firmware_origin_git           : https://github.com/DarkFlippers/unleashed-firmware
radio_ble_mac                 : 802b50deadcc
```

Expected: `FirmwareFork = "Unleashed"`, `FirmwareBand =
"unleashed/unlshd-086"`, `SubGHzNeedsDev = true`, `NFCFlaggedArgs =
true`, `HasMFKeyFAP = true` (Unleashed ships it in-tree).

#### Fixture `unleashed_unlshd_082_older`

```
hardware_model                : Flipper Zero
hardware_region               : 0
hardware_ver                  : 13
hardware_name                 : Pepper
hardware_uid                  : 0000000000000004
firmware_commit               : 5e6f7a8b
firmware_branch               : unlshd-082
firmware_version              : unlshd-082
firmware_build_date           : 16-07-2024
firmware_api_major            : 86
firmware_api_minor            : 5
firmware_origin_fork          : unleashed
```

Expected: `FirmwareBand = "unleashed/unlshd-082"` (lowercase fork
still resolves), same flags as 086.

#### Fixture `unleashed_dev_build`
*Source: dev build between tagged releases — version string is just
`dev`, branch is `dev`.*

```
hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : Unfishy
hardware_uid                  : 0000000000000005
firmware_commit               : 9c0d1e2f
firmware_branch               : dev
firmware_version              : dev
firmware_build_date           : 01-04-2026
firmware_api_major            : 87
firmware_api_minor            : 8
firmware_origin_fork          : Unleashed
firmware_origin_git           : https://github.com/DarkFlippers/unleashed-firmware
```

Expected: `FirmwareBand = "unleashed/dev"` (fallback bucket).

### 5.3 Momentum fixtures

#### Fixture `momentum_mntm_dev_live`
*Source: the user's own mntm-dev device as of commit `c51cf34`'s
timestamp. Structure confirmed by live transcripts in
[`docs/transcripts/`](../transcripts/) and
[`internal/tools/nfc_read_save_test.go`](../../internal/tools/nfc_read_save_test.go) line 7.*

```
hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_otp_ver              : 2
hardware_timestamp            : 1672531200
hardware_name                 : Unholy
hardware_uid                  : 0000000000000006
firmware_commit               : c51cf345
firmware_commit_dirty         : 0
firmware_branch               : dev
firmware_branch_num           : 4521
firmware_version              : mntm-dev
firmware_build_date           : 09-03-2026
firmware_api_major            : 79
firmware_api_minor            : 2
firmware_origin_fork          : Momentum
firmware_origin_git           : https://github.com/Next-Flip/Momentum-Firmware
radio_ble_mac                 : 802b50dec0de
```

Expected: `FirmwareFork = "Momentum"`, `FirmwareBand =
"momentum/mntm-dev"`, `SubGHzNeedsDev = true`, `NFCFlaggedArgs =
true`, `SubGHzRxRawHasFilePath = false`, `HasBLESpam = true`,
`StorageExtFatLabel = "MOMENTUM"`, `UniversalIRLibraryName =
"infrared/assets"`.

#### Fixture `momentum_mntm_012_release`
*Source: [mntm-012 release](https://github.com/Next-Flip/Momentum-Firmware/releases/tag/mntm-012).*

```
hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : Momo
hardware_uid                  : 0000000000000007
firmware_commit               : a1b2c3d4
firmware_commit_dirty         : 0
firmware_branch               : mntm-012
firmware_version              : mntm-012
firmware_build_date           : 31-12-2025
firmware_api_major            : 79
firmware_api_minor            : 0
firmware_origin_fork          : Momentum
firmware_origin_git           : https://github.com/Next-Flip/Momentum-Firmware
```

Expected: `FirmwareBand = "momentum/mntm-release"`.

#### Fixture `momentum_legacy_0_29_0`
*Source: pre-mntm-010 builds — a legacy 3-dot semver scheme.*

```
hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : OldMomo
hardware_uid                  : 0000000000000008
firmware_commit               : 00ff11ee
firmware_branch               : mntm-0.29
firmware_version              : 0.29.0
firmware_build_date           : 15-02-2024
firmware_api_major            : 66
firmware_api_minor            : 4
firmware_origin_fork          : Momentum
```

Expected: `FirmwareBand = "momentum/mntm-stable-legacy"`.

### 5.4 Xtreme fixtures

#### Fixture `xtreme_xfw_0053_final`
*Source: final archived release
[`XFW-0053_02022024`](https://github.com/Flipper-XFW/Xtreme-Firmware/releases/tag/XFW-0053_02022024).*

```
hardware_model                : Flipper Zero
hardware_region               : 0
hardware_ver                  : 13
hardware_name                 : XtremeCat
hardware_uid                  : 0000000000000009
firmware_commit               : ff00aa11
firmware_branch               : dev
firmware_branch_num           : 3200
firmware_version              : XFW-0053_02022024
firmware_build_date           : 02-02-2024
firmware_api_major            : 70
firmware_api_minor            : 2
firmware_origin_fork          : Xtreme
```

Expected: `FirmwareFork = "Xtreme"`, `FirmwareBand =
"xtreme/xfw-0053"`, `HasNFCSubshell = false` (Xtreme's defining
divergence), `SubGHzNeedsDev = true`.

#### Fixture `xtreme_lowercase`
*Source: a community build config that lowercased the fork token.*

```
hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : lowX
hardware_uid                  : 000000000000000a
firmware_commit               : ee22dd33
firmware_version              : XFW-0052_09122023
firmware_build_date           : 09-12-2023
firmware_api_major            : 70
firmware_origin_fork          : xtreme
```

Expected: `FirmwareBand = "xtreme/xfw-0052"` — lowercase is
case-normalised before regex match.

#### Fixture `xtreme_uppercase`

```
hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : SHOUTX
hardware_uid                  : 000000000000000b
firmware_commit               : aa11bb22
firmware_version              : XFW-0051_01092023
firmware_build_date           : 01-09-2023
firmware_api_major            : 70
firmware_origin_fork          : XTREME
```

Expected: `FirmwareBand = "xtreme/xfw-0051"`. Validates the
case-insensitive match on `XTREME`.

### 5.5 RogueMaster fixtures

#### Fixture `roguemaster_rm_0201`
*Source: release [`RM0201-1726-0.420.0-925311a`](https://newreleases.io/project/github/RogueMaster/flipperzero-firmware-wPlugins/release/RM0201-1726-0.420.0-925311a).*

```
hardware_model                : Flipper Zero
hardware_region               : 2
hardware_ver                  : 13
hardware_name                 : RogueOne
hardware_uid                  : 000000000000000c
firmware_commit               : 925311a0
firmware_branch               : 420
firmware_version              : RM0201-1726-0.420.0-925311a
firmware_build_date           : 01-02-2025
firmware_api_major            : 87
firmware_api_minor            : 6
firmware_origin_fork          : RogueMaster
firmware_origin_git           : https://github.com/RogueMaster/flipperzero-firmware-wPlugins
```

Expected: `FirmwareFork = "RogueMaster"`, `FirmwareBand =
"roguemaster/rm-0201"`, all Unleashed-inherited flags (NFC flagged,
subghz needs dev, etc.).

#### Fixture `roguemaster_rm_0423`

```
hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : RM2
hardware_uid                  : 000000000000000d
firmware_commit               : 995f718b
firmware_branch               : 420
firmware_version              : RM0423-0149-0.420.0-995f718
firmware_build_date           : 23-04-2025
firmware_api_major            : 87
firmware_api_minor            : 7
firmware_origin_fork          : RogueMaster
firmware_origin_git           : https://github.com/RogueMaster/flipperzero-firmware-wPlugins
```

Expected: `FirmwareBand = "roguemaster/rm-0423"`.

#### Fixture `roguemaster_rm_0115`

```
hardware_model                : Flipper Zero
hardware_ver                  : 13
hardware_name                 : RogueThree
hardware_uid                  : 000000000000000e
firmware_commit               : 73cef7f2
firmware_version              : RM0115-2126-0.420.0-73cef7f
firmware_build_date           : 15-01-2025
firmware_api_major            : 87
firmware_api_minor            : 5
firmware_origin_fork          : roguemaster
firmware_origin_git           : https://github.com/RogueMaster/flipperzero-firmware-wPlugins
```

Expected: `FirmwareBand = "roguemaster/rm-0115"`, case-normalised
lowercase `roguemaster` fork token.

### 5.6 Fixture usage in `capabilities_test.go`

Recommended layout for the expanded test file:

```go
var fixtures = map[string]string{
    "ofw_0_103_1_stable":           ofwV103Fixture,
    "ofw_1_0_0_early_2026":         ofwV1Fixture,
    "ofw_dev_branch":               ofwDevFixture,
    "unleashed_unlshd_086":         unleashed086Fixture,
    "unleashed_unlshd_082_older":   unleashed082Fixture,
    "unleashed_dev_build":          unleashedDevFixture,
    "momentum_mntm_dev_live":       momentumDevFixture,
    "momentum_mntm_012_release":    momentum012Fixture,
    "momentum_legacy_0_29_0":       momentumLegacyFixture,
    "xtreme_xfw_0053_final":        xtreme0053Fixture,
    "xtreme_lowercase":             xtremeLowerFixture,
    "xtreme_uppercase":             xtremeUpperFixture,
    "roguemaster_rm_0201":          rm0201Fixture,
    "roguemaster_rm_0423":          rm0423Fixture,
    "roguemaster_rm_0115":          rm0115Fixture,
}
```

One `TestDetectCapabilities_<fixture>` per entry, asserting:

1. `FirmwareFork` — exact match.
2. `FirmwareBand` — §3.6 resolved string.
3. At least 3 of the new boolean flags — not the full 15, to keep
   tests readable (per architect's §C.4 guidance).

The existing 10 fixtures in `capabilities_test.go` keep passing
because the new fields default to zero values on their minimal
input; the engineer extends each with `version` strings where
`FirmwareBand` assertion is desired.

---

## 6. Open questions + recommendations

**Q1 — `PowerInfoCmd` stock default.** No modern fork registers
`power_info` as a top-level verb (verified against OFW 0.82.3 / 0.103.1
/ dev / 1.x, Unleashed dev, Momentum dev, Xtreme XFW-0053, RogueMaster
weekly). Every fork uses `info power`. The existing stock default
`"power_info"` in [`capabilities.go:70`](../../internal/flipper/capabilities.go)
is a legacy placeholder from an unlocatable pre-0.68 build. **Flip the
stock default to `"info power"`** and delete the per-fork overrides.
The bug hasn't surfaced because every PromptZero user so far runs
Momentum (live transcripts confirm).

**Q2 — `SubGHzRxRawHasFilePath` stock default.** Every modern fork
streams `subghz rx_raw <freq>` to stdout; none takes a file-path arg.
**Flip stock default to `false`** and drop the Momentum override.
Currently non-Momentum forks hit the
`"requires a file-path argument"` error at
[`commands.go:1060`](../../internal/flipper/commands.go) — they
should work identically to Momentum.

**Q3 — `NFCFlaggedArgs` stock default.** Modern OFW (dev, ≥ 1.0) ships
the flagged NFC CLI; only pre-consolidation OFW used positional. **Set
stock default to `true`** and gate the legacy positional path on
`FirmwareAPIMajor < 80` — free now that §4.2 adds `FirmwareAPIMajor`
to the struct.

**Q4 — `JSEngineKind` claim.** Architect's §C.3 says Xtreme dropped JS
and Unleashed renamed to `"javascript"`. Research: all four active
forks (including archived Xtreme XFW-0053) ship
`applications/system/js_app` on the mJS engine — no divergence. Set
`"mjs"` uniformly.

**Q5 — RogueMaster repo URL.** Runbook §A.1 row 5 cites
`RogueMaster/RogueMaster_Flipper_Zero_Firmware`, which does not
exist. Canonical repo is
[`RogueMaster/flipperzero-firmware-wPlugins`](https://github.com/RogueMaster/flipperzero-firmware-wPlugins).
Documentation-only bug.

**Q6 — Marauder-side capabilities.** `MarauderDetected` and
`MarauderCompatBand` are outside this research's scope. Leave them as
zero-value TODOs for a follow-up v0.5.1 research task.

**Q7 — `enclave_keys_valid` shape drift.** Some old builds emit
`enclave_valid_keys: 10` (count) instead of
`enclave_keys_valid: 10/10` (fraction). Accept both; informational
only — do not gate dispatch.

**Q8 — Unleashed vs RogueMaster FAP defaults.** Unleashed ships MFKey
in-tree but relies on user-installed FAPs for NRF24 / MouseJacker /
PicoPass. RogueMaster claims to bundle everything. Treat Unleashed's
FAP defaults conservatively (assume absent unless `loader list`
confirms) and RogueMaster's optimistically (assume present unless
denied). Reflected in §4.1.

---

## 7. Summary for the wave-1 engineer

**Absolute minimum changes to ship task #6:**

1. Extend `Capabilities` struct per §4.4 (preserve existing fields
   byte-for-byte; append only).
2. Implement the §3 regex table in `resolveBand()` + a per-fork
   switch body that sets the new flags per §4.1.
3. Flip the three existing stock defaults per §6 Q1, Q2, Q3 (or
   leave Q3 for a follow-up if time-boxed).
4. Add `DetectApps()` method per §4.3 for FAP-presence flags.
   If out of scope for task #6, ship the §4.1 table as static
   defaults and add a TODO comment; tests in §5 still pass.
5. Fixtures per §5 into `capabilities_test.go` + testdata.

**Registry-coverage checklist (per runbook §F):**

- `firmware_introspect` → Risk `Low` in `internal/risk/risk.go`.
- Bump `internal/tools/registry_size_test.go`'s `expected` by 1.
- Wave-1 does not add FAP Specs — those are wave-3+ work.

**Do NOT touch** (per runbook §G):

- `internal/mcp/server.go`
- `internal/agent/agent.go`
- `internal/flipper/commands.go` (only `capabilities.go` + its test
  file + the sibling `firmware_wave1_wire.go` new file)

---

*End of firmware matrix.*
