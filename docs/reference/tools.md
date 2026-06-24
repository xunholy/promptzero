# Tool reference

A curated reference of the **core** device, RF, NFC/RFID, and credential tools,
grouped by subsystem — the most-used primitives, not the whole registry. The
full set is much larger (600+ tools and growing); run `/tools` (or
`tool_search <query>`) in the REPL for the complete live list with schemas and
risk levels. Each entry below shows:

- **Schema** — required/optional parameters and their types.
- **Risk** — the code's classification (`risk.Classify`).
  Anything ≥ `high` prompts for confirmation unless you run `--yolo`.
- **Prompt that works** — a natural-language input verified against a
  live Flipper; links to the transcript.
- **Notes** — gotchas, firmware gating, or side effects worth knowing.

Canonical definitions: the tool registry lives in `internal/tools/` — each
`Spec` is registered via `Register`, and `internal/tools/spec.go` exposes the
`All()` / `Get()` accessors the CLI, web, and MCP surfaces share.

---

## Device & session (info)

### `device_info` · low
No parameters. Returns firmware, hardware, radio, region, UID. (Also
reachable by its legacy alias `system_info`.)

**Prompt:** *"What's my Flipper's firmware version and hardware
revision?"* — [transcript smoke-test](../transcripts/01-storage-list.log)
and the initial `pzrunner` sanity check.

### `power_info` · low
No parameters. Returns battery charge, voltage, current, temperature.

**Prompt:** *"What's the battery level and is it charging?"* →
fires `power_info`, responds *"Battery: 100% — fully charged,
not currently drawing charge current. Health 100%, 27°C, 4.165V."*
([transcript 29](../transcripts/29-power.json))

### `bt_hci_info` · low
No parameters. Local Bluetooth chip metadata; no BLE stack brought up.

**Prompt:** *"Tell me my Flipper's Bluetooth controller info — chip,
firmware, MAC"* → fires `bt_hci_info`. MAC is not exposed by stock
firmware — expect the model to flag this and fall back to HCI version.
([transcript 35](../transcripts/35-bt-info.json))

### `device_reboot` · high
No parameters. **Disconnects serial while the Flipper reboots** — plan
for the `/reconnect` slash command in the REPL.

### `power_reboot_dfu` · critical
No parameters. Leaves the Flipper in STM32 DFU mode with **no running
firmware**. Only call when you're about to reflash.

### `update_install` · critical
`manifest` (string, required). Reflashes the firmware. Wrong manifest
= brick. Normally you stage an update with qFlipper, then point this
at `/ext/update/<…>/update.fuf`.

### `crypto_store_key` · critical
`slot` (int), `key_type` (master|simple|encrypted), `key_size` (128|256),
`hex` (required). Overwrites the target slot permanently.

### `flipper_raw_cli` · high
`command` (string, required). Escape hatch to the Flipper CLI.

**When to prompt for this:** *"Run the Flipper CLI command
`info power` verbatim"* — the model reaches for `flipper_raw_cli`
only when you explicitly ask for the raw command, otherwise it
prefers a dedicated tool.

**Example invocation:**
```json
{
  "command": "device_info"
}
```
This sends `device_info` directly to the Flipper CLI and returns the raw
output. Classified `high` because the `command` string is passed through
without type-safety checks or risk classification — any valid (or invalid)
CLI command can be issued, bypassing the structured tool layer entirely.

### `log_stream` · low
`duration_seconds` (int, default 15). Tails the firmware debug log.

### `loader_info` · low
No parameters. Name of the currently running app — useful to confirm a
`loader_open` actually landed before you send `input_send` events.

### `loader_signal` · medium
`signal` (int, required). App-specific opcode delivered to the running
FAP.

---

## Storage (SD card)

All storage paths are Flipper-side (`/ext/…`, `/int/…`). Read-only tools
are safe to fire on any prompt; write/delete paths should stay under
a scratch prefix (`/ext/pztest…`) unless you mean it.

### `storage_list` · low
`path` (string, required).
**Prompt:** *"List the files at /ext on my Flipper and tell me what's
there"* → fires `storage_list /ext`.
([transcript 01](../transcripts/01-storage-list.json))

### `storage_tree` · low
`path` (string, required). Recursive walk.
**Prompt:** *"Show me everything under /ext/subghz — files and folders,
recursively"* ([transcript 03](../transcripts/03-storage-tree.json))

### `storage_read` · low
`path` (string, required).

### `storage_info` · low
`path` (string, required). Size/type only, no contents.

### `storage_md5` · low
`path` (string, required).
**Prompt:** *"Compute the MD5 of /ext/subghz/Tesla/Tesla_EU_AM270.sub"* →
fires `storage_md5` and returns the 32-char hex.
([transcript 34](../transcripts/34-storage-md5.json))

### `storage_mkdir` · low
`path` (string, required).

### `storage_copy` · low
`src`, `dst` (strings). Overwrites destination.

### `storage_rename` · medium
`src`, `dst` (strings). Move/rename.

### `storage_delete` · high
`path` (string, required). Irreversible.

The agent will self-cleanup scratch files in the same turn when
you ask it to: *"Delete the test file /ext/badusb/hello_pztest.txt
I created earlier"* → fires a single `storage_delete`.

### `discover_apps` · low
No parameters. Categorised inventory of the whole SD card.
**Prompt:** *"Do a full discover of what's on my SD card — apps, saved
signals, everything. Give me a categorized inventory."*
([transcript 21](../transcripts/21-discover.json))

### `list_apps` · low
No parameters. Built-in apps + installed FAPs + settings menu.
**Prompt:** *"What apps are installed on my Flipper?"*
([transcript 02](../transcripts/02-list-apps.json))

### `list_devices` · low
No parameters. Reads the `devices:` map from your config.
**Prompt:** *"List my configured devices — the named ones I've
mapped to signal files"*
([transcript 20](../transcripts/20-list-devices.json))

---

## Sub-GHz

### `subghz_receive` · medium (receive-only)
`frequency` (Hz, required), `duration_seconds` (default 30).
**Prompt:** *"Do a quick receive on 433.92MHz for 5 seconds and tell
me if anything's in the air"*
([transcript 06](../transcripts/06-subghz-rx.json))

### `subghz_rx_raw` · medium (Momentum/Xtreme/Rogue only)
Same frequency/duration args. Returns **raw pulse data** rather than
decoded frames — use when you want to eyeball an unknown protocol.

**Prompt:** *"Record raw Sub-GHz pulses on 433.92MHz for 3 seconds
and dump the raw data (don't save to SD)"*
([transcript 24](../transcripts/24-subghz-rx-raw.json))

### `subghz_decode` · low
`file` (string, required). Parses a saved `.sub`.
**Prompt:** *"Decode /ext/subghz/Tesla/Tesla_US_AM650.sub — show me the
protocol, frequency and whatever key data you can extract"*
([transcript 30](../transcripts/30-subghz-decode.json))

### `subghz_transmit` · **critical** (active RF)
`file` (string, required).
**Prompt that works:** *"Transmit /ext/subghz/garage.sub"* — the agent
will ask you to confirm before firing. Only run with authorisation for
the target device.

### `subghz_bruteforce` · **critical**
`file`, `frequency`, `duration_seconds`. Replays variations. Huge
RF footprint — effectively always illegal outside a lab.

### `subghz_tx_key` · **critical**
Raw bytes on a frequency. `key_hex`, `frequency`, `te`, `repeat`. Used
for protocol experimentation / replay; you supply the timing.

### `subghz_chat` · **critical**
`frequency` (req), `duration_seconds`. Opens an interactive Sub-GHz
text chat that transmits on every keystroke.

---

## Infrared

### `ir_receive` · low
`timeout_seconds` (default 30). Passive.
**Prompt:** *"Try to learn an IR signal — I'll press a remote at the
Flipper. Give it 8 seconds."*
([transcript 31](../transcripts/31-ir-receive.json))

### `ir_transmit` · high (active IR emission)
`protocol` (NEC, Samsung32, RC6, SIRC, …), `address`, `command`.

### `ir_transmit_raw` · high
`data` (required), `frequency` (default 38000), `duty_cycle` (default 0.33).

### `ir_bruteforce` · **critical**
`file` (required), `duration_seconds`. Cycles through a universal
library looking for a match.

### `ir_decode_file` · low
`path` to an `.ir` file. Returns the parsed protocol/address/command
per button.

### `ir_universal_list` · low
`library` (`tv`, `ac`, `audio`, `projector`).

---

## NFC / 13.56 MHz

### `nfc_detect` · low
`timeout_seconds` (default 30). Early-returns on detection.
**Prompt:** *"Try to detect an NFC tag for 8 seconds"*
([transcript 09](../transcripts/09-nfc-detect.json))

### `nfc_emulate` · **critical** (active emission)
`file` (string). The Flipper acts as the tag.

### `nfc_subcommand` · high
`subcommand` (scanner|emulate|dump|field|raw|apdu|mfu). Low-level
hatch into the NFC CLI subshell.

### `nfc_raw_frame` · high
`hex` (ISO14443 frame). Fork-gated; not on Xtreme.

### `nfc_apdu` · high
`hex` (APDU). Use for EMV / DESFire / applet-hosting cards.

### `nfc_mfu_rdbl` · medium
`page` (int). Reads 4 bytes from Ultralight/NTAG.

### `nfc_mfu_wrbl` · **critical**
`page`, `hex` (4 bytes). Destructive; some pages are OTP.

### `nfc_dump_protocol` · high
`protocol` (`Mifare_Classic`, `Mifare_Ultralight`, …). Full dump.

---

## RFID (125 kHz LF)

### `rfid_read` · low
`mode` (optional — leave empty for auto-detect), `timeout_seconds` (15).
Hardware: fob flat against the **back** of the Flipper.

**Prompt:** *"Try to read a 125kHz RFID fob — I'm holding one against
the back of the Flipper. Give it 8 seconds max."*
([transcript 08](../transcripts/08-rfid-read.json))

### `rfid_emulate` · high
`protocol`, `data` (hex).

### `rfid_write` · **critical**
`protocol`, `data`. Writes to a T5577 blank (or similar).

### `rfid_raw_read` · medium
`file` (dest), `mode`, `duration_seconds`. Unprocessed bitstream.

### `rfid_raw_analyze` · low
`file`.

### `rfid_raw_emulate` · **critical**
`file`, `duration_seconds`.

---

## iButton / 1-Wire

### `ibutton_read` · low
`timeout_seconds` (default 30).

### `onewire_search` · low
`duration_seconds` (default 10). Lower-level than `ibutton_read`;
returns every ROM code on the 1-Wire bus.

**Prompt:** *"Look for any 1-Wire devices on the iButton pad"* (and
*"Scan for iButton keys for 8 seconds"* also routes here — the model
treats 1-wire as the more general tool).
([transcript 10](../transcripts/10-ibutton-read.json),
[transcript 12](../transcripts/12-onewire.json))

### `ibutton_emulate` · high
`protocol` (Dallas|Cyfral|Metakom), `hex_data`.

### `ibutton_write` · **critical**
`hex_data`. Dallas only.

---

## GPIO / hardware

### `gpio_set` · medium
`pin` (PA7/PA6/PA4/PB3/PB2/PC3/PC1/PC0), `value` (0|1).

### `gpio_read` · low
`pin`.

### `i2c_scan` · low
No parameters. Sweeps addresses; optionally launches the I2C Scanner FAP.
**Prompt:** *"Scan the I2C bus for devices connected to the Flipper's
GPIO header"*
([transcript 11](../transcripts/11-i2c-scan.json))

---

## BadUSB

### `badusb_run` · **critical**
`file`. Types arbitrary keystrokes into the host computer.

### `badusb_validate` · low
`file`. Lints a DuckyScript for dangerous patterns (`rm -rf /`, reverse
shells, persistence, defense-disable). Returns severity + line numbers.

**Prompt (safe):** *"Validate the BadUSB payload at
/ext/badusb/hello_pztest.txt — is it safe to run?"* →
`severity: info`. ([transcript 18](../transcripts/18-badusb-validate.json))

**Prompt (malicious sample):** *"Deploy a BadUSB payload to
/ext/badusb/pztest_dangerous.txt that does 'rm -rf /' on Linux, then
validate it WITHOUT running it to check what the validator flags"* →
deploys, then validates with `severity: critical`, rule `rm_rf_root`.
([transcript 32](../transcripts/32-badusb-validate-bad.json))

---

## Input / UI

### `loader_open` · medium
`app_name` (NFC|SubGHz|Infrared|iButton|Bad USB|GPIO|…), `args` (opt).
**Prompt:** *"Open the NFC app on my Flipper, tell me what app is
running, then close it"* → chains `loader_open` → `loader_info` →
`loader_close`. ([transcript 25](../transcripts/25-loader-flow.json))

### `loader_close` · low
No parameters.

### `input_send` · medium
`button` (up|down|left|right|ok|back), `event_type` (press|release|
short|long|repeat).

### `led_set` · low
`channel` (r|g|b|bl), `value` (0–255).
**Prompt:** *"Blink my Flipper's LEDs red, green, blue, then turn them
all off"* → six sequential `led_set` calls.
([transcript 04](../transcripts/04-led-blink.json))

### `vibro` · low
`on` (bool). Toggle the buzzer.
**Prompt:** *"Vibrate the Flipper briefly"* → `vibro(true)` → `vibro(false)`.
([transcript 07](../transcripts/07-vibro.json))

---

## FAP launchers (require the FAP installed on SD)

These all take no parameters and simply launch the FAP. The agent
checks `list_apps` first when uncertain.

| Tool | FAP | Risk |
|---|---|---|
| `loader_nfc_magic` | NFC Magic (UID writer) | high |
| `loader_mfkey` | MFKey32 (MIFARE Classic key recovery) | medium |
| `loader_mifare_nested` | Mifare Nested | medium |
| `loader_picopass` | PicoPass / HID iClass | medium |
| `loader_seader` | SEADER (iClass SE) | high |
| `loader_t5577_multiwriter` | T5577 batch writer | high |
| `loader_subghz_bruteforcer` | Sub-GHz Bruteforcer | critical |
| `loader_subghz_playlist` | Sub-GHz Playlist | critical |
| `loader_protoview` | ProtoView (RX only) | low |
| `loader_spectrum_analyzer` | Spectrum Analyzer (RX only) | low |
| `loader_signal_generator` | GPIO square-wave gen | low |
| `loader_nrf24mousejacker` | NRF24 Mousejacker | critical |
| `loader_uart_terminal` | UART Terminal | low |
| `loader_spi_mem_manager` | SPI Mem Manager | medium |
| `loader_unitemp` | Temperature/humidity sensors | low |

---

## Scripting

### `js_run` · **critical**
`path` (.js), `duration_seconds` (default 60). Arbitrary JS on the
Momentum/Xtreme/Rogue JS runtime.

---

## File-format (structural read/edit/diff)

Parse Flipper capture files into structured JSON rather than raw text.

### `fileformat_read` · low
`path`. Returns the parsed fields.
**Prompt:** *"Decode the Tesla_EU_AM270.sub file on my Flipper — what
protocol, frequency and key does it use?"* → `fileformat_read` (and
`subghz_decode` for the protocol-specific detail).
([transcript 05](../transcripts/05-fileformat-read.json))

### `fileformat_edit` · medium
`path`, `edits` (object), `output_path` (opt). Allowed edit keys per
format documented in the tool description.

> ⚠️ **Known issue** ([transcript 27](../transcripts/27-fileformat-edit.json))
> `fileformat_edit` corrupts multi-`RAW_Data` `.sub` files — it emits
> only one RAW_Data line. Use `storage_copy` + manual edit via
> `storage_read`/`storage_delete` when editing RAW captures.

### `fileformat_diff` · low
`path_a`, `path_b`.
**Prompt:** *"Diff the two Tesla EU sub files in /ext/subghz/Tesla —
what's different between AM270 and AM650?"* → fires `storage_list`
then `fileformat_diff`; reports the single preset difference.
([transcript 19](../transcripts/19-fileformat-diff.json))

---

## Generation pipeline (LLM-backed)

Every `generate_*` tool takes a natural-language `description`, plus
`deploy` (bool, default **true** — pass `false` to preview only) and
`path` (custom SD destination).

### `generate_badusb` · high (critical with `deploy=true`)
`description` (req), `target_os` (windows|macos|linux), `deploy`, `path`.
**Prompt:** *"Generate a BadUSB payload for Windows that pops a Hello
World notepad window — generate only, do NOT deploy"*
([transcript 13](../transcripts/13-gen-badusb.json))

### `generate_evil_portal` · high
`description` (req), `deploy`, `path` (default
`/ext/apps_data/evil_portal/index.html`).
**Prompt:** *"Generate an evil-portal HTML page that looks like a
corporate guest WiFi login — don't deploy"*
([transcript 23](../transcripts/23-gen-evil-portal.json))

### `generate_subghz` · high
`description` (req), `deploy`, `path`.

### `generate_ir` · low
`description` (req), `deploy`, `path`.
**Prompt:** *"Generate an IR remote file for a generic Samsung TV —
generate only, do NOT deploy"*
([transcript 14](../transcripts/14-gen-ir.json))

### `generate_nfc` · medium
`description` (req), `deploy`, `path`.

### `generate_deploy_run` · **critical**
`type` (evil_portal|badusb|subghz|ir|nfc), `description`, `target_os`
(badusb only), `path`. End-to-end — generates, writes to SD, executes.

### `run_payload` · **critical**
`path` (on SD), `command` (IR button name if applicable). Dispatches to
the right tool based on extension.

### `analyze_image` · low
`image` (base64 or file path), `question` (optional).

---

## Workflows (composite)

One LLM-callable wrapper around a chain of primitives. Prefer these
when the user's goal is a *task* rather than a single command.

### `workflow_hw_recon_blackbox_device` · low
`gpios` (opt override).
**Prompt:** *"Run the black-box hardware recon workflow on whatever's
hooked up to my GPIO header right now"* → single
`workflow_hw_recon_blackbox_device` call, aggregates i2c_scan /
onewire_search / GPIO sweep / bt_hci_info / device_info.
([transcript 15](../transcripts/15-workflow-hwrecon.json))

### `workflow_garage_door_triage` · medium (RX only)
`frequencies` (opt), `per_freq_seconds` (default 5).
**Prompt:** *"Do a garage-door triage sweep — listen on all the common
garage and car remote frequencies and tell me what you hear. Use 3
seconds per frequency."*
([transcript 16](../transcripts/16-workflow-garage.json))

### `workflow_nfc_badge_pipeline` · high
`attempt_dump` (default false), `timeout_seconds` (default 30).
**Prompt:** *"I'm holding an unknown NFC badge against the back of the
Flipper — run the badge-triage workflow on it with a 8 second timeout,
and do NOT dump yet."*
([transcript 26](../transcripts/26-workflow-nfc.json))

### `workflow_phys_pentest_badge_walk` · medium
`duration_seconds` (30–1800), `dedupe_window_seconds`, `csv_path`.

### `workflow_rolljam_lab_demo` · **critical**
`frequency` (req), `lab_consent=true` (req), `output_dir`,
`capture_window_seconds`. Refuses without `lab_consent=true`.

### `workflow_badusb_target_profile` · high (critical with `auto_run=true`)
`description` (req), `target_os` (req), `output_path`, `auto_run`.

### `workflow_wifi_target_to_hashcat` · **critical** (Marauder only)
`scan_seconds`, `capture_seconds`, `bssid`, `output_path`. Returns a
friendly error if the Marauder isn't connected.

---

## ESP32 Marauder (WiFi devboard — only when `--wifi` or `marauder.enabled`)

If the Marauder isn't attached, none of these tools are registered
and the agent won't mention them.

**Scanning:** `wifi_scan_ap`, `wifi_scan_all`, `wifi_stop_scan`,
`wifi_list_aps`, `wifi_list_stations`, `wifi_list_ssids`,
`wifi_clear_aps`, `wifi_clear_ssids`, `wifi_clear_stations`.

**Target selection:** `wifi_select_ap`, `wifi_select_station`,
`wifi_select_ssid` — all take `indices` as a comma string or `all`.

**Active attacks (high/critical):** `wifi_deauth`,
`wifi_deauth_station_list`, `wifi_beacon_spam`, `wifi_beacon_random`,
`wifi_beacon_clone`, `wifi_beacon_rickroll`, `wifi_beacon_funny`,
`wifi_probe_flood`, `wifi_csa_attack`, `wifi_sae_flood`,
`wifi_evil_portal_start`, `wifi_evil_portal_stop`, `wifi_ble_spam`.

**Passive capture:** `wifi_sniff_pmkid`, `wifi_sniff_beacon`,
`wifi_sniff_deauth`, `wifi_sniff_probe`, `wifi_sniff_pwnagotchi`,
`wifi_sniff_raw`, `wifi_sniff_bt`, `wifi_sniff_skimmer`.

**Network recon (requires joining a network):** `wifi_join`,
`wifi_ping_scan`, `wifi_arp_scan`, `wifi_port_scan`.

**MAC manipulation:** `wifi_random_mac`, `wifi_clone_mac`.

**SSID list:** `wifi_add_ssid`, `wifi_remove_ssid`,
`wifi_generate_ssids`, `wifi_save_ssids`, `wifi_load_ssids`,
`wifi_save_aps`, `wifi_load_aps`.

**Settings:** `wifi_settings`, `wifi_set_setting`, `wifi_set_channel`,
`wifi_info`, `wifi_reboot`.

---

## Audit

### `audit_query` · low
`limit` (default 20).
**Note:** audit logging attaches to the `~/.promptzero/audit.db`
session. When running under `pzrunner` (no audit log wired), the
agent reports "audit logging isn't enabled on this session" — run
via the `promptzero` REPL to see rows.
([transcript 22](../transcripts/22-audit-query.json))

### `audit_stats` · low
No parameters. Count + success-rate aggregation.

### `audit_export` · low
No parameters. Full JSON export of the session.
