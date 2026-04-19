# Transcripts

Each JSON file here is one prompt captured end-to-end against a
real Flipper Zero `"Unholy"` on Momentum `mntm-dev`, running
through `cmd/pzrunner`. These are the evidence base for every
example prompt in the scenario docs.

## Index

| # | File | What it demonstrates |
|---|---|---|
| 01 | [01-storage-list.json](01-storage-list.json) | `storage_list /ext` — SD inventory |
| 02 | [02-list-apps.json](02-list-apps.json) | `list_apps` — installed apps |
| 03 | [03-storage-tree.json](03-storage-tree.json) | `storage_tree /ext/subghz` — recursive walk |
| 04 | [04-led-blink.json](04-led-blink.json) | `led_set` ×6 — R→G→B→off |
| 05 | [05-fileformat-read.json](05-fileformat-read.json) | `fileformat_read` + path fallback to Tesla subdir |
| 06 | [06-subghz-rx.json](06-subghz-rx.json) | `subghz_receive` at 433.92MHz, 5s |
| 07 | [07-vibro.json](07-vibro.json) | `vibro` toggle |
| 08 | [08-rfid-read.json](08-rfid-read.json) | `rfid_read` (no fob) — positioning hint |
| 09 | [09-nfc-detect.json](09-nfc-detect.json) | `nfc_detect` (no tag) |
| 10 | [10-ibutton-read.json](10-ibutton-read.json) | `onewire_search` (picked over `ibutton_read`) |
| 11 | [11-i2c-scan.json](11-i2c-scan.json) | `i2c_scan` — wiring advice on no-result |
| 12 | [12-onewire.json](12-onewire.json) | `onewire_search` direct |
| 13 | [13-gen-badusb.json](13-gen-badusb.json) | `generate_badusb` Hello World (`deploy=false`) |
| 14 | [14-gen-ir.json](14-gen-ir.json) | `generate_ir` Samsung TV (`deploy=false`) |
| 15 | [15-workflow-hwrecon.json](15-workflow-hwrecon.json) | `workflow_hw_recon_blackbox_device` |
| 16 | [16-workflow-garage.json](16-workflow-garage.json) | `workflow_garage_door_triage` per_freq=3s |
| 17 | [17-badusb-deploy.json](17-badusb-deploy.json) | `generate_badusb` with `deploy=true` + "don't run" |
| 18 | [18-badusb-validate.json](18-badusb-validate.json) | `badusb_validate` on safe payload |
| 19 | [19-fileformat-diff.json](19-fileformat-diff.json) | `fileformat_diff` AM270 vs AM650 |
| 20 | [20-list-devices.json](20-list-devices.json) | `list_devices` (empty map) |
| 21 | [21-discover.json](21-discover.json) | `discover_apps` — full SD categorised |
| 22 | [22-audit-query.json](22-audit-query.json) | `audit_query` — audit-not-enabled path |
| 23 | [23-gen-evil-portal.json](23-gen-evil-portal.json) | `generate_evil_portal` corporate guest (`deploy=false`) |
| 24 | [24-subghz-rx-raw.json](24-subghz-rx-raw.json) | `subghz_rx_raw` Momentum-only pulse dump |
| 25 | [25-loader-flow.json](25-loader-flow.json) | `loader_open` → `loader_info` → `loader_close` |
| 26 | [26-workflow-nfc.json](26-workflow-nfc.json) | `workflow_nfc_badge_pipeline` no-dump |
| 27 | [27-fileformat-edit.json](27-fileformat-edit.json) | `fileformat_edit` — reveals RAW_Data bug |
| 28 | [28-cleanup-check.json](28-cleanup-check.json) | Scratch-file cleanup verification |
| 29 | [29-power.json](29-power.json) | `power_info` |
| 30 | [30-subghz-decode.json](30-subghz-decode.json) | `subghz_decode` Tesla US AM650 |
| 31 | [31-ir-receive.json](31-ir-receive.json) | `ir_receive` (no remote) |
| 32 | [32-badusb-validate-bad.json](32-badusb-validate-bad.json) | `badusb_validate` on `rm -rf /` payload |
| 33 | [33-cleanup-triage.json](33-cleanup-triage.json) | Bulk `storage_delete` by pattern |
| 34 | [34-storage-md5.json](34-storage-md5.json) | `storage_md5` |
| 35 | [35-bt-info.json](35-bt-info.json) | `bt_hci_info` |

## Reproducing

```bash
export ANTHROPIC_API_KEY=sk-ant-…
./bin/pzrunner --timeout 60 --quiet "<exact prompt from the file>" > /tmp/run.json 2>/tmp/run.log
jq '{prompt, tools: [.tools[] | select(.phase=="start") | {name, input}], response}' /tmp/run.json
```

Expect some variance in tool-call order, exact wording of replies,
and path-fallback behaviour — LLM non-determinism is real. The
tool *set* is stable; the **response shape** and the **high-level
sequence** are what the docs rely on.
