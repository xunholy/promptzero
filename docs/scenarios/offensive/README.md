# Offensive / active-emission scenarios

Everything here **actively transmits**, **emulates access credentials**,
or **types on a real keyboard**. Every tool in this section is
classified `high` or `critical` and is confirmation-gated by default.

Use only with written authorisation for the target device or
environment. Common legitimate contexts:

- Physical penetration tests (with a scope document)
- Your own hardware (home, car, garage)
- A sandboxed lab / RF shielded enclosure
- CTF competitions

If you're running with `--yolo` (risk gate off), you own the
outcome. The agent will still tell you when it's about to do
something destructive — read those responses.

## Contents

- [`subghz-tx.md`](subghz-tx.md) — replay, raw transmit, brute force,
  garage-door workflow transmit phase.
- [`ir-tx.md`](ir-tx.md) — active IR, device-vs-library transmits.
- [`nfc-emulate.md`](nfc-emulate.md) — tag emulation, writes, magic UID.
- [`rfid-clone.md`](rfid-clone.md) — prox card cloning onto T5577.
- [`badusb-execute.md`](badusb-execute.md) — running generated payloads
  on the host.
- [`physical-walk.md`](physical-walk.md) — RFID/NFC/iButton census
  during a site walk.
- [`rolljam.md`](rolljam.md) — lab-only rolljam capture (requires
  explicit consent flag).
- [`wifi-attacks.md`](wifi-attacks.md) — Marauder-gated WiFi/BLE.

## Risk-gate cheat sheet

| REPL flag | Behaviour |
|---|---|
| *(default)* | Anything `high`+ prompts for `y`/`n`/type `all` |
| `--confirm-risk=critical` | Only `critical` prompts (high runs silently) |
| `--confirm-risk=none` or `--yolo` | Everything runs without prompting |
| `--persona defender` | Reduced tool set; many offensive tools excluded |

In scripted mode (`pzrunner`) the callback isn't wired — tools
execute immediately.
