# Scenarios

Task-oriented walkthroughs. Each file answers "I want to do *X*, what
do I ask the agent?"

Organised by intent rather than by tool:

- [`inventory.md`](inventory.md) — see what's on the device and SD card.
- [`subghz.md`](subghz.md) — listening, decoding, transmitting.
- [`nfc-rfid.md`](nfc-rfid.md) — reading badges, triaging unknown tags.
- [`infrared.md`](infrared.md) — learning remotes, sending commands.
- [`badusb.md`](badusb.md) — generating, validating, running DuckyScript.
- [`hardware.md`](hardware.md) — GPIO, I²C, 1-Wire, black-box recon.
- [`files.md`](files.md) — storage management, capture file
  structural diffs.
- [`ui-control.md`](ui-control.md) — drive the Flipper UI (apps, LEDs,
  buzzer, keys).
- [`offensive/`](offensive/) — RF transmission, active attacks,
  physical pentest workflows. All high-risk; read
  [`offensive/README.md`](offensive/README.md) first.
- [`marauder.md`](marauder.md) — ESP32 Marauder WiFi/BLE flows
  (only available with `--wifi`).

For the underlying tool schemas, see
[`../reference/tools.md`](../reference/tools.md).

For how to phrase things reliably, see
[`../reference/prompt-patterns.md`](../reference/prompt-patterns.md).
