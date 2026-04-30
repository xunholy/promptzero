# Transports

Every CLI command, web session, and MCP invocation talks to the Flipper through a pluggable transport. Select one with the `serial.transport_url` config field, or the `--transport` CLI flag (flag overrides config).

## Schemes

| Scheme | Example | When to use |
|---|---|---|
| `serial://` | `serial:///dev/ttyACM0?baud=230400` | Default. USB CDC-ACM. Fastest + most reliable. |
| `ble://`    | `ble://AA:BB:CC:DD:EE:FF` (Linux/Windows) <br> `ble://e127efc1-05ec-...` (macOS) | Wireless. No cable. Slower (~2–8 kB/s) but every tool works. |
| `mock://`   | `mock:///dev/pts/5` | Test harness pty slave. Used by `internal/flipper/mock`. |

> [!NOTE]
> **Marauder is serial-only.** `marauder.port` is always a `/dev/ttyUSB0`-style path — upstream Marauder firmware has no wireless control surface. Only the Flipper supports BLE.

## Serial (USB)

- **Connection**: USB CDC ACM (`/dev/ttyACM0` on Linux, `/dev/cu.usbmodem*` on macOS, `COM*` on Windows).
- **Baud rate**: irrelevant for CDC ACM virtual serial (set to 230400 by convention).
- **DTR**: asserted automatically.
- **Command terminator**: `\r` (CR, 0x0D).
- **Prompt**: `>: ` with ANSI escape stripping for subshells like `[nfc]>: `.
- **File writes**: use `storage write_chunk` (not interactive `storage write`).

## BLE (wireless)

The `ble://` URL accepts three forms — picked automatically by shape:

| Form | Example | Where it works |
|---|---|---|
| Hardware MAC       | `ble://80:E1:26:69:6E:55`                     | Linux, Windows |
| CoreBluetooth UUID | `ble://e127efc1-05ec-ce53-014e-b79fee9117fa`  | macOS only — UUID is per-Mac |
| Device LocalName   | `ble://Unholy`                                | Any platform; fallback when above are inconvenient |

To find the right identifier:

```bash
promptzero --ble-discover
```

Scans for ~8 s and prints visible peripherals with name, address, and RSSI. Suggests the strongest-signal Flipper as a copy-pasteable URL.

### Pairing

**Linux (BlueZ)** — the adapter needs to know the device before PromptZero can connect:

```bash
bluetoothctl scan on        # until you see your Flipper
bluetoothctl pair AA:BB:CC:DD:EE:FF
bluetoothctl trust AA:BB:CC:DD:EE:FF
```

**macOS** — pair once via **System Settings → Bluetooth** so CoreBluetooth caches the identifier UUID. Subsequent connects take the direct fast path (`retrievePeripherals(withIdentifiers:)`) — no scan, no MAC lookup.

> macOS hides hardware BLE MACs from apps for privacy. The address PromptZero uses is the per-Mac CoreBluetooth identifier UUID — stable on this Mac for the life of the pairing, but **different on every other Mac**. Re-run `--ble-discover` if you move the config to another machine.

**Windows** — pair via Settings → Bluetooth & devices. PromptZero uses the hardware MAC.

### Limitations

- **WSL cannot do BLE.** Windows doesn't pass Bluetooth through to the Linux guest. Use USB + `usbipd`, or run PromptZero natively on Windows.
- **Throughput is ~10× slower than USB.** A `log_stream` or long `subghz rx` capture is less responsive — but every wrapper works (the CLI protocol is identical over Flipper's serial GATT service).
- **Range** is Bluetooth Class 2 normal (~10 m in practice).

All registered tools work unchanged over BLE — capabilities detection, NFC subshell, loader close-via-back-button, everything. The transport is the only thing that changes.

### macOS build note

The upstream `tinygo.org/x/bluetooth` package needs CGO. The release pipeline builds darwin/amd64 + darwin/arm64 binaries on macOS runners with `CGO_ENABLED=1`, so the standard `install.sh` does the right thing.

Building from source on macOS:

```bash
CGO_ENABLED=1 GOOS=darwin go build ./cmd/promptzero
```

Cross-compiled darwin binaries from a Linux host ship a stub that returns a clear "rebuild on macOS with CGO" error when BLE is attempted.

## WSL2 USB passthrough

USB devices aren't passed through to WSL by default. Install [usbipd-win](https://github.com/dorssel/usbipd-win) on Windows, then from an admin PowerShell:

```powershell
usbipd list
usbipd bind --busid <BUSID>      # one-time
usbipd attach --wsl --busid <BUSID>
```

The Flipper then appears as `/dev/ttyACM0` inside WSL.

## Mock transport

`mock:///dev/pts/N` connects to a pseudo-terminal slave. Used by `internal/flipper/mock` for hermetic transport tests — not relevant to operators.
