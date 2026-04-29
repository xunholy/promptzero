# Marauder CLI fixtures

These fixtures back the parser unit tests in `internal/marauder/parsers/`.

The format of each fixture is the **body lines as they appear on serial after
the Marauder client (`internal/marauder.Marauder`) has stripped the `#<cmd>`
echo line and the trailing `> ` prompt** — i.e. the same shape a parser sees
when reading from `Marauder.Stream`'s line channel or when iterating
`strings.Split(Exec(...), "\n")`.

## Source of truth

Upstream Marauder firmware:

- Repo: <https://github.com/justcallmekoko/ESP32Marauder>
- Commit: `a1c14c2580a43ea73fb01dd8a40867071ff5b509`
- Wiki: <https://github.com/justcallmekoko/ESP32Marauder/wiki>

When wire format and wiki disagree, **the source wins** (this is what the
firmware actually emits over USB CDC). The wiki examples are a useful sanity
check for command names but lag the firmware on output formatting.

## Fixture index

Each fixture is one captured / synthesised CLI session for the named command.
Lines were derived from these source locations:

| File | Command | Source path / line                                  |
|---|---|---|
| `scanap.txt`        | `scanap`              | `WiFiScan.cpp` apSnifferCallbackFull (lines ~5697–5743) |
| `scanall.txt`       | `scanall`             | Same callback in `WIFI_SCAN_AP_STA` mode |
| `sniffbeacon.txt`   | `sniffbeacon`         | Maps to `WIFI_SCAN_AP` (`CommandLine.cpp:660`) → same callback as `scanap` |
| `sniffprobe.txt`    | `sniffprobe`          | `WiFiScan.cpp` ~line 7287, `WIFI_SCAN_PROBE` branch |
| `sniffdeauth.txt`   | `sniffdeauth`         | `WiFiScan.cpp:7625` `WIFI_SCAN_DEAUTH` branch |
| `sniffraw.txt`      | `sniffraw`            | `WiFiScan.cpp:9451` `renderRawStats` |
| `packetcount.txt`   | `packetcount`         | `WiFiScan.cpp:9510` `renderPacketRate` |
| `gpsdata.txt`       | `gpsdata`             | `WiFiScan.cpp:3658` GPS data emit + `CommandLine.cpp:329` start banner |
| `ls.txt`            | `ls /`                | `SDInterface.cpp:136` `listDir` |
| `blescan.txt`       | `sniffbt -t all`      | `WiFiScan.cpp:469` `BT_SCAN_ALL` branch (spec calls this "blescan -t all") |
| `blewardrive.txt`   | `wardrive`            | `WiFiScan.cpp:511` BLE `WIFI_SCAN_WAR_DRIVE` (spec calls this "blewardrive") |
| `attack_deauth.txt` | `attack -t deauth`    | `WiFiScan.cpp:9963` `displayTransmitRate` + `lang_var.h:39` `text18` |
| `evilportal.txt`    | `evilportal -c start` | `EvilPortal.cpp` lines 24, 309, 320, 328, 71 |

## Spec deviations recorded here (upstream is authoritative)

- The spec's WiFi → "Scan Stations" → `scansta` no longer exists upstream
  (commented out in `CommandLine.h:69`). `scanall` is the sanctioned
  replacement; we keep `scansta.txt` synthesised against the *historical*
  wire format so the parser stays useful for older boards, and add
  `scanall.txt` for current firmware.
- BLE scan is called `blescan` in the spec but the actual command on current
  firmware is `sniffbt [-t <airtag/flipper/flock/meta/all>]`. Default (no
  `-t`) takes the `BT_SCAN_ALL` path. The fixture file is named `blescan.txt`
  to keep the registry naming the spec uses; the parser is `ParseBLESniff`.
- BLE wardrive is `blewardrive` in the spec but upstream just has `wardrive`
  (which switches between WiFi and BLE wardrive based on the active scan
  mode). Fixture is named `blewardrive.txt` for spec consistency.
- The spec lists Packet Monitor as `packetcount` polled at 1 Hz emitting
  `{tsMs, beacon, probe, deauth, eapol, raw}`. Upstream `packetcount` only
  emits per-AP/per-station packet counts (`<essid>: <n>`); the *aggregate*
  counts that match the spec's shape come from `sniffraw`'s
  `renderRawStats()` block. Both fixtures are captured. The runtime can
  pick whichever shape it needs.

## Adding fixtures

When adding a fixture for a new command:

1. Record the upstream source path + line range in this README.
2. Either capture from a real device (preferred) or hand-synthesise from the
   `Serial.print*` calls in the source — match `\n` line endings exactly.
3. Strip the `#<cmd>` echo and trailing `> ` prompt; the Marauder client
   handles those.
4. Include at least one row that exercises an edge case (hidden SSID, empty
   field, unexpected whitespace) so parser tolerance gets tested.
