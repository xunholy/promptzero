# PromptZero Companion FAP

On-device status renderer for the PromptZero agent. Shows what the
host is doing — current tool, target detail, risk level, and pending
confirmations — on the Flipper OLED while plugged in via USB.

The integration is **optional**. If this FAP is not installed,
PromptZero detects its absence at startup and runs unchanged. If it
is installed, the host writes a small JSON status file to SD on
every tool boundary; the FAP polls that file and updates the screen
~4 times per second.

## Build

Requires Docker on the host (the build runs the official
`ghcr.io/flipperdevices/ufbt:latest` image so you don't need a
local Flipper SDK).

```sh
task fap:companion:build
# → bin/fap/promptzero_companion.fap
```

If you don't have `task` installed, the equivalent direct command is:

```sh
docker run --rm \
  -v "$PWD/fap/companion:/src" -w /src \
  ghcr.io/flipperdevices/ufbt:latest build
# the .fap lands in fap/companion/dist/
```

## Install on the Flipper

Three options, pick one:

1. **qFlipper** — connect the Flipper, drag
   `bin/fap/promptzero_companion.fap` onto `SD card → apps → Tools`.

2. **PromptZero itself** — run the agent and ask it to deploy the
   build artefact:

   ```
   > use fap_build to compile fap/companion and deploy it to the Flipper
   ```

   The agent will invoke the `fap_build` tool with `deploy: true`
   which pushes the binary to `/ext/apps/promptzero_companion.fap`.

3. **Manual SD card** — pop the µSD out, copy the .fap into
   `apps/Tools/`, put it back. (Requires CFW that allows
   sideloaded apps.)

PromptZero's startup probe checks these locations in order:

```
/ext/apps/Tools/promptzero_companion.fap
/ext/apps/Misc/promptzero_companion.fap
/ext/apps/Main/promptzero_companion.fap
/ext/apps/promptzero_companion.fap
```

Any of them counts as "installed".

## Run

On the Flipper: **Apps → Tools → PromptZero Companion**. The screen
shows `PromptZero — no events yet` until the host pushes its first
status update.

Start PromptZero on the laptop:

```sh
promptzero
```

You should see one of these on the host:

```
✓ Companion FAP (at /ext/apps/Tools/promptzero_companion.fap)
```

(if installed and detected) or no companion line at all (if not
installed — silent fallback to NopSink).

Type a prompt. The Flipper screen updates as the agent runs:

| Host event | FAP screen |
|------------|------------|
| `Idle`     | `o PromptZero ready` / `waiting for the host` |
| `Busy`     | `> working` / `<tool>` / `<detail>` / `risk: <level>` |
| `Confirm`  | `! confirm` / `<tool>` / `risk: <level>` / `OK=yes  LEFT=no  BACK` |
| `Done` ok  | `v done` / `<tool>` |
| `Done` err | `x done` / `<tool>` |

### Answering confirm prompts from the device

When the host fires a high-risk confirm (e.g. before a Sub-GHz
transmit, a Wi-Fi deauth, or a destructive write) the FAP shows
the pending action and waits for one of:

- **OK** — approve. The FAP writes `{"id":…,"decision":"approve"}`
  to `response.json`; the host picks it up within ~250 ms and
  releases the agent.
- **LEFT** — deny. Same path with `"decision":"deny"`. The agent
  short-circuits and skips the tool call.
- **BACK** — exit the FAP without answering. The host's terminal
  prompt is still live; whoever (terminal Y/N or device button)
  answers first wins. If neither responds, the agent's idle
  timeout fires (default 5 min → deny).

The terminal and the FAP race for the answer; the host treats them
as equally authoritative. There is no way for both to "win" a
single confirm — the host's wait loop returns on the first
matching response.

Press `BACK` outside a confirm to leave the FAP. The host keeps
writing status updates regardless — when you re-open the app, the
latest state is on screen immediately.

## Configuration

Defaults work with no config. Optional settings under `companion:`
in `~/.promptzero/config.yaml`:

```yaml
companion:
  enabled: true                                                       # default: auto-detect
  status_path: /ext/apps_data/promptzero_companion/status.json        # default
  auto_idle_after: 1.5s                                                # reserved (currently unused)
```

Set `enabled: false` to skip the SD probe entirely (slightly faster
startup, useful in CI).

## Wire format

Two files, both small JSON. One per direction.

### Status (host → FAP)

`/ext/apps_data/promptzero_companion/status.json` — overwritten on
every event, terminated with a newline:

```json
{"v":1,"t":"confirm","label":"wifi_deauth","risk":"critical","id":"7a3f2c08","ts":1714060801}
```

Fields:

| Field    | Type   | Notes                                                                |
|----------|--------|----------------------------------------------------------------------|
| `v`      | int    | Wire version. Currently `1`.                                         |
| `t`      | string | One of `idle`, `busy`, `confirm`, `done`.                            |
| `label`  | string | Tool name (`subghz_tx`, `wifi_deauth`, …) or `agent` for "thinking". |
| `detail` | string | One-line summary of the most operator-relevant input field.          |
| `risk`   | string | `low` / `medium` / `high` / `critical`.                              |
| `ok`     | bool   | Only on `done`. Missing implies `true` (saves bytes for the path).   |
| `id`     | string | Set on `confirm`. The FAP echoes this in its response.               |
| `ts`     | int    | Unix seconds when the host emitted the event.                        |

### Response (FAP → host)

`/ext/apps_data/promptzero_companion/response.json` — written when
the operator presses OK or LEFT during a confirm:

```json
{"id":"7a3f2c08","decision":"approve"}
```

| Field      | Type   | Notes                                                          |
|------------|--------|----------------------------------------------------------------|
| `id`       | string | Must match the `id` from the corresponding `confirm` event.    |
| `decision` | string | `approve` or `deny`. Anything else is treated as `deny`.       |

The host polls this file at 250 ms cadence only while a confirm is
pending; the link is silent between prompts. The host dedups by
file content — pressing the same button twice is a no-op.

## Known limitations

- No hardware E-stop yet: the FAP can answer confirm prompts but
  cannot abort an in-flight tool call mid-execution. A long-press
  BACK during a Busy state simply leaves the FAP; the agent keeps
  going. Requires plumbing cancellation through the agent loop
  and individual tool implementations — many tools aren't
  cancellable today. Separate planning session.
- No real RPC channel: the wire transport is SD-card-file polling
  at ~250 ms. Adequate for status display; sub-optimal for
  high-frequency telemetry. The native path would be a real
  protobuf-RPC channel over the second USB CDC interface
  (roadmap `P2-22`). Multi-week architectural lift.

## Design notes

Decisions worth recording so the next person doesn't re-litigate
them when something looks "wrong":

- **UP toggles vibration AND sound together.** Single button
  controls both; there is no way to enable one without the other.
  Rationale: in field use the operator wants either "all
  notifications" or "silent mode" — a per-channel toggle is
  power-user ergonomics that cost a button slot we don't have.
  If you eventually need them split, the right move is to add a
  proper Settings page (UP-long-press) rather than burning DOWN
  on a second toggle.
- **Risk badge clips at 8 chars.** Fits `low`/`medium`/`high`/
  `critical` exactly. Any future risk level longer than that
  (e.g. `extreme-high`) gets silently truncated to keep the
  inverse-video block at a fixed 38 px width. Either keep risk
  level names ≤8 chars or widen `BADGE_W` and `BADGE_MAX_CH` in
  the FAP source.
- **Wire format `v` is hardcoded to 1.** When (not if) the host
  bumps to v=2, the FAP renders a "host newer — please update"
  warning and stops parsing. There is no v1↔v2 compatibility
  shim. Migration story: bump v *after* shipping a FAP build
  that knows both, or accept brief broken-screen windows during
  rolling host updates.
- **Web confirm race is unbounded.** The FAP can answer a confirm
  the browser hasn't seen yet (mid-tab-refresh). This is by
  design — the operator at the device is physically closer to
  the consequence and should always be able to deny. See the
  comment in `internal/web/server.go` around the confirm
  callback for the full rationale.
- **Status file is truncated every 50 writes.** Tunable via
  `FlipperSink.TruncateEvery` (host-side). Set to 0 to disable
  truncation entirely; the FAP's seek-to-tail handles arbitrary
  file size, but truncation keeps SD usage and read latency
  predictable.

See `docs/specs/roadmap.md` for the long-form plan.
