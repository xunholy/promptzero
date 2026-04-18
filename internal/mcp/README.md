# PromptZero MCP Server

`promptzero --mcp` launches a Model Context Protocol (MCP) server over stdio
that exposes the Flipper Zero (and optional ESP32 Marauder) tool surface to
any MCP client — Claude Desktop, Claude Code, a custom LLM agent, or the
standalone `mcptest` harness.

The server wraps every callable primitive in `internal/flipper`, the
composite pentest workflows in `internal/workflows`, the structural
`internal/fileformat` helpers, the Phase-5 `internal/validator` pre-flight,
and (when the `--wifi` flag is active) the Marauder command surface.

## Starting the server

```sh
# Over USB-serial to a local Flipper
promptzero --mcp

# With the Marauder devboard attached
promptzero --mcp --wifi

# Against a specific Flipper URL
promptzero --mcp --flipper serial:///dev/ttyACM0
```

The process holds stdin/stdout open for the MCP client and logs a single
banner to stderr reminding the operator that, unlike the REPL, every tool
call executes immediately — MCP has no shell to prompt on.

## Adding to Claude Desktop

Edit your `claude_desktop_config.json`:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

```jsonc
{
  "mcpServers": {
    "promptzero": {
      "command": "/usr/local/bin/promptzero",
      "args": ["--mcp"]
    }
  }
}
```

For a Marauder-equipped setup, add `"--wifi"` to `args`. Restart Claude
Desktop and the `promptzero` server appears in the MCP picker.

## Adding to Claude Code

Use the built-in MCP management:

```sh
claude mcp add promptzero /usr/local/bin/promptzero --mcp
```

The same tool list and persona prompts then surface in Claude Code's
`/mcp` menu.

## What the server advertises

Each tool carries MCP annotations derived from PromptZero's risk classifier
(`internal/risk`):

| Annotation        | Meaning                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `readOnlyHint`    | True for `risk.Low` tools (e.g. `device_info`, `storage_list`).        |
| `destructiveHint` | True for `risk.High` and `risk.Critical` (`subghz_transmit`, `js_run`). |
| `openWorldHint`   | True for anything beyond pure reads — the tool touches external state. |
| `title`           | `<tool_name> (<level>)` so the picker renders the risk at a glance.    |

Clients can gate destructive tools client-side (prompt the user, require a
typed confirmation) using these hints. The server itself does not prompt —
see the caveat below.

## Tool categories

- **Flipper primitives.** Sub-GHz, infrared, NFC, RFID, iButton, GPIO,
  BadUSB, loader/FAP shortcuts, storage, input, log streaming, JS runtime,
  `flipper_raw_cli`, etc.
- **File-format.** `fileformat_read` / `fileformat_edit` / `fileformat_diff`
  for structural reads and edits of `.sub`, `.nfc`, `.ir`, `.rfid`.
- **Pre-flight validators.** `badusb_validate` scans DuckyScript for
  destructive patterns without executing.
- **Workflows.** Pure-Flipper composites: `workflow_hw_recon_blackbox_device`,
  `workflow_garage_door_triage`, `workflow_phys_pentest_badge_walk`.
  LLM-driven workflows (`workflow_badusb_target_profile` etc.) are not
  surfaced in MCP mode — they require the full agent context.
- **Marauder tools** (only with `--wifi`). Scans, deauth, beacon spam,
  PMKID capture, evil portal, BLE spam, MAC manipulation, etc.

## Persona prompts

The six built-in personas (`default`, `rf-recon`, `badge-cloner`,
`hw-recon`, `physical-pentest`, `read-only`) are registered as MCP prompts
under the `persona_<name>` naming scheme. Selecting one in an MCP client
inserts the persona's system prompt as a user message, letting the
downstream model adopt the operator mode without PromptZero having to
stream the switch itself.

## Limitations and caveats

- **All tool calls auto-execute.** MCP servers do not have an interactive
  confirmation channel. Destructive tools execute as soon as the client
  issues `tools/call`. The risk annotations are the primary gating surface;
  clients that do not honour them should not be pointed at a live device.
- **BadUSB writes are not auto-approved in the REPL — they *are* here.**
  If you want the REPL's confirmation gate for BadUSB drops, drive the
  Flipper through the REPL (`promptzero`) instead of MCP.
- **Audit logging is disabled in MCP mode.** MCP doesn't carry the CLI's
  audit sink, so `audit_query` / `audit_export` / `audit_stats` are not
  advertised.
- **Generator + vision tools are not in MCP mode.** Tools that need the
  Anthropic SDK client (`generate_*`, `analyze_image`) require the agent
  context and are not registered here.
- **JS runtime is fork-gated.** `js_run` only works on Xtreme / Momentum /
  RogueMaster firmware. Stock / Unleashed / RogueMaster builds return a
  friendly-fork error.

## Testing

```sh
go test -race -count=1 ./internal/mcp/...
```

The integration test wires the server to an in-process `mcp-go` client via
`io.Pipe` and exercises `initialize` → `tools/list` → `tools/call` →
`prompts/list` → `prompts/get`, backed by the shared `internal/testmocks`
Flipper and Marauder fakes.
