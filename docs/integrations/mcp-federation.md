# Outbound MCP federation

PromptZero (v0.6) can act as a **client** to other MCP servers, registering
their tools as native Specs. This unlocks third-party capabilities without
re-implementing each one in Go.

The package is `internal/mcpfed`. The boot path is wired in
`cmd/promptzero/setup.go:setupMCPFederation`. Configuration lives in the
operator's `config.yaml` under `mcp_clients:`.

## Quick example

```yaml
# ~/.promptzero/config.yaml
api_key: ${ANTHROPIC_API_KEY}
model: claude-sonnet-4-6

mcp_clients:
  # FuzzingLabs security hub: nmap, nuclei, sqlmap, ghidra, hashcat
  - prefix: secsec
    transport: stdio
    command: docker
    args: [run, --rm, -i, --network=host, ghcr.io/fuzzinglabs/security-hub:latest]
    sandbox: docker
    risk_default: high
    env:
      SHODAN_API_KEY: $SHODAN_API_KEY

  # Proxmark3 iceman federation
  - prefix: pm3
    transport: stdio
    command: pm3-mcp
    sandbox: none
    risk_default: high

  # MorDavid/BloodHound-MCP-AI for AD attack-path queries
  - prefix: bh
    transport: http
    url: http://localhost:7474/mcp
    headers:
      Authorization: Bearer $BLOODHOUND_TOKEN
    risk_default: medium
```

## Tool naming

Federated tools become `<prefix>__<remoteName>` in the agent's catalogue.
For example, the security-hub's `nmap_scan` shows up as `secsec__nmap_scan`.
The double underscore is a hard rule (Anthropic's tool-name regex is
`^[a-zA-Z0-9_-]{1,64}$`; the separator must not collide with names that
remote servers might emit).

## Risk classification

mcpfed reads each remote tool's MCP `annotations` and maps them to a
PromptZero `risk.Level`:

| Annotation                        | Mapped level |
| --------------------------------- | ------------ |
| `destructiveHint: true`           | Critical     |
| `readOnlyHint: true`              | Low          |
| `openWorldHint: true` (and other) | bumps default tier by 1 |
| no annotations                    | `risk_default` (or High) |

The risk level drives the same confirmation gate as native Specs — the
agent will pause for operator approval before invoking a Critical
federated tool, exactly like `flipper_raw_cli` or `subghz_bruteforce`.

## Sandbox profiles

Stdio transports support four profiles via the `sandbox:` field:

| Sandbox    | Effect                                                          |
| ---------- | --------------------------------------------------------------- |
| `none`     | bare `exec` — only for trusted, operator-vetted CLIs.           |
| `docker`   | `docker run --rm -i --network=none --read-only <image> [args…]` — image is the `command:` field, args become the container's process args. |
| `bwrap`    | `bwrap --ro-bind / / --tmpfs /tmp --unshare-all --share-net <cmd>`. |
| `firejail` | `firejail --net=none --private <cmd>` (WSL-friendly).            |

http and sse transports must use `sandbox: none` (no process is spawned
locally). The validation layer rejects anything else.

## Lifecycle

The federation is created during `setupMCPFederation` in the agent boot
sequence — after the agent itself is constructed, before the REPL hands
control to the model. Each `mcp_clients[]` entry spawns a long-lived
client (sub-process for stdio, persistent HTTP/SSE connection for the
network transports) that lives until process shutdown.

Failure on a single client is non-fatal: the federation collects errors,
logs them via `statusWarn`, and brings up whatever clients did succeed.
Operators see the resulting prefix list in the boot output:

```
[ok] MCP federation (3 servers: secsec, pm3, bh)
```

## Reconnect

mcp-go does not auto-reconnect. mcpfed wraps every tool call with one
transparent retry: on a transport-closed error, the client is closed,
re-spawned, re-Initialized, and the call retries once. A second failure
surfaces to the agent as a regular tool error.

Health pings (default cadence 30s, override via `health_interval:` in
the config) mark a client unhealthy when ping fails; the next call path
will redial via the retry loop.

## Auth pass-through

Stdio child processes inherit the env list from `env:` after `$VAR`
expansion against the parent process's environment:

```yaml
env:
  SHODAN_API_KEY: $SHODAN_API_KEY      # forwarded if set on the host
  HEADER_AUTH:    "Bearer xyz"          # literal value
  MISSING_OPT:    $UNDEFINED_VAR        # forwarded as empty string
```

HTTP/SSE clients use `headers:`:

```yaml
headers:
  Authorization: Bearer $BLOODHOUND_TOKEN
  X-Service-ID:  promptzero
```

## Audit log

Every federated tool invocation goes through the same audit log as
native ones (`internal/audit`). The `tool` field is the prefixed name
(`secsec__nmap_scan`); the `params` field is the raw `Arguments` map
passed to `CallTool`. Operators can grep / export by prefix to scope a
report to "everything secsec did last session".

## Recommended servers

The capability audit identifies these as the highest-leverage
integrations. Each is a maintained Go-callable MCP today:

| Server                               | Transport | Notes                                              |
| ------------------------------------ | --------- | -------------------------------------------------- |
| FuzzingLabs/mcp-security-hub (530★)   | stdio     | Aggregator: nmap, nuclei, sqlmap, ghidra, hashcat. |
| MorDavid/Hashcat-MCP                 | stdio     | Closes WiFi → cracker chain on captured PMKID.     |
| mplogas/pm3-mcp                      | stdio     | Proxmark3 iceman — Picopass, iCLASS, HID Prox.     |
| MorDavid/BloodHound-MCP-AI (335★)     | http      | AD attack-path queries via natural language.       |
| LaurieWired/GhidraMCP                | stdio     | Reverse-engineer dumped firmware blobs.            |
| PortSwigger/mcp-server               | stdio     | Official Burp Suite MCP for web-app traffic.       |
| GH05TCREW/MetasploitMCP              | stdio     | Post-exploitation primitives.                      |

Stable URLs: see `docs/refactor/v0.5-runbook.md` for the canonical citation list.
