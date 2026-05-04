# Configuration reference

PromptZero reads configuration from (in order):

1. `--config <path>` CLI flag.
2. `PROMPTZERO_CONFIG` environment variable.
3. `~/.promptzero/config.yaml`.
4. `./config.yaml`.

A fully-commented template is in [`examples/config.yaml`](../../examples/config.yaml).

## Quick setup

```bash
cp examples/config.yaml ~/.promptzero/config.yaml
$EDITOR ~/.promptzero/config.yaml         # set api_key + serial.port
```

## Environment variables

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY`            | Claude API key for the main agent. Required unless `api_key` is set in config. |
| `OPENAI_API_KEY`               | OpenAI key for Whisper voice transcription. Optional. |
| `OPENROUTER_API_KEY`           | OpenRouter key when `--gen-provider openrouter` is in use. Optional. |
| `PROMPTZERO_CONFIG`            | Path to the config file; overrides default search. |
| `PROMPTZERO_WEB_TOKEN`         | Bearer token for the web UI; overrides `web.token`. |
| `PROMPTZERO_LOG_LEVEL`         | `debug` \| `info` \| `warn` \| `error`. Overrides `observability.log_level`. |
| `PROMPTZERO_SERIAL_DEBUG`      | Any non-empty value dumps Flipper serial I/O to stderr. |
| `PROMPTZERO_MCP_ALLOW_HIGH`    | Set to `1` to allow Risk-High tools through the MCP server. |
| `PROMPTZERO_MCP_ALLOW_CRITICAL`| Set to `1` to allow Risk-Critical tools through the MCP server. |
| `OTEL_EXPORTER_OTLP_ENDPOINT`  | Standard OTel env — when set, the agent emits GenAI spans. |

## Read-only safety rail

`--read-only` (or `read_only: true` in config) is the v0.19.0 safety gate. When engaged, dispatch refuses any tool whose `Spec.Risk` is above `risk.Low` — no writes, no transmits, no emulation, no payload generation. The LLM's catalog is also narrowed to only Low-risk tools so the model doesn't waste turns planning something it would only get refused at dispatch.

```bash
promptzero --read-only           # one-shot
```

```yaml
read_only: true                  # in config; persistent
```

The 78 currently-Low-risk tools cover audit queries, scans, file reads, decodes, and inventory. Anything that mutates state or transmits (Medium / High / Critical) is refused.

> **Migrating from `--mode`:** `--mode recon|intel|stealth` are deprecated and aliased to `--read-only` with a one-release deprecation window. `--mode standard|assault` are deprecated no-ops. v0.20.0 will remove the flag entirely.

## Personas

Personas are YAML files that set the agent's system prompt, default risk threshold, per-tier model routing, per-tier extended-thinking budget, and (new in v0.19.0) per-tier provider override. Four templates ship in `examples/personas/`:

| Persona | Use case | Risk threshold |
|---|---|---|
| [`red-team-day.yaml`](../../examples/personas/red-team-day.yaml)     | Authorised offensive engagement | High — full surface |
| [`blue-team-audit.yaml`](../../examples/personas/blue-team-audit.yaml) | Read-only forensic; **pair with `--read-only`** | Low — passive observation only |
| [`ctf-shelf.yaml`](../../examples/personas/ctf-shelf.yaml)            | CTF puzzle solving | Medium — file-format surgery, audit replay |
| [`hw-lab.yaml`](../../examples/personas/hw-lab.yaml)                  | Hardware bench | Medium — GPIO/I2C/OneWire/UART/SPI focus |

Load with `promptzero --persona <name>` or set `persona: <name>` in config. Switch at runtime with `/persona <name>`.

> **Per-persona tool allowlist (`tools:` field):** **deprecated in v0.19.0.** The tool-narrowing job moved to `--read-only` at the safety layer. User personas under `~/.promptzero/personas/*.yaml` that still set `tools:` keep working for one release; v0.20.0 will retire the field. Strip the `tools:` list and pair with `--read-only` for the equivalent intent.

### Per-tier provider override (v0.19.0+)

A persona can declare a fallback LLM provider for one or more tiers (`classify` / `generate` / `plan` / `exploit`). Useful when the main provider's policy refuses a legitimate offensive task — pin the affected tier to a local model:

```yaml
name: physical-pentest-with-fallback
system_prompt: |
  You are PromptZero in PHYSICAL-PENTEST mode for an authorised engagement…
provider:
  generate: ollama        # local payload synthesis
  exploit: claude         # higher-quality reasoning stays on Claude
```

## Reactive rules

Rules let an external trigger (filesystem, webhook, scheduled tick) fire a prompt against the agent. See [`examples/rules.yaml`](../../examples/rules.yaml) for three reactive recipes — critical alerts, Mifare auto-triage, risk-level log breadcrumbs.

## Multi-provider generation

The generation pipeline (BadUSB / evil portal / `.sub` / `.ir` / `.nfc`) can use a different LLM provider from the main agent. Useful for keeping payload synthesis local.

```bash
# Default: Claude generates
promptzero

# Local Ollama (no exfiltration)
promptzero --gen-provider ollama --ollama-model qwen2.5-coder:14b

# OpenRouter
promptzero --gen-provider openrouter
```

## Self-upgrade

```bash
promptzero version --check                    # what's installed; flag if outdated
promptzero upgrade                            # atomic self-replace to latest
promptzero upgrade --dry-run                  # show plan without touching disk
promptzero upgrade --version v0.17.0          # pin
```

**Guardrails:** refuses to downgrade, refuses to replace a dev build, verifies SHA-256 against the release's `checksums.txt`, runs the candidate with `--version` before swapping, atomic rename so a failed download never leaves a half-written install. Pass `--force` to bypass.

Windows users: download the `.zip` from the [releases page](https://github.com/xunholy/promptzero/releases). Self-upgrade isn't supported on Windows — a running `.exe` can't be replaced atomically.
