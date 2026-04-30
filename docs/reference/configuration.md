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

## Personas

Personas are YAML files that scope the agent's tool surface, risk threshold, and system prompt. Four templates ship in `examples/personas/`:

| Persona | Use case | Risk threshold |
|---|---|---|
| [`red-team-day.yaml`](../../examples/personas/red-team-day.yaml)     | Authorised offensive engagement | High — full surface |
| [`blue-team-audit.yaml`](../../examples/personas/blue-team-audit.yaml) | Read-only forensic | Low — no transmit/emulate/write |
| [`ctf-shelf.yaml`](../../examples/personas/ctf-shelf.yaml)            | CTF puzzle solving | Medium — file-format surgery, audit replay |
| [`hw-lab.yaml`](../../examples/personas/hw-lab.yaml)                  | Hardware bench | Medium — GPIO/I2C/OneWire/UART/SPI only |

Load with `promptzero --persona <path>` or set `persona: <path>` in config. Switch at runtime with `/persona <name>`.

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
