# Security Policy

PromptZero is deliberately offensive tooling. It generates and deploys payloads
that, used outside authorised contexts, are illegal in most jurisdictions.
Please read this document before reporting an issue.

## Scope — What counts as a vulnerability

Vulnerabilities I want to hear about:

- **Loss of control of the Flipper device**: paths where the user's own device
  gets wedged, reboots unexpectedly, or has files overwritten without intent.
- **Command injection into the Flipper CLI** beyond the documented
  `flipper_raw_cli` escape hatch (e.g., an LLM-supplied string bypassing
  `sanitizeArg` and injecting a second CLI command).
- **Host-side privilege issues**: world-readable session files, audit DB,
  config files, or `~/.promptzero/` entries leaking secrets (API keys, tool
  inputs, device UIDs) to other local users.
- **MCP/web trust-boundary violations**: any path where an attacker on the
  local network (web mode) or an MCP client acquires capabilities that should
  have required confirmation.
- **Credential leakage**: API keys written to disk in plaintext outside the
  user's config file, or accidentally echoed to stdout/stderr/logs.
- **Supply-chain concerns**: malicious dependencies, compromised build
  artifacts, or CI exposure.

## Out of scope — Not vulnerabilities

These are features, not bugs:

- The risk confirmation gate not firing on Low/Medium-classified tools at
  the default threshold. This is the intended UX — use `--confirm-risk=low`
  or lower if you want everything gated.
- `flipper_raw_cli` accepting arbitrary strings. It's a deliberate escape
  hatch, Critical-classified, and prompts on every call.
- `generate_evil_portal` and `generate_badusb` producing phishing / HID
  payloads without extra confirmation. Generating is the primary workflow;
  deployment tools (`wifi_evil_portal_start`, `badusb_run`) are risk-gated.
- MCP mode running **Low/Medium**-risk tools without a confirmation
  prompt — MCP has no shell to prompt on. Note that **High/Critical**-risk
  tools are *refused by default* in MCP mode; operators opt in per tier
  via `PROMPTZERO_MCP_ALLOW_HIGH=1` / `PROMPTZERO_MCP_ALLOW_CRITICAL=1`,
  and every call is audited. A startup banner states this explicitly.
- The web UI not requiring authentication. It's local-first by default
  (`127.0.0.1`), and non-loopback binds print a warning.
- Bugs in AI-generated payloads (scripts, signal files, portal HTML).
  PromptZero does not validate the correctness of what the model produces —
  review before deploying.

## Reporting

**Do not open a public issue for any of the above.** Instead, reach out via:

- GitHub Security Advisories (preferred): use the "Report a vulnerability"
  button on the repo's Security tab.
- Email: open an issue asking for a contact and I will reach out.

Please include:

- A description of the issue and the impact.
- Minimal reproduction steps or a proof-of-concept.
- The commit SHA of the code you tested against.
- Whether you'd like credit in the fix notes.

I'll acknowledge within 72 hours and aim to ship a fix (or a documented
mitigation) within 14 days for critical issues, 30 days for others.

## Defensive postures (operator-facing safety rails)

PromptZero's safety model is defence-in-depth: a tool call passes through
several independent gates, and untrusted data crossing any boundary into the
model is sanitised or bounded. The rails compose; none relies on another.

### Risk gating

- **Risk classification with a safe default.** Every tool carries a
  `Spec.Risk` tier (`Low` / `Medium` / `High` / `Critical`); an
  *unknown* tool classifies as `High`, so a misconfiguration fails
  cautious rather than open. A regression test additionally guards that
  any tool whose name denotes an active high-blast-radius operation
  (transmit / emulate / deauth / jam / spam / flood / inject / replay /
  bruteforce) is `High` or above — it can never be auto-approved or slip
  past the gates below.
- **`--read-only` (or `read_only: true`)** — refuses any tool above
  `risk.Low` at dispatch. No writes, transmits, emulation, or payload
  generation. Introduced in v0.19.0; layers with the per-mode group
  allow-list in `--mode` (`standard` / `recon` / `intel` / `stealth` /
  `assault`): dispatch consults `--read-only` first, then the per-mode
  gate. `--mode recon|intel|stealth` engages `--read-only` automatically.
- **`--confirm-risk <level>`** — interactive confirmation before any tool
  at or above the given tier dispatches. Default `high`. The operator can
  approve, deny, approve-all, or revise; **approve-all is scoped** — it
  auto-approves same-or-lower-risk tools in the turn but re-prompts on an
  escalation to a higher tier, and `Critical` always re-prompts.

### Audit trail (accountability, fail-closed + tamper-evident)

- **Fail-closed audit gate.** When no audit log is wired, every action at
  `High` or above is *refused* (`RequireOpen`) — high-consequence
  operations cannot run unrecorded. Low-risk reads still proceed.
- **Tamper-evidence (v0.761).** Each audit row is hash-chained onto the
  previous (`SHA-256(prev ‖ row)`), so a post-hoc edit, mid-chain
  deletion, reorder, or forged insert made directly against the SQLite DB
  breaks the chain. `audit_verify` reports the break and the offending
  row. This is tamper-*evidence* against casual DB edits, not
  cryptographic non-repudiation.
- **Out-of-band anchor (v0.762).** `audit_verify` returns the chain head
  hash + row count; recording them externally and passing them back later
  also detects a full-chain rewrite or truncation of the newest rows —
  the two attacks the in-DB chain alone cannot catch.

### Prompt-injection quarantine (always on)

Tool output from hardware or other untrusted sources (scanned SSIDs,
NFC/NDEF records, BLE device names, SD-card file contents, and the results
of composite workflows that read them) is control-character sanitised and
wrapped in `<untrusted-hardware-output>` / `<untrusted-audit-content>` tags,
with a paired system-prompt clause telling the model to treat tagged
content as data, not instructions. A smuggled closing tag is neutralised so
the boundary can't be escaped. It is an allow-list (default-wrap /
fail-closed): a new tool is quarantined unless explicitly marked
structured-internal. The quarantine is a **shared primitive**
(`internal/quarantine`, v0.766) applied identically on the agent loop **and**
the MCP server surface, so a tool invoked by an external MCP host is
quarantined too.

### MCP server and federation (untrusted-edge hardening)

- **MCP consent gate.** Over MCP, tools at `High`/`Critical` are refused by
  default; the operator opts in per-tier via environment variables, and
  enabling `High` does **not** unlock `Critical`.
- **Federated servers are untrusted.** PromptZero can federate external
  MCP servers; their tool output is **size-bounded** before it reaches the
  model/audit log (a malicious/buggy remote can't flood the context,
  v0.767), and their self-declared annotations may **raise** a tool's risk
  but never lower it below the operator's configured floor — a server
  cannot mark a destructive tool "read-only" to bypass the gates (v0.768).

### Transport and outbound robustness

- **Bounded device reads.** Both the Flipper (serial/BLE) and the Marauder
  read loops cap accumulation (8 MiB), so a flooded RF environment or a
  malicious/malfunctioning board returns truncated output instead of
  exhausting memory (v0.769).
- **Webhook SSRF guard.** Event webhooks refuse private, loopback,
  link-local (incl. the cloud-metadata `169.254.169.254`), and CGNAT
  destinations unless explicitly allowed, and the webhook *response* is
  discarded, never read back into the agent.
- **Adversarial-input-hardened decoders.** The byte-ingesting decoders
  bound their allocations against the input length and are fuzzed, so a
  crafted artifact (captured frame, SD-card file, certificate, token)
  cannot trigger an unbounded allocation or a panic.

Defence-in-depth posture for blue-team / forensics / training:

```bash
promptzero --read-only --persona defender --confirm-risk low
```

## Authorised-use reminder

This tool is intended for:

- Penetration testers operating under written scope.
- Security researchers on equipment they own or have explicit authorisation
  to test.
- Hardware enthusiasts exploring their own devices.

Unauthorised use against systems, networks, or radio equipment you do not
own or have written permission to test is illegal in most jurisdictions,
and the maintainers assume no liability. The AGPL-3.0-or-later license
disclaims warranty and liability in full (see `LICENSE`); this document
does not supersede it.

If you are unsure whether your intended use is authorised, **it probably
isn't** — consult your legal counsel or the target system's owner before
proceeding.

## Licensing note

PromptZero is released under AGPL-3.0-or-later. If you run a modified version
of PromptZero as a service accessible over a network — for example as a hosted
or SaaS deployment — you must make the modified source code available to the
users of that service under the same licence. This obligation applies to
network-accessible deployments; local personal use on your own machine does not
trigger it. See the `LICENSE` file at the root of this repository for the full
licence text.
