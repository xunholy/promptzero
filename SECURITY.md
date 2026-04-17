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
- MCP mode executing all tools without confirmation. MCP has no shell to
  prompt on — a startup banner warns explicitly.
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

## Authorised-use reminder

This tool is intended for:

- Penetration testers operating under written scope.
- Security researchers on equipment they own or have explicit authorisation
  to test.
- Hardware enthusiasts exploring their own devices.

Unauthorised use against systems, networks, or radio equipment you do not
own or have written permission to test is illegal in most jurisdictions,
and the maintainers assume no liability. The MIT license disclaims warranty
and liability in full (see `LICENSE`); this document does not supersede it.

If you are unsure whether your intended use is authorised, **it probably
isn't** — consult your legal counsel or the target system's owner before
proceeding.
