# BadUSB execute scenarios

For generation and validation see
[`../badusb.md`](../badusb.md). This page only covers **running**
payloads — the moment the Flipper starts typing on the host.

## Run an existing payload

> *"Run /ext/badusb/payload.txt"*

Fires `badusb_run(file=…)`. Classified `critical`. The host's
keyboard input gets driven at wire-speed until the script exits.

Validate first (lint without executing):

> *"Validate /ext/badusb/payload.txt and only run it if it comes
> back clean"*

Chain: `badusb_validate` → `badusb_run` (agent gates on the
validator severity).

## Generate-deploy-run in one shot (maximum convenience, maximum risk)

> *"Open Notepad on my test Windows VM, type 'pwnd' and save to
> Desktop. Generate, deploy, and run now."*

Fires `generate_deploy_run(type=badusb, target_os=windows, …)`.
Classified `critical`. Every step is confirmation-gated unless
`--yolo`.

## Target-profiled generation (then run)

> *"Generate a BadUSB for a Windows machine with PowerShell
> restricted, deploy to /ext/badusb/profile.txt, and run it."*

Fires `workflow_badusb_target_profile(target_os=windows,
description=…, auto_run=true)`. Workflow threads OS-specific
constraints into the generation prompt (no PowerShell, use `cmd`
instead, etc.).

## Safety / blast radius

- The Flipper is already enumerated as an HID keyboard from USB
  plug-in — the host trusts it as soon as the payload starts.
- There's no "abort in progress" channel mid-payload; the script
  runs to completion. Disconnect USB if you need to stop it.
- Post-payload, the host OS has keystrokes that may have launched
  other processes. Treat the host as compromised until you verify.
- `badusb_validate` catches the common dangerous rules but is a
  lint, not a sandbox. Novel / obfuscated payloads can still be
  destructive.
