# BadUSB (DuckyScript) scenarios

The Flipper enumerates as a USB HID keyboard and types whatever's
in a `.txt` script on the SD card. The host sees it as a normal
keyboard — there's no sandbox. Running a BadUSB payload is
equivalent to typing at someone's machine.

## Validate a payload before running

> *"Validate the BadUSB payload at /ext/badusb/hello_pztest.txt — is
> it safe to run?"*

Fires `badusb_validate`. Returns severity (`info` / `warn` /
`critical`) plus every matched rule with line numbers. Rules
catch: `rm -rf /`, reverse shells, persistence, defense-disable,
credential exfiltration, PowerShell download-cradle, etc.

Safe payload → `Severity: info (0)`.
[Transcript 18](../transcripts/18-badusb-validate.json)

Malicious payload →

> *"Deploy a BadUSB payload to /ext/badusb/pztest_dangerous.txt that
> does 'rm -rf /' on Linux, then validate it WITHOUT running it to
> check what the validator flags"*

`Severity: critical (2)`, rule `rm_rf_root`, line 6.
[Transcript 32](../transcripts/32-badusb-validate-bad.json)

## Generate a payload

Describe what you want, let the agent write the DuckyScript:

> *"Generate a BadUSB payload for Windows that pops a Hello World
> notepad window — generate only, do NOT deploy"*

Fires `generate_badusb(target_os=windows, deploy=false)`.
[Transcript 13](../transcripts/13-gen-badusb.json)

## Generate and deploy in one step

> *"Deploy this BadUSB payload for Windows to
> /ext/badusb/hello_pztest.txt: prints 'Hi from pzrunner' in Notepad.
> After deploy, DO NOT run it."*

Fires `generate_badusb(…, path=…, deploy=true)`. The "DO NOT run it"
clause is respected.
[Transcript 17](../transcripts/17-badusb-deploy.json)

## Generate, deploy, and execute (highest-risk path)

> *"Generate a BadUSB payload that plays a Rickroll on the target
> Windows machine and run it now"*

Fires `generate_deploy_run(type=badusb, target_os=windows, …)`.
Classified `critical`. The REPL will surface a confirmation prompt
for both the deploy and the execute steps unless you're in `--yolo`.

## Target-OS-aware generation (workflow)

> *"I'm going to plug the Flipper into a locked-down corporate
> Windows laptop with no UAC prompts available. Generate a BadUSB
> that opens the default browser to https://example.com — target
> profile it for that environment, don't auto-run."*

Fires `workflow_badusb_target_profile(description=…, target_os=windows,
auto_run=false)`. The workflow threads OS-specific constraints
(shell, UAC rules, PowerShell vs cmd) into the generation prompt.

## Run an existing payload

> *"Run /ext/badusb/payload.txt"*

Fires `badusb_run`. Classified `critical`. Validator runs implicitly
first on most firmwares — call `badusb_validate` yourself beforehand
if you want to preview.

## Clean up test payloads

> *"Delete the test file /ext/badusb/hello_pztest.txt I created
> earlier"*

Fires `storage_delete`. The agent happily cleans up scratch files
in one call when asked.
