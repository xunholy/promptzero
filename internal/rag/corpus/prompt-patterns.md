# Prompt patterns

Rules of thumb observed across 30+ live runs against a real Flipper.
Each pattern is tied back to a transcript so you can see the behaviour.

## 1. Ask for the *goal*, not the *tool*

The agent is much better at picking the right tool when you describe
what you want than when you spell out a tool name.

| Bad (narrow) | Better (goal) |
|---|---|
| *"Call `storage_list` on `/ext`"* | *"List the files at /ext on my Flipper and tell me what's there"* |
| *"Run `badusb_validate` on hello.txt"* | *"Validate the BadUSB payload at /ext/badusb/hello.txt — is it safe to run?"* |
| *"Run `workflow_garage_door_triage` with 3s per freq"* | *"Listen on the common garage / car remote frequencies for 3s each and tell me what you hear"* |

Evidence: [transcript 01](../transcripts/01-storage-list.json),
[transcript 18](../transcripts/18-badusb-validate.json),
[transcript 16](../transcripts/16-workflow-garage.json).

## 2. Put the hardware hint *in* the prompt

Scans time out quickly when nothing's there. Telling the agent what
you've physically done (fob positioned, remote pointed, board wired)
makes it both pick the right tool and shorten the timeout.

> *"Try to read a 125kHz RFID fob — I'm holding one against the back
> of the Flipper. Give it 8 seconds max."*
> → `rfid_read(timeout_seconds=8)`, returns within 15s.
> ([transcript 08](../transcripts/08-rfid-read.json))

If you don't mention positioning, expect a 30s default and a
"reposition…" recovery tip in the response.

## 3. "Don't deploy" / "don't run" / "don't transmit" is respected

The agent honours explicit negative constraints on `generate_*` and
workflow tools. Phrases that work:

- *"— don't deploy"* → sets `deploy: false`
- *"generate only, do NOT deploy"* → same
- *"After deploy, DO NOT run it"* → deploys, then skips `badusb_run`
- *"do NOT dump yet"* → `workflow_nfc_badge_pipeline(attempt_dump: false)`
- *"for receive only"* → avoids TX tools

Confirmed in
[transcript 13](../transcripts/13-gen-badusb.json),
[transcript 17](../transcripts/17-badusb-deploy.json),
[transcript 26](../transcripts/26-workflow-nfc.json).

## 4. Chain three verbs for a mini workflow

The agent will compose small chains when you list 2–3 actions:

> *"Open the NFC app on my Flipper, tell me what app is running,
> then close it"*
> → `loader_open(NFC)` → `loader_info` → `loader_close`
> ([transcript 25](../transcripts/25-loader-flow.json))

> *"Blink my Flipper's LEDs red, green, blue, then turn them all off"*
> → six `led_set` calls.
> ([transcript 04](../transcripts/04-led-blink.json))

Longer chains (4+ steps) are fine too, but `max-tools-per-turn`
defaults to 32 so very long chains will truncate.

## 5. Paths are matched loosely — the agent will correct itself

If you cite a wrong path, the agent checks the parent directory and
finds the right one. Example:

> *"Decode the Tesla_EU_AM270.sub file on my Flipper"*
> Agent tries `/ext/subghz/Tesla_EU_AM270.sub` (not present) →
> falls back to `storage_list /ext/subghz` → retries at
> `/ext/subghz/Tesla/Tesla_EU_AM270.sub`.
> ([transcript 05](../transcripts/05-fileformat-read.json))

Cost: +1–2 extra tool calls. Mitigation: always include the full path
you mean (`/ext/subghz/Tesla/…`).

## 6. When two tools fit, the agent picks the lower-level one

*"Scan for iButton keys for 8 seconds"* fires `onewire_search`, not
`ibutton_read`. Reasoning in the transcript:
`onewire_search` returns every ROM code on the 1-Wire bus, which
covers iButton as a subset. Both tools work on the same hardware pad.
([transcript 10](../transcripts/10-ibutton-read.json))

If you want protocol-decoded output (Dallas/Cyfral/Metakom), say
*"Read a Dallas iButton key for 8 seconds"* instead.

## 7. Scratch-file etiquette

When you ask the agent to produce test files, **say where** and
**say to clean up afterwards**. The agent will self-clean if asked:

> *"Copy X to /ext/pztest_edit.sub … diff …"*
> → ends the turn with `storage_delete /ext/pztest_edit.sub` on its
> own initiative once it's done reasoning about the diff.
> ([transcript 27](../transcripts/27-fileformat-edit.json))

Convention used throughout this repo: prefix ad-hoc test files with
`pztest_` or put them under `/ext/pztest/`.

## 8. Risk confirmation is on by default

In the interactive REPL, any `high` or `critical` tool pauses with a
`⚠ About to run …` prompt. The approval path differs by risk level:

**High risk:**
- `y` / `Y` → approve this one tool
- `n` / `N` / Enter / Esc → deny
- type `all` + Enter → approve all remaining *non-critical* tools in this turn

**Critical risk (destructive or irreversible):**
- type `confirm` + Enter → approve this one tool
- any other input (including `y`, `all`, or Enter alone) → deny

`all` does **not** auto-approve critical tools — each critical tool
always requires its own `confirm` + Enter.

In `pzrunner` (no UI), no callback is wired, so high/critical tools
execute immediately — only run `pzrunner` against prompts you
wouldn't be nervous to confirm manually. The scenarios under
`scenarios/offensive/` explicitly flag where this matters.

## 9. Firmware-fork notes

PromptZero is tested against **Momentum**. Some tools are gated on
fork capability:

- `nfc_raw_frame`, `nfc_apdu`, `nfc_mfu_*`, `nfc_dump_protocol` —
  require the `nfc` CLI subshell. Stock/Unleashed/RogueMaster have
  it; Xtreme returns a friendly error.
- `subghz_rx_raw` — Momentum only. Stock/Unleashed/Xtreme users
  should use `subghz_receive` plus `storage_read` instead.
- `js_run` — Xtreme, Momentum, RogueMaster only.
- `bt_hci_info` — returns chip metadata on all forks; MAC field
  only exposed on Momentum `info bt` (stock firmware returns 0).

## 10. Known issues (surfaced by real runs)

**`fileformat_edit` corrupts multi-`RAW_Data` `.sub` files.** When a
`.sub` has multiple `RAW_Data:` lines (any workflow_garage_door_triage
capture, any manual raw recording), `fileformat_edit` emits only the
first line and doesn't truncate the file — header bleed-through
results. Workaround: use `storage_copy` + hand-edit via
`storage_read` / `storage_write`, or use the Flipper UI.
([transcript 27](../transcripts/27-fileformat-edit.json))
