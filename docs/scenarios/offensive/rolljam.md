# Rolljam (lab demo)

Rolljam captures two consecutive rolling-code presses from a remote
and suppresses the first from reaching the receiver; a later replay
of code 1 still works because the receiver hasn't seen it.

## The tool is lab-only and consent-gated

> *"Run the rolljam lab demo on 433.92 MHz, save captures to
> /ext/subghz/rolljam_demo, lab_consent=true"*

Fires `workflow_rolljam_lab_demo(frequency=433920000, lab_consent=true,
output_dir=…)`. Classified `critical`.

**The workflow refuses to run without `lab_consent=true`.** This is
a deliberate circuit-breaker — the prompt `lab_consent=true` must be
explicit in your input. The agent will not set it silently.

## What it does

- Waits for press #1, captures to `<output_dir>/press_1.sub`.
- Waits for press #2, captures to `<output_dir>/press_2.sub`.
- Returns both file paths.

**The workflow does NOT transmit.** Transmitting the captures is a
separate step; without a rolling-code-jamming RF stage (which
requires a second radio), the captures are just replay candidates.

## Running the replay

Two separate `subghz_transmit` calls against the two files. The
agent will confirmation-gate each — see
[`subghz-tx.md`](subghz-tx.md).

## When to use

- Authorised research into rolling-code receivers.
- Lab / RF-shielded enclosure.
- Security training demos.

## When NOT to use

Everything else. Rolljam against a real vehicle or garage is a
federal offence in most jurisdictions.
