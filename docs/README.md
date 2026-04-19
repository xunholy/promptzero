# PromptZero Docs

Hands-on guide to driving a **Flipper Zero (Momentum firmware)** — plus
an optional ESP32 Marauder — through natural-language prompts.

Every example in this folder was run against a real Flipper Zero `"Unholy"`
on Momentum `mntm-dev`. Raw transcripts live under `transcripts/` as JSON.

## Contents

- [`scenarios/`](scenarios/) — task-oriented walkthroughs. Start here if
  you know *what* you want (read a tag, decode a remote, generate a
  payload) but not *how* to ask.
- [`reference/tools.md`](reference/tools.md) — every registered tool with
  its schema, risk level, what hardware it touches, and which prompts
  reliably fire it.
- [`reference/prompt-patterns.md`](reference/prompt-patterns.md) — the
  rules of thumb that produced reliable tool-picking across the test runs.
- [`transcripts/`](transcripts/) — reproducible evidence. Each file is
  one prompt → tool calls → final response captured by `cmd/pzrunner`.

## Running the examples

```bash
export ANTHROPIC_API_KEY=sk-ant-…
task build                         # builds bin/promptzero
go build -o bin/pzrunner ./cmd/pzrunner   # non-interactive harness

# Interactive (REPL) — paste any prompt from the docs:
./bin/promptzero

# Scripted (one prompt → JSON transcript):
./bin/pzrunner "What apps are installed on my Flipper?"
```

The scripted harness (`cmd/pzrunner`) is the same agent the REPL uses —
it just swaps the terminal UI for JSON on stdout, so you can diff
expected vs. actual tool-call sequences in CI or in docs.

## Reading the transcripts

Each transcript in `transcripts/` is the full log of one prompt:

```json
{
  "prompt": "…",
  "response": "final assistant message",
  "tools": [ { "phase": "start|finish", "name": "…", "input": {…}, "output": "…" } ],
  "duration_s": 8.4,
  "model": "claude-opus-4-7"
}
```

When you see a prompt in a scenario doc that cites a transcript,
open that file to see exactly which tools fired and what they returned.

## Safety

The Flipper can transmit RF, emulate access cards, act as a USB
keyboard, and reflash its own firmware. PromptZero honours a risk gate
by default (any tool classified `high` or `critical` prompts for
confirmation). The scenarios under `scenarios/offensive/` assume you
have the operator's authorisation for every radio/contactless action.
