# pzrunner

Non-interactive harness for the promptzero Agent. Runs one or more
prompts against the connected Flipper (and optional Marauder) and
emits a JSON record of the full tool-call sequence on stdout.

Not shipped by `task build`. This is a development tool used to:

- Reproduce the example prompts in `docs/`.
- Catch tool-selection regressions when the model version changes.
- Generate fresh transcripts when the tool set changes.

## Build

```bash
task build:runner
# or
go build -o bin/pzrunner ./cmd/pzrunner
```

## Use

```bash
export ANTHROPIC_API_KEY=sk-ant-…

./bin/pzrunner "What apps are installed on my Flipper?"

# Read a long prompt from stdin
echo "detailed multi-line instruction…" | ./bin/pzrunner --stdin

# Multiple prompts, shared history
./bin/pzrunner --keep "Scan for NFC tags" "If you saw a tag, dump its contents"

# Include the Marauder if attached
./bin/pzrunner --wifi "Scan WiFi APs for 20s"
```

## Output shape

Stdout: one pretty-printed JSON object per prompt, each with
`prompt`, `response`, `tools[]`, `duration_s`, `model`, and optional
`error`. Stderr gets connection banner + per-tool progress icons.

## Exit codes

| code | meaning |
|---|---|
| 0 | every prompt returned a response |
| 1 | config load or Flipper connect failed |
| 2 | flag / usage error |
| 3 | one or more prompts returned an error from `ai.Run` |

## Flags

`--config`, `--wifi`, `--stdin`, `--timeout`, `--quiet`, `--max-tools`,
`--keep`. `pzrunner --help` for the detailed list.

## Updating the docs

After changing `internal/agent/tools.go` or the prompt construction,
regenerate transcripts:

```bash
cd docs/transcripts
for prompt_file in *.prompt; do
  ../../bin/pzrunner --quiet "$(cat $prompt_file)" > "${prompt_file%.prompt}.json" 2>&1
done
```

(Prompt files aren't checked in — keep them local. The transcript
README has a short reproduction recipe.)
