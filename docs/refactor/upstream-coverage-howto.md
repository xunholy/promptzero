# Upstream Coverage Diff — Operator Guide

`cmd/coverage-diff` scrapes five awesome-flipperzero-style repositories every
Monday and produces a markdown gap report listing tool/verb names found in
those lists that PromptZero does not yet expose.

---

## Reading the report

The report has two sections:

### 1. Summary table

| Repository | Tokens | Matched | Gaps | Coverage |
|---|---|---|---|---|
| djsime1/awesome-flipperzero | 412 | 87 | 325 | 21.1% |
| … | … | … | … | … |

* **Tokens** — unique canonical identifiers extracted from that README.
* **Matched** — tokens that are substrings of (or equal to) at least one
  registered PromptZero tool name.
* **Gaps** — tokens that matched no registered tool (the action items).
* **Coverage** — Matched / Tokens × 100.

### 2. Gap candidates

Each upstream repository gets its own section listing canonical gap tokens
(`nfcmagic`, `blespam`, `subghzbruteforcer`, …). These are the names to
triage.

---

## Triaging gaps

For each candidate token decide:

| Decision | Action |
|---|---|
| **Port now** | Open a task, implement the tool, it disappears from the next report automatically. |
| **Port later (v0.6+)** | No action needed; it will keep appearing as a gap. |
| **Out of scope** | Add the canonical token to `docs/coverage/out-of-scope.yaml` (see below). The next run will suppress it. |

---

## Suppressing false positives

Edit `docs/coverage/out-of-scope.yaml`:

```yaml
tokens:
  - nfcmagic        # NFC Magic FAP — out of scope (requires custom firmware)
  - blespam         # BLE Spam — deferred to v0.6
  - someothertoken
```

The canonical form strips `-`, `_`, and spaces and lowercases.
`nfc_magic`, `nfc-magic`, `NFC Magic`, and `nfcmagic` are all the same
canonical token.

Commit the updated YAML; the next weekly run will exclude those tokens from
the gap list.

---

## Running locally

```bash
# Build the binary.
CGO_ENABLED=1 go build -o bin/coverage-diff ./cmd/coverage-diff

# Generate a report (writes to stdout; uses ${TMPDIR} cache).
./bin/coverage-diff > /tmp/coverage-report.md

# Force a fresh fetch (bypass cache).
./bin/coverage-diff --no-cache > /tmp/coverage-report.md

# Use a custom out-of-scope allowlist.
./bin/coverage-diff --out-of-scope path/to/allowlist.yaml > /tmp/report.md
```

The binary exits 0 even when gaps exist (gaps are informational).  It exits 1
only when every upstream fetch fails.

---

## CI setup

The workflow runs weekly via `.github/workflows/coverage-diff.yaml`.

* The report is uploaded as a GitHub Actions artifact (retained 90 days).
* The full report is written to the job's **Step Summary** for quick in-browser
  reading.
* If a GitHub issue labelled `coverage-diff` is open in this repository, the
  workflow posts the report as a new comment on that issue.

The coverage-diff step uses `continue-on-error: true` so a broken upstream
README never blocks the main CI pipeline.

---

## Adding a new upstream source

1. Open `cmd/coverage-diff/scraper.go`.
2. Append a new `Source{Name: "...", URL: "..."}` entry to `upstreamSources`.
3. Run `CGO_ENABLED=1 go test -short -race ./cmd/coverage-diff/...` to confirm
   the new source doesn't break existing tests.
4. Commit.

The next weekly run will include the new source in the report.
