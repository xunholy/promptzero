---
name: Phase 0 hotfix review
description: Verification of v0.8 audit Phase 0 hotfixes — all five are implemented in the local working tree, but uncommitted; HEAD still carries the bugs
type: reference
created: 2026-04-26T00:00
tags: [review, v0.8, hotfix]
---

# Phase 0 hotfix review — `v0.8-catalog-and-hotfix` team

Reviewer: team-lead
HEAD reviewed: `a911fcb` (clean) + uncommitted working-tree changes
Audit reference: `docs/refactor/v0.8-team-audit.md` lines 27–44

## Verdict

**The audit is accurate against HEAD. All five Phase 0 hotfixes are implemented in the local working tree but are NOT yet committed.** The required action is for the user to review the uncommitted diff, run the test suite, and create a Phase 0 commit. No additional engineering is required.

## Per-task findings

For each item: HEAD state (the bug as the audit described it) vs working-tree state (the fix already in place uncommitted).

### #1 — mfoc/mfcuk goroutine leak

| | State |
|---|---|
| HEAD `internal/tools/mifare.go` | `RecoverNestedWithRange(cap, 0, hiCap)` and `RecoverDarksideWithRange(cap, 0, hiCap)` — no context passed; goroutine leaks past deadline. |
| Working tree | `RecoverNestedWithRange(runCtx, cap, 0, hiCap)` at `:175` and `RecoverDarksideWithRange(runCtx, cap, 0, hiCap)` at `:318`. Comments at `:173-174` / `:316-317` cite leak prevention. |
| Tests | Cancellation tests already exist at `internal/crypto1/mfoc_test.go:184` and `internal/crypto1/mfcuk_test.go:153`. Both pass. |

**Verdict: PASS** once committed.

### #2 — Faultier `Sweep` ignores ctx

| | State |
|---|---|
| HEAD `internal/faultier/client.go` | `Sweep(startUS, endUS, stepUS uint32)` — plain `for` loop, no cancellation check. |
| Working tree | `Sweep(ctx context.Context, startUS, endUS, stepUS uint32)` at `:166` with `ctx.Err()` check at `:174`. |
| Tests | `TestSweepContextCancellation` at `internal/faultier/client_test.go:250`. Passes. |

**Verdict: PASS** once committed.

### #3 — canbus shell-injection

| | State |
|---|---|
| HEAD `internal/tools/canbus.go` | `id_filter`, `output_path`, `id`, `data` flow straight into `RawCLI` via string concat. No validators present. |
| Working tree | Three validators landed at `:50-83` (`validateCanHexID`, `validateFlipperPath`, `validateCanHexData`). All `RawCLI` callsites validate first (`:141, :147, :202, :209, :248`). New test file `internal/tools/canbus_test.go` covers each rejection branch. |

**Verdict: PASS** once committed.

### #4 — Faultier `Close` not concurrency-safe

| | State |
|---|---|
| HEAD `internal/faultier/client.go` | `Close` checks `c.closed` without a mutex — race window between read and set. |
| Working tree | `closeMu sync.Mutex` declared at `:38` guarding `closed bool`. `Close` at `:79-87` is mutex-guarded and idempotent. Doc comment at `:74-78` documents the contract. |

**Verdict: PASS** once committed.

### #5 — `firmware_extract` mis-grouped

| | State |
|---|---|
| HEAD `internal/tools/firmware_extract.go:51` | `Group: GroupFlipperHW`. |
| Working tree | `Group: GroupHostTools` at `:51`. |

**Verdict: PASS** once committed.

## Test evidence (against working tree)

```
$ go test -short -run "TestSweep|TestClose|TestRecover|TestValidate|TestCanbus|TestFirmwareExtract" \
    ./internal/faultier/ ./internal/crypto1/ ./internal/tools/
ok    github.com/xunholy/promptzero/internal/faultier   0.004s
ok    github.com/xunholy/promptzero/internal/crypto1    0.009s
ok    github.com/xunholy/promptzero/internal/tools      0.010s
```

All cancellation/idempotence/validator regression tests pass with the working-tree changes applied.

## Recommended actions for the user

1. **Inspect the uncommitted diff** — `git status` shows ~24 modified files plus `internal/tools/canbus_test.go` (new). Most of the diff is Phase 0 hotfixes; some files (`crypto1_test.go`, `mfkey32.go`, `recover_fast.go`, etc.) appear to be unrelated in-progress work not part of Phase 0. Separate concerns when committing.
2. **Stage Phase 0 narrowly** — recommend a commit scoped to:
   - `internal/tools/mifare.go` — runCtx forwarding (#1)
   - `internal/faultier/client.go` + `client_test.go` — Sweep ctx + Close mutex (#2, #4)
   - `internal/tools/canbus.go` + `canbus_test.go` — validators (#3)
   - `internal/tools/firmware_extract.go` — group move (#5)
   - `internal/crypto1/mfoc_test.go` + `mfcuk_test.go` — cancellation tests (regression for #1)
3. **Stash or land the rest separately** — `recover_fast.go`, `mfkey32.go`, `internal/flipper/companion/`, `fap/`, `Taskfile.yml`, REPL/setup/router/config changes are not Phase 0 work. They should commit on their own merits, not under the Phase 0 banner.
4. **After Phase 0 lands**, proceed to Phase 1 (Backend interface + concurrency-aware workflow runner) per `docs/refactor/v0.8-team-audit.md` line 50–124. That is the load-bearing v0.8 theme.

## Earlier review error (transparency note)

An earlier draft of this document concluded "all five hotfixes are already pre-fixed; strike Phase 0 from the audit." That conclusion was wrong: it was based on reading the working tree without comparing against HEAD. HEAD still carries every bug the audit described. The audit is correct; the local work simply hadn't been committed yet. This review is the corrected version.

## What this review did NOT cover

- The lower-priority drift fixes the audit lists at lines 38–43 (naming, error wrapping, stale TODOs, `//nolint:unused`, `glitch_disarm` risk-level rationale) — verify these separately.
- The non-Phase-0 working-tree changes — they need their own review pass before committing.
