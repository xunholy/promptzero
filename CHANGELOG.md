# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Streaming abort-early UX** (the natural follow-up flagged in the
  v0.55 closeout). Builds on the streaming-tool-output infrastructure
  shipped in v0.55 and turns it into something the agent or operator
  can actually steer mid-flight: a long-running scan can stop the
  moment a useful frame lands ("got a handshake — stopping") without
  forcibly killing the producer.

  - `streaming.Sink` gains `Abort()`, `Aborted() <-chan struct{}`,
    and `IsAborted() bool`. Abort closes the abort channel exactly
    once (`abortOnce`); `Send` is intentionally NOT short-circuited
    so producers honouring abort can emit a final summary frame
    between observing the signal and calling Close. Nil-sink sentinel
    semantics extend to all three new methods.
  - `Agent.SetToolStreamCallback` callback signature changes from
    `func(streaming.Frame)` to `func(streaming.Frame) bool`. Returning
    true keeps the stream alive; false triggers abort-early. The
    only callers were internal tests, so the rename is safe — no
    host code (cmd/, fap/) referenced the old signature.
  - `dispatchStreaming` now derives a per-call cancellable context
    (`context.WithCancel(ctx)`); on callback false it calls
    `sink.Abort()` AND `cancel()`. Belt-and-suspenders: producers
    polling `ctx.Done()` see the abort even if they ignore
    `sink.Aborted()`. After abort the drain goroutine keeps draining
    but stops invoking the callback, so the producer's Send calls
    don't wedge on a full buffer while it winds down.
  - Abort is **cooperative**: a producer that ignores both signals
    runs to completion. The alternative (forced kill) was rejected
    because it would risk leaving hardware in a half-configured
    state — a stuck Sub-GHz radio mid-TX is worse than a delayed
    stop. Producers MUST poll `Aborted()` or `ctx.Done()` to honour
    abort within reasonable latency.
  - 7 new tests pin: `Sink.Abort` signal + idempotency, post-Abort
    Send still works (final summary frame), nil-sink Abort no-ops,
    dispatch closes Aborted on cb=false, dispatch cancels ctx on
    cb=false, drained-after-abort frames are silently swallowed,
    stubborn producer that ignores both signals still runs to
    completion and the dispatcher returns its final string.

- **First real streaming tool: `subghz_receive`.** Wires the v0.55
  streaming infrastructure to a real long-running capture so the
  abort-early UX has a production consumer, not just tests. Hosts
  that install a stream callback now see one frame per
  firmware-emitted candidate line; returning false from the callback
  aborts the capture promptly via `sink.Aborted()` + ctx cancel.
  Hosts without a callback fall back to the existing blocking
  Handler — unchanged behaviour for non-streaming consumers.

  - New `Flipper.SubGHzRxStream(ctx, frequency, duration, onLine)`
    in `internal/flipper/commands.go`. Wraps `StreamCtx` with the
    same fork-aware command shape as `SubGHzRx` (`subghz rx <freq>
    [device]`) and the same budget/cancel-as-success semantics
    (DeadlineExceeded / Canceled return the accumulated raw with a
    nil error). The dispatched command's echo line — a serial-protocol
    artifact — is filtered out before the first frame so streaming
    callers never see one frame of "subghz rx 433920000" noise per
    call. Stops the firmware command via the StreamCtx-deferred
    Ctrl+C on every exit path (budget, ctx cancel, onLine stop).
  - `subghz_receive` tool in `internal/tools/subghz.go` gains
    `Streams: true` and a `StreamHandler` that pumps each onLine
    line via `sink.Send`, polls `sink.IsAborted()` for the
    consumer-driven stop, and returns the same parsed
    `{candidates:[...]}` JSON the blocking Handler already returns
    so the LLM-facing tool_result is unchanged on the streaming
    path.
  - 3 new mock-pty tests pin the contract: per-line delivery
    (`onLine` called once per candidate line, accumulated raw
    matches), `stop=true` from `onLine` ends capture early and
    sends Ctrl+C (and the post-stop line is NOT in the accumulated
    output), ctx cancel ends capture promptly with no error and
    leaves the session healthy for a follow-up DeviceInfo call.

## [0.55.0] - 2026-05-10

**Roadmap closeout.** v0.55 lands the last two genuinely-open P3
items: ensemble voting on critical decisions (P3-33) and the
streaming-tool-output infrastructure (P3-28 first half). The
breaker half of P3-28 shipped in v0.54.

After this release, every roadmap item that wasn't explicitly
flagged "defer until X" is in main:

- P0-01..P0-06 (foundations)            ✅ v0.3.0
- P1-07..P1-18 (quality + diff)         ✅ v0.3.0
- P2-19..P2-27 (strategic bets)         ✅ v0.51..v0.53
- P3-28 (streaming + breakers)          ✅ v0.54 (breakers) + v0.55 (streaming)
- P3-29 (confidence scoring)            ✅ v0.54
- P3-30 (adversarial test suite)        ✅ v0.54
- P3-31 (prompt + persona versioning)   ✅ v0.53
- P3-32 (fine-tune data export)         ✅ v0.53
- P3-33 (ensemble voting)               ✅ v0.55

The two outstanding P3 items are explicit defer-by-design from the
roadmap's Anti-goals / "Revisit after…" sections:

- P3-34 (plugins): "defer until plugin demand is real."
- P3-35 (pwnagotchi-learning): "Revisit after ≥1 year of audit-log
  data."

### Added

- **Streaming-tool-output infrastructure** (roadmap P3-28 first half
  — closes the item). The breaker half shipped in v0.54; this lands
  the gRPC-style server-streaming dispatch path for tools that opt
  in. Operator-facing live feedback is enabled; the abort-early-
  on-partial-result UX (e.g. "got a handshake — stopping") is the
  natural follow-up that builds on this infrastructure.

  - New `internal/streaming/` package: `Sink` is a bounded-channel
    frame buffer with a non-blocking `Send` (drops on overflow,
    counted as `Drops`), idempotent `Close`, monotonic `Seq`
    numbering, byte-buffer copy-on-send so producers can reuse a
    parse buffer. Nil-sink methods are no-ops so dispatch code can
    pass nil for non-streaming paths without an "if sink != nil"
    wrapper at every emission site.
  - `tools.Spec.Streams bool` — declarative opt-in flag.
  - `tools.Spec.StreamHandler` — optional alternate handler with
    signature `(ctx, deps, args, *streaming.Sink) (string, error)`.
    Returns the same final string the non-streaming Handler would
    so the LLM contract is unchanged — partial frames are
    operator-side only.
  - `Agent.SetToolStreamCallback` — host wires the per-frame
    consumer (CLI status line, web UI, SSE forwarder). Dispatch
    routes through the streaming path only when ALL three are true:
    Spec.Streams=true, Spec.StreamHandler set, callback installed.
    Otherwise dispatch falls through to the regular Handler — safe
    default; existing tools unaffected.
  - `Agent.dispatchStreaming` blocks until the consumer drain
    completes so callers can assume "dispatch done = all frames
    observed". Important for audit log + report generator
    consistency.
  - 16 new tests pin: Sink default-buffer, send/round-trip, copy-
    on-send, monotonic Seq, drops-on-full, post-close send rejected,
    idempotent close, range-loop terminates on close, nil-sink no-
    ops, concurrent producers (uniqueness + drop accounting),
    Sequence accessor; agent: SetToolStreamCallback round-trip,
    streaming dispatch forwards frames + returns final string,
    fallback when callback unset, fallback when Streams=false flag
    is false, no-frames-after-dispatch-return drain guarantee.

  After this release, every actually-open roadmap item is delivered.
  Remaining P3 items (34 plugins, 35 pwnagotchi-learning) are
  explicit "defer until X" by design — see Anti-goals.

- **Ensemble voting on critical-risk decisions** (roadmap P3-33).
  Closes the item. When the active persona declares
  `consensus: [model-a, model-b, …]` and the about-to-fire tool is
  `risk == critical`, the agent runs the prospective-critique prompt
  once per listed model and aggregates the verdicts. Disagreement
  prepends a `<consensus-disagreement>` block on the tool result so
  the model stops and surfaces the split to the operator;
  unanimity falls through to the existing single-model prospective
  path with no behavioural change.

  - New `internal/consensus/` package — pure logic, no I/O. `Vote`
    tallies a slice of `Verdict{Model, Risk, Critique}` and returns
    a `Result` with `Unanimous` + `AgreedRisk` + an `Abstentions`
    tally. Risk values are normalised to the canonical `ok` /
    `unclear` / `risky` set; unrecognised values count as
    abstention so a typo can't masquerade as agreement. A single
    non-abstain voter still passes (a Haiku rate-limit shouldn't
    block the call when Sonnet votes ok). All-abstain produces no
    signal (`Unanimous=false, AgreedRisk=""`).
  - `consensus.DisagreementMessage` produces the structured
    `<consensus-disagreement>…</consensus-disagreement>` block:
    one line per non-abstain verdict listing the model + risk +
    one-line critique excerpt (cap 200 chars), plus an abstention
    tally. Empty when the panel is unanimous OR when fewer than
    two models actually voted (no real split to escalate).
  - `Persona.Consensus []string` — operator-supplied list of model
    identifiers; YAML key `consensus`. Empty disables ensemble
    voting; the existing single-model prospective check still runs.
  - Agent integration: new `consensus.go` with
    `runEnsembleProspective` + `prospectiveWithModel` +
    `extractRiskFromCritique`. Wired alongside the existing
    `maybeProspectiveReflect` in dispatch — additive, no change
    to the single-model path. Logs
    `ensemble_consensus_disagreement` (warn) on a real split.
  - 19 new tests pin: empty input, all-agree, disagreement,
    case/whitespace normalisation, unknown-risk-as-abstention,
    all-abstain-no-signal, single-voter-passes, disagreement
    message structure (open + close tags, model + risk + excerpt
    rendering, abstention tally singular/plural), summarise-
    critique cap, extract-risk-from-critique parsing across
    valid/missing/malformed/empty, no-client safety, empty/blank
    models filtered. Persona YAML round-trip + absent-stays-nil.

  `task lint` clean; full short test suite passes.

## [0.54.0] - 2026-05-10

P3 sweep — three more roadmap items closed. v0.54 finishes the
"safety / observability / fine-tune-readiness" cluster of P3 items
that pair naturally with the v0.53 versioning + cache work:

- P3-30 — adversarial test suite (`test/adversarial/`) pins the
  combined parser → quarantine → sanitiser contract end-to-end.
- P3-29 — classifier-output confidence + persona-tunable abstention
  on vision and the per-turn router. Closes the symmetrical gap
  with the v0.4-era input-grounding sibling.
- P3-28 (second half) — per-tool circuit breaker + structured
  `<circuit-breaker-open>` escalation message in agent dispatch.
  Streaming-tool-outputs (the first half) is deferred — it requires
  changes to the tool Spec interface that don't fit a single
  iteration cleanly.

After this release, every P0 + P1 + P2 item plus P3-29, P3-30,
P3-31, P3-32, and the breaker half of P3-28 are in main.
Remaining P3: 28 streaming half, 33 ensemble voting, 34 plugins
(deferred-by-design), 35 pwnagotchi-learning (deferred-by-design).

### Added

- **Per-tool circuit breaker — second half of P3-28**. Closes the
  "circuit breakers stop the N-th retry loop" sub-item the roadmap
  flagged after the loader_close infinite-loop incidents. Streaming
  tool outputs (the first half) is a larger architectural change
  touching the tool Spec interface and is deferred.

  - New `internal/breaker/` package: `Counter` tracks per-tool
    consecutive same-kind error streaks. `Record(tool, errOrOutput)`
    increments on error, resets on success or different-kind error;
    threshold defaults to 3. `State` reports `Open=true` once the
    streak hits the threshold. Same-kind matching is a normalised
    string compare (trim + lower + collapse whitespace) so a model
    retrying with a slightly-different prompt but the same
    underlying error still trips. Per-tool isolation prevents fan-
    out across tools from accidentally tripping any one breaker.
  - `breaker.EscalationMessage(state)` produces a structured
    `<circuit-breaker-open>…</circuit-breaker-open>` block the
    dispatcher can prepend to the offending tool result so the model
    sees an explicit "stop hammering this; pick a different
    approach" cue alongside the original error. Symmetry with the
    existing `<untrusted-hardware-output>` quarantine routing.
  - Wired into `Agent.streamOnce` tool dispatch: when the breaker
    trips, the escalation block is prepended before reflection /
    detector / quarantine wrapping. A structured
    `circuit_breaker_open` warn log records the trip with tool +
    streak + kind for telemetry.
  - `Agent.SetBreaker` / `Agent.Breaker` are the public attach /
    detach surface. Nil counter is a usable sentinel — every
    breaker method is a no-op so the agent's tool dispatch can
    unconditionally guard with `if a.breakerCounter != nil`.
  - 17 new tests pin: threshold defaulting, trip-at-threshold,
    different-kind reset, success reset, per-tool isolation,
    normalised same-kind detection across whitespace + case,
    Reset / ResetAll / unknown-tool state, nil-counter no-ops,
    Snapshot tally, escalation-message shape (only when Open;
    contains tool + streak + kind), concurrent safety (20×100
    interleaved Record calls), agent SetBreaker/Breaker round-trip,
    full-loop integration mirroring the dispatch-side composition.

  `task lint` clean; full short test suite passes.

- **Vision + router classifier-output confidence with persona-tunable
  abstention** (roadmap P3-29 second half — closes the item). The
  v0.4-era `confidence.Evaluate` covered tool-input grounding; this
  release closes the symmetrical gap on classifier *outputs*.

  - `confidence.ParseClassifierResponse` — pure helper that extracts
    `confidence` from the JSON envelope a classifier emits, clamps to
    [0, 1], and falls back to no-signal (`hasSignal=false, score=1.0`)
    when the model returned the legacy bare-array form or free-text
    prose. Backward-compatible by construction: unchanged callers see
    "always proceed" semantics.
  - `confidence.ShouldAbstainAt(score, threshold)` — strict-less-than
    abstention check; threshold ≤0 falls back to
    `confidence.DefaultClassifierThreshold` (0.5).
  - `Persona.Confidence map[string]float64` — per-classifier-surface
    threshold overrides keyed by `vision`, `router`, etc. Empty map
    keeps every surface at the 0.5 default.
  - **Router**: prompt updated to ask for
    `{"groups":[…],"confidence":<0-1>}`. Below-threshold confidence
    routes to the documented `nil, nil` "fall back to full catalog"
    path with a structured `router_abstain_low_confidence` log.
    Bare-array responses still parse (legacy callers unaffected).
  - **Vision**: new typed `Result{Text, Confidence, HasConfidence,
    LowConfidence}`. `Analyzer.AnalyzeFileWithConfidence` /
    `AnalyzeBase64WithConfidence` are the new entry points; the
    string-returning `AnalyzeFile` / `AnalyzeBase64` keep working as
    a thin wrapper. The vision prompt asks the model to wrap its
    answer in `{"answer":"…","confidence":…}`; an extractor pulls
    the answer + score and falls through to raw prose if the model
    returned a bare paragraph.

  19 new tests pin: classifier-helper round-trip + clamping +
  malformed-input handling + non-numeric-confidence rejection,
  ShouldAbstainAt threshold defaulting, persona YAML round-trip on
  the Confidence map (with-and-without override), router threshold
  lookup across (no persona, no confidence map, override present,
  vision-only override), abstention helper composition, vision
  extraction from object-with-answer / object-without-answer / prose
  / over-range-clamping. `task lint` clean.

- **`test/adversarial/` — centralised adversarial test suite**
  (roadmap P3-30). A unified attacker-shaped corpus + assertion
  harness covering the *combined* parser-then-quarantine-then-
  sanitiser contract. Existing per-package injection tests pin
  individual surfaces in isolation; this directory pins the layered
  end-to-end safety story so a regression in any one layer surfaces
  as a centralised CI failure.

  Corpus categories (in `corpus.go`):
  - `InjectionPayloads` — direct-instruction injections, role-
    confusion, JSON tool-call mimicry, tag-escape attempts, ANSI
    escapes, raw control bytes, Unicode RTL/LRO display attacks.
  - `MarauderAPLines` / `MarauderProbeLines` / `MarauderBLELines`
    in the canonical formats from each parser's own seed tests, so
    a parser-format change has to update one corpus file rather
    than scatter regressions across packages.
  - `HardwareToolNames` / `AuditToolNames` /
    `StructuredInternalToolNames` — the three quarantine classes.

  Test contracts (in `adversarial_test.go`):
  - Every hardware tool wraps in `<untrusted-hardware-output>` for
    every payload in the corpus (the most direct prompt-injection
    surface).
  - Audit tools wrap in `<untrusted-audit-content>` instead.
  - Structured-internal tools never get wrapped (their output is
    self-attested PromptZero text).
  - Error-path output gets wrapped on the same rule as success-path
    output (an error message can carry attacker-controllable text
    too — e.g. an SSID embedded in a connection-failure message).
  - ANSI escape sequences are stripped, raw NUL/BEL/DEL bytes are
    stripped, but `\n` and `\t` survive (multi-line tool output
    must keep its formatting).
  - Marauder AP / Probe / BLE parsers keep BSSID, Client MAC, RSSI,
    Channel clean even when the free-text fields they sit alongside
    carry injection payloads.
  - Tag-escape attempts (a payload containing the closing wrapper
    string itself) stay inside the wrapper — pinned by counting the
    open + close tag occurrences in the rendered output.

  Required exposing one new agent helper: `agent.QuarantineOutput`
  (a thin public wrapper around the existing unexported sibling) so
  the cross-package test can call into the production sanitiser +
  wrapper without re-implementing them.

  11 tests, 30+ subtests. `task lint` clean (Unicode RTL/LRO
  literals written as Go escape sequences for staticcheck ST1018).

## [0.53.0] - 2026-05-10

P2 closeout + P3 down-payment. Three commits closing the last P2
roadmap item (semantic cache for generated payloads) plus the two
P3 items that pair directly with the future fine-tuning track:
prompt + persona versioning on every audit row (P3-31), and the
fine-tune dataset exporter learning the `--since` and
`--persona-version` filters that work with those new fields (P3-32).

After this release, P0 + P1 + every P2 item is in main, P3-31 +
P3-32 are in main, and P3-29 input-grounding confidence is partial
(input-side abstention shipped in earlier releases; classifier-output
confidence — vision, intent router — is still backlog). Remaining
P3 items: 28 streaming, 29 (vision/router half), 30 adversarial test
suite, 33 ensemble voting, 34 plugins, 35 pwnagotchi-learning.

### Added

- **Fine-tune dataset export upgrades** (roadmap P3-32). The
  `internal/trainset` JSONL/chat exporter learns three new dimensions
  that pair directly with the P3-31 audit-row enrichment shipped this
  release window:

  - `Options.Since` — drop entries with `Timestamp` strictly before a
    cutoff. Wired in the REPL via `--since=YYYY-MM-DD` (anchored at
    midnight UTC) or `--since=2026-04-01T15:30:00Z` for finer slicing.
    `trainset.ParseSince` is exposed so other call sites (a future
    headless `promptzero export` subcommand) can reuse the format
    contract.
  - `Options.PersonaVersions` — restrict the export to entries whose
    `Entry.PersonaVersion` matches one of the listed values. CLI
    `--persona-version=1.2.0` (repeat to allow multiple). Mirrors the
    typical workflow: bump the persona version after a prompt fix,
    export only the post-fix sessions for the next fine-tune cycle,
    leave the pre-fix sessions out.
  - `Record.PersonaVersion` + `Record.PromptHash` flow into JSONL
    rows; `ChatRow.Meta["persona_version"]` + `Meta["prompt_hash"]`
    flow into the OpenAI-chat format. Downstream pipelines can group
    rows by exact prompt content even when the operator forgot to
    bump the version string.

  5 new tests pin: since-filter boundary semantics, persona-version
  filter, JSONL Record carries the new fields, ChatRow Meta carries
  the new fields, `ParseSince` accepts ISO-8601 date and RFC3339,
  rejects garbage, and treats empty as zero-time. `task lint` clean.

- **Prompt + persona versioning on every audit row** (roadmap P3-31).
  Closes the first P3 item. Regression analysis and the future
  fine-tuning data exporter (P3-32) need to know *exactly* which
  prompt + persona configuration produced an audit row, otherwise
  a prompt typo fix can't be distinguished from a new persona
  rollout.

  - `Persona.Version` (YAML `version:`) — operator-supplied,
    typically a SemVer string or a date. Empty for unversioned
    personas (the safe default; analysers can group by content
    hash instead).
  - `agent.PromptTemplateHash(name)` and `agent.SystemPromptHash(p,
    hasWiFi, hasWorkflows)` — pure functions returning 64-char hex
    SHA-256 of the embedded template / fully-assembled system
    prompt the agent would present for the given args. Hashes are
    in-memory only; the prompt content itself is never persisted.
  - `audit.PersonaContext{PersonaVersion, PromptHash}` plus
    `Log.SetPersonaContextResolver(fn)` mirror the existing
    `TechniqueResolver` pattern: a per-session hook the agent
    installs once at startup; the audit log invokes it on each
    `Record` to populate `Entry.PersonaVersion` and
    `Entry.PromptHash`. Nil resolver leaves both empty.
  - `Agent.SetAuditLog` now wires the resolver as a closure over
    `personaAtomic` so a mid-session `/persona` switch updates the
    next audit row's PersonaVersion + PromptHash without re-wiring.
  - 9 new tests pin the contract: YAML round-trip, template hashes
    are stable + distinct + 64-char-hex, assembled-prompt hashes
    differ across persona / hasWiFi / hasWorkflows changes,
    resolver flows through to Entry observers, nil resolver leaves
    fields empty, resolver fires exactly once per Record, agent
    wiring captures correct hash + version, persona-switch updates
    next row, nil log is a no-op.

  `task lint` clean; full short suite passes.

- **`internal/semcache` — durable, file-backed semantic cache for
  generated payloads** (roadmap P2-27). Closes the second-to-last
  P2 item. Key idea: identical generation inputs (task label,
  provider name, system prompt, message list) produce identical
  outputs, so a second call should return the prior bytes without
  re-billing the LLM.

  - Cache key is `SHA-256(task ‖ provider ‖ system ‖ <role,content>*)`,
    null-terminated between parts so two concat-equivalent splits
    don't collide.
  - On-disk layout: one JSON file per entry under `~/.promptzero/
    cache/generations/<key>.json`. No in-process state besides a
    mutex; `rm -rf` is safe and idempotent.
  - LRU eviction by `LastAccessed`; capacity defaults to 256 entries.
  - Get refreshes `LastAccessed` and increments `Hits`; Put
    normalises empty timestamps and triggers eviction; Clear /
    Stats round out the public surface.
  - Corrupt JSON entries are dropped on read so a malformed file
    doesn't poison subsequent calls.
  - Nil `*Cache` is a usable sentinel — every public method is a
    no-op so callers can wire `g.cache = nil` and skip "if c != nil"
    plumbing.
  - 12 unit tests pin: deterministic + collision-resistant keys,
    capacity defaulting, round-trip + Hits/LastAccessed update,
    miss on unknown key, corrupt-entry recovery, empty-key
    rejection, nil-Cache no-op, LRU eviction order, Clear,
    Stats shape, DefaultRoot under HOME, timestamp normalisation.

- **`Generator.SetCache` / `SetCacheBypass` integration**
  (P2-27 wiring). `completeWithFallback` now consults the cache
  before each LLM call and writes successful non-refusal responses
  back into it. Refusals are explicitly NOT cached — re-running
  might succeed, and caching a transient policy refusal would lock
  the operator out. Bypass mode skips reads but still writes, so
  `--no-cache` / `/regen` semantics keep the cache populated for
  future calls.

  Re-keys after a fallback so a subsequent identical refusal-then-
  fallback chain short-circuits at the cache. 7 new integration
  tests pin: cache hit avoids LLM call, miss on different
  description, miss on different task label, bypass-skips-read-
  still-writes, refusal-is-not-cached, no-cache fall-through,
  cleanOutput-preserved-via-cache (the second call's content
  matches the first after both pass through cleanOutput).

  `task lint` clean; full short test suite passes.

## [0.52.0] - 2026-05-10

P2-20 (Freqman + signal-library interop) closed. Three commits
covering the parser, the host-side library walker, and the
HTTPS-only importer with allowlist + hash-pin. The operator now
has a complete catalogue lifecycle for Sub-GHz signals: import a
community-curated list, search it before any RF capture or
transmit, and round-trip individual entries to/from Flipper `.sub`
files for the actual hardware operation.

### Added

- **`signal_import` tool — HTTPS-only Freqman list importer with
  hash-pin, allowlist, size cap, and parse-before-write validation**
  (roadmap P2-20 final). Closes the third and last sub-item of
  P2-20: an operator can now seed the local catalogue from
  community-curated public lists with the same end-to-end safety
  posture as the rest of the agent's risky-write tools.

  - Allowlist of vetted hosts (`lab.flipper.net`, `flipc.org`,
    `raw.githubusercontent.com`, `gist.githubusercontent.com`).
    Adding a host is a deliberate PR-time decision; hash-pinning
    is defence-in-depth, not the primary trust gate.
  - HTTPS-only — non-HTTPS URLs rejected pre-fetch.
  - Size cap of 1 MiB; oversize responses refused.
  - Optional `expected_sha256` parameter pins the fetched body's
    digest. The handler always returns the actual `sha256` so the
    operator can copy it into a follow-up call to lock the import
    against future drift.
  - `CheckRedirect` hook on the package-level HTTP client refuses
    any redirect hop whose host is off the allowlist (CDN-fronted
    catalogues that 301 elsewhere stay safe).
  - Filename sanitisation rejects `/`, `\`, `.`, `..`, and any
    suffix other than `.txt` (so the saved file is reachable by
    the v0.51 `SearchFreqmanDir` walker).
  - Parse-before-write: bytes that don't decode as a Freqman list
    surface as an error instead of polluting `~/.promptzero/freqman/`.
  - Risk: Medium. Pinned by 14 new tests (URL + filename + hash
    validation; 200/404/oversize/parse-fail/hash-mismatch behaviours;
    happy-path round-trip with httptest server; CheckRedirect-hook
    direct test). Registry size pinned at 274 (was 273).

- **`signal_library_search` tool + recursive Freqman directory walker**
  (roadmap P2-20 mid-stage). Builds on the v0.51-shipped Freqman parser
  to give the agent a host-side library lookup before any RF capture
  or transmit: ask the catalogue at `~/.promptzero/freqman/` for
  hits on a frequency or description substring, and reuse a vetted
  entry instead of capturing fresh.

  - `fileformat.SearchFreqmanDir(root, query, limit)` walks `*.txt`
    files recursively, parses each as a Freqman list, and returns
    `FreqmanMatch{File, Line, Entry}` records. Pure-numeric queries
    match by Hz: equality on single-frequency entries, inclusive
    band membership on `a=…,b=…` range entries (so a query of
    `317000000` finds a 315–320 MHz sweep). Non-numeric queries
    case-insensitively substring-match `Description`. Malformed
    libraries surface in the error slice rather than blanking the
    result set; non-`.txt` files are ignored. Symlinks that resolve
    outside `root` are dropped (defence in depth).
  - `signal_library_search` (Risk: Low, Group: meta.util) is the
    LLM-visible wrapper. JSON envelope returns `{root, query,
    matches[], match_count, limit, parse_warnings[]}`. Limit
    defaults to 50, clamped to 500. Empty `query` rejected; missing
    `~/.promptzero/freqman/` returns `match_count=0`.
  - 16 new tests pin the contract: directory walking, range-band
    membership, recursion, non-`.txt` skip, malformed surfaced as
    warnings, line-number accounting through comments + blanks,
    and the tool's JSON envelope shape, limit defaulting + clamping,
    home-dir override via `t.Setenv`. `task lint` clean.

  Registry size pinned at 273 (was 272). Signal-import-from-URL is
  P2-20's last sub-item and lands in a follow-up release.

- **Freqman list parser/marshaller in `internal/fileformat/freqman.go`**
  (roadmap P2-20 foundation). Tolerant CSV parser for the de-facto
  `f=<Hz>,m=<mod>,bw=<n>,s=<step>,d=<desc>` interop format shared by
  HackRF/PortaPack-Mayhem, OpenSDR, and Flipper community signal lists.
  Supports both single-frequency entries and `a=<startHz>,b=<endHz>`
  range-scan entries; preserves unknown `key=value` pairs in `Extra`
  for round-trip lossless behaviour against firmware-fork extensions.
  `FreqmanFromSub` / `ToSubLite` interconvert single-frequency entries
  with the existing `*SubFile` so an operator can move a captured
  `.sub` into a Freqman library or hydrate a stub `.sub` from a known
  catalogue entry. The follow-on `signal_library_search` and
  `signal_import` tools (P2-20 mid/late) build on this primitive in a
  later release.

  Sticky-tail rule for `d=`: everything after the first top-level
  `d=` token (start-of-line or `,`-anchored) is the description, so
  unquoted commas inside descriptions — Mayhem's emitter does not
  quote — round-trip correctly. `Find` does Hz-or-description lookup
  case-insensitively; `Sort` orders entries by frequency stably so
  intra-band operator ordering survives.

  Pinned by 19 unit tests covering round-trip, range entries,
  CRLF input, comment/blank lines, malformed-token rejection, float-
  Hz rejection, and `*SubFile` interconversion. `task lint` clean.

## [0.51.0] - 2026-05-10

Parser-security parity sweep. Three sibling tests pinning the
prompt-injection-isolation contract on every WiFi/BLE-scan
parser in the codebase that captures attacker-controllable
free-text fields. The quarantine layer in `internal/agent` is
the downstream catch-all, but the structured parsers are the
first line of defence — operators and the LLM key off the
*structured* fields (BSSID, RSSI, Channel, ClientMAC, MAC),
which must not get corrupted by injection text dropped into
the *free-text* fields (SSID, Probe, Name).

### Added

- **`TestParseAPList_InjectionPayloadStaysInSSID`** in
  `internal/bruce`. WiFi AP-scan parser sibling of the
  long-standing `TestParseAPList_InjectionPayloadStaysInSSID`
  guard in `internal/marauder/parse_test.go` (since v0.5).
  Closes the access-point-side parity gap.

- **`TestParseSniffProbe_InjectionStaysContained`** in
  `internal/marauder/parsers`. Probe-request SSIDs are
  attacker-controllable (any nearby client can broadcast a
  probe with arbitrary SSID payload); pin that the structured
  parser keeps RSSI/Channel/ClientMAC clean while letting the
  payload sit in `Probe`. Closes the probe-request-side gap.

- **`TestParseBLESniff_InjectionStaysContained`** in
  `internal/marauder/parsers`. BLE friendly-names (the GAP
  Complete Local Name field) are operator-supplied on the
  broadcasting device. Pin that the parser's MAC heuristic
  doesn't get fooled by non-MAC injection text and that RSSI
  stays clean.

After this release, every WiFi/BLE-scan parser surface in
the codebase has explicit isolation pinning. Prompt-injection
wrappers in `internal/agent` (`<untrusted-hardware-output>`)
remain the downstream quarantine layer; the parser tests pin
that the structured fields the LLM keys off don't get
corrupted upstream of that quarantine.

## [0.50.0] - 2026-05-10

Test-coverage pass on untrusted-input parsers, plus one
final documentation-drift cleanup. No code-path changes; all
six commits are tests or doc edits, but the fuzz tests do
add a new `testdata/fuzz/` directory pattern under
`internal/vision/`, `internal/iclass/`, `internal/marauder/`,
and `internal/tools/`.

### Added

- **Four `Fuzz` tests pinning the no-panic guarantee on
  attacker-shaped input** to the parsers most-exposed to
  LLM- or operator-supplied data:
  - `vision.parseDataURL` (data-URL extraction; previously
    pinned by a single regression test for the v0.47
    slice-bounds fix)
  - `iclass.ParseCapturesHex` (hex Proxmark3 capture
    decoding)
  - `marauder.parseMarauderResponse` (raw serial response
    line normalization). The fuzz itself surfaced a
    contract subtlety in the draft assertion (CR-only
    inputs expand into multiple normalized lines under
    `\r → \n` rewrite) — the no-panic guarantee was kept
    and the speculative line-count invariant dropped.
  - `tools.parsePorts` (LLM-supplied port-spec parser for
    `port_scan_tcp`; this one had **zero direct tests**
    before — only transitive coverage through tool e2e).
    Added 6 unit tests + the fuzz; fuzz pins
    sorted/deduplicated/in-range invariants on success +
    nil-slice on error.

  Each fuzz seeds the boundary inputs the unit tests cover,
  and 5-second runs on each surfaced 20–65 new coverage
  paths under 28 workers without a single panic. Run with
  `go test -fuzz=Fuzz<Name> ./internal/<pkg>/`.

- **`tools.UnregisterForTest` direct coverage.** The helper
  added in v0.48.0 (so cross-package tests can register a
  fake tool with `t.Cleanup` and not leak it under
  `-count=N`) had only transitive coverage. Two focused
  tests now pin the contract: removes-canonical-and-aliases,
  and no-op-on-unregistered-name.

### Changed

- **`SECURITY.md` alignment with rescinded deprecation.**
  The Safety model section still claimed
  `--mode recon|intel|stealth` "alias to [--read-only]
  during a one-release deprecation window" — framing
  retracted in v0.47/v0.48-era code commits and aligned
  elsewhere (configuration.md, agent comments, persona +
  config example YAMLs). Last user-facing doc carrying the
  stale framing; rewritten to describe the actual
  layering.

## [0.49.0] - 2026-05-10

Maintenance release. One real bug fix carried forward from
the v0.48 write-path-Close audit, plus a flake-headroom test
fix and four polish items found via static-analyzer
(staticcheck, errcheck) sweeps.

### Fixed

- **`trainset.Export` swallowed `bufio.Writer.Flush` error.**
  Same write-path-Close suppression pattern as v0.48.0's
  `/upgrade` and `/audit export` fixes, one layer deeper:
  `Export` wraps the destination writer in a `bufio.Writer`
  and used `defer bw.Flush()`. The deferred ignore meant a
  failure during the final flush (network FS hiccup, ENOSPC
  mid-drain) silently truncated the export — and the v0.48
  file-Close fix wouldn't help here, because the bytes never
  even made it from buffer to file. Replaced with explicit
  `Flush()` at the success exit, with the error wrapped via
  `flush:` prefix. Pinned by `TestExport_FlushErrorSurfaced`.

- **Error chain preservation in `resolveValidatePath`.**
  The web layer's path-validation helper used
  `fmt.Errorf("invalid path %q: %v", p, err)` for
  `filepath.Abs` failures — `%v` breaks the error chain so
  callers can't `errors.Is` against the underlying fs error.
  Switched to `%w`. Pure correctness; no behaviour change
  unless a future caller adds an `errors.Is` check.

### Changed

- **`TestStreamCancelViaDone` drain window 2s → 5s.** The
  Stream goroutine polls `done` at ~100ms granularity, so a
  non-flake drain completes in <500ms. Under heavy parallel
  load + race detector, CPU contention occasionally pushed
  iterations past the 2s window (1 in ~50 runs during the
  v0.48 release cycle). The extra 3s is pure headroom; no
  contract change.

- **Polish items.** Three small consistency fixes surfaced
  by static-analyzer sweeps:
  - `staticcheck U1000`: dropped unused `federatedFallbackMsg`
    constant in `internal/tools/mifare.go`. Stranded since
    v0.7 when native mfoc/mfcuk replaced the federated
    Proxmark3 redirect; papered over with `//nolint:unused`.
    The proper docstrings on the `mfoc_attack` /
    `mfcuk_attack` / `mfkey32_recover` specs document the
    offline workflow authoritatively now.
  - `staticcheck ST1016`: unified `ToolError` receiver name
    (`JSON` used `e`, `withDeviceState` used `te`) to `e`
    consistently.
  - `errcheck`: prefixed `_ =` on four cleanup-path
    `Close()` discards in `internal/audit/audit.go` and
    `internal/flipper/mock/mock.go` to match the existing
    convention (the very next line of the audit case
    already used `_ = releaseFlock(...)`).

## [0.48.0] - 2026-05-10

Test-isolation hardening + two real write-path bugs in the
`/upgrade` and `/audit export` flows.

### Fixed

- **Self-upgrade download swallowed `Close` error.**
  `cmd/promptzero/upgrade.go:downloadFile` used a deferred
  `f.Close()` after `io.Copy(f, resp.Body)`. A delayed flush
  failure (ENOSPC mid-flush, fsync error on a network FS)
  would silently leave a truncated/corrupt binary on disk
  while the upgrade flow reported success — breaking the
  next launch with no diagnostic. Replaced with the
  explicit-Close pattern that's already used by the sibling
  archive-extraction path (line 416).

- **`/audit export` swallowed `Close` error.** Same
  pattern in `cmd/promptzero/commands.go`: a delayed flush
  during `Close()` could corrupt the exported audit log
  while the operator's terminal showed the green "wrote N
  rows" message. Particularly bad for an audit export — the
  file is supposed to be a faithful record. Now surfaces
  the close error before printing success.

- **`tools.resetForTest()` permanently destroyed the
  registry.** The package-private helper used by
  `spec_test.go` cleared `byName`/`byAlias`/`order` and
  never restored them. Test ordering at `-count=1` hid the
  bug because `audit_test.go` (consumer) ran before
  `spec_test.go` (resetter), but `-count=2+` produced
  reliable failures in subsequent iterations:
  `tool "audit_query" not registered`. CI passes because it
  runs `-count=1`. Changed `resetForTest`'s signature to
  take a test helper, snapshot the registry, and register a
  `t.Cleanup` that restores. All 10 call sites migrated.
  The full short test suite is now green under
  `go test -race -count=3 -shuffle=on ./...`.

- **`TestDispatch_RecoversToolHandlerPanic` leaked a
  registered tool.** Sibling test-isolation issue:
  `internal/agent/mode_dispatch_test.go` registered a
  `_test_panic_tool_for_dispatch_recover` Spec without
  cleanup, hitting `tools.Register`'s duplicate-name
  panic on the second iteration. Added
  `tools.UnregisterForTest(name)` as a public sibling of
  the package-private `resetForTest` so cross-package tests
  can register fake tools with `t.Cleanup` and not leak
  them.

### Added

- **`TestClassifyExplicit`** in `internal/risk` — pins the
  `(Level, bool)` contract corners (compile-time hit,
  unknown miss, runtime register, runtime override of
  compile-time). Previously only covered transitively
  through coverage validators.

### Changed

- **`cmd/promptzero` termios consolidation.**
  `enableOPOSTONLCR` and `watchWindowSize` were ~90%
  duplicated across `main_termios_linux.go` and
  `main_termios_unixlike.go` — only the ioctl request
  constants differed. Pull both functions into a new shared
  `main_termios.go` (build-tagged Linux ∪ BSDs); each
  per-OS file shrinks to a 10-line constants module.
  Net +60 / -86 lines; future termios additions land once
  instead of being copy-pasted.

- **Documentation drift cleanup**, follow-up to the
  v0.47-era deprecation rescinds. Five example YAMLs
  (`examples/config.yaml` + four personas) and
  `docs/reference/configuration.md` still echoed
  `"deprecated in v0.19.0, removed in v0.20.0"` framings
  that earlier commits this cycle had retracted in code.
  Rewritten to describe the actual layering (read-only
  first, then mode/Tools as positive scoping); the four
  shipped persona templates leave Tools empty because their
  other knobs cover the intent, but Tools allowlists remain
  a supported feature for personas that want positive
  catalog scoping.

## [0.47.0] - 2026-05-10

Cleanup pass: a real slice-bounds bug fix in vision, two
straggler panic-recovery sites picked up after v0.46.0
shipped, and a long-overdue deprecation rescind across four
files where the "v0.20.0 will remove this" comments had
remained through v0.46.0.

### Fixed

- **`vision.AnalyzeBase64` data-URL parser**: an LLM-supplied
  `image` arg of shape `"X;base64,..."` (where `";base64,"`
  appeared in the first five bytes) tripped a `b64data[5:idx]`
  slice-bounds panic. Extracted to a `parseDataURL` helper
  that requires the literal `"data:"` prefix before slicing
  and returns `ok=false` for malformed inputs so callers fall
  back to raw-base64 mode. Pinned by
  `TestParseDataURL_PanicSlicePathRegression` plus seven
  other parse + extension-routing cases. Closes the only
  `internal/` package that previously had no test file.

- **`flipper/serial.go` handshake goroutine** (post-v0.46.0
  follow-up): same channel-send-or-block contract as the REPL
  turn dispatcher, missed by the v0.46.0 sweep because the
  ctx-done arm's `<-done` synchronisation read makes the
  potential deadlock less visible. Custom inline recover
  now always sends to `done` with a synthetic
  `"handshake panicked: ..."` error.

- **SIGWINCH watcher goroutines** (post-v0.46.0 follow-up):
  `watchWindowSize` on both Linux and BSD-likes wraps a long-
  lived goroutine that delivers terminal-resize events to a
  caller-supplied callback. Both build-tagged variants were
  missed by the v0.46.0 sweep. Plain `obs.SafeGo` wraps; no
  channel-send contract.

### Changed

- **Deprecation rescind sweep** across four files where the
  "phased out in v0.19.0, removed in v0.20.0" comments had
  remained through v0.46.0:
  - `agent.SetMode` / `agent.opMode` / `agent.ErrBlockedByMode`
    — mode is genuinely useful as a coarse capability filter
    layered after the read-only rail; deprecation rescinded
    and the layering documented.
  - `persona.Persona.Tools` — allowlist-shape persona scoping
    is genuinely useful alongside the read-only rail rather
    than redundant with it. Rescinded plus eleven
    `//nolint:staticcheck` markers across four files removed.
  - `config.Config.Mode` field — comment rewritten to describe
    the layering with `ReadOnly`.
  - `setup.go setupMode` — function-level deprecation comment
    dropped; two misleading runtime warnings (`"--mode recon
    is deprecated"`, `"--mode assault is now a no-op"`)
    removed because they lied about observable behaviour
    (`ai.SetMode(m)` actually applies the mode and assault
    genuinely allows everything Standard does). Kept the
    recon/intel/stealth → SetReadOnly auto-enable as
    documented defence-in-depth.

### Removed

- **`voice.Engine.Record / .Transcribe / .TranscribeReader`
  non-ctx wrappers**. Production already on the Ctx variants
  (`cmd/promptzero/repl.go` uses `RecordCtx`,
  `internal/web/server.go` uses `TranscribeReaderCtx`); only
  three test sites still called the wrappers, migrated to
  `…Ctx(context.Background(), …)`.
- **`marauder.Marauder.ExecLong`** alias for `Exec`. Zero
  callers anywhere in the repo.

After this release, the only remaining `Deprecated:` markers
in the codebase are auto-generated protobuf comments in
`internal/flipper/rpc/pb/*.pb.go`.

## [0.46.0] - 2026-05-09

Panic-recovery hardening sweep across every long-lived
goroutine that processes external input or drives the REPL.
Seven commits, all on the same theme: a panic in any one of
these paths previously crashed the whole CLI; with this
release, every site is wrapped so the panic logs a stack
trace and the surrounding system stays responsive.

### Fixed

- **`marauder.Stream` serial reader** — long-lived goroutine
  parsing untrusted bytes from the ESP32 Marauder. Wrapped in
  `obs.SafeGo`; deferred lock release and channel close still
  fire during panic unwind.
- **`marauder/ble.scan_for_address`** — BLE advertisement
  callback. A panic in the scan handler no longer crashes the
  CLI; the caller's select falls through to the normal scan
  timeout.
- **`hash_crack_dictionary` / `port_scan_tcp` / `http_enum_common`
  producers** — work-distributing goroutines that feed worker
  pools via channels. Wrapped + hoisted `close(ch)` to
  `defer` so a producer panic no longer leaves workers
  blocked in `for range ch` and deadlocks `wg.Wait()` for the
  process lifetime.
- **`crypto1.Mfkey32Fast` racing recovery paths** — both the
  Garcia §4 fast path and the guaranteed fallback are now
  panic-safe. A panic in one path is recovered; the surviving
  goroutine still produces a result and the outer select
  unblocks normally.
- **`rules.DetectorEngine` parallel detectors** — a panicking
  detector now yields a structured `Verdict{VerdictUnknown,
  evidence: "detector panic: ..."}` rather than crashing the
  process or leaving an empty slot. Sibling detectors in the
  same batch keep running. Behaviour pinned by
  `TestDetectorEngine_DetectorPanicYieldsUnknown`.
- **REPL turn dispatcher** — `ai.Run` runs on a goroutine that
  must always send to `turnDone` and call `releaseTurn()` or
  the main select loop deadlocks. Custom inline `defer
  recover()` now fills `turnResult.err` with `"agent panicked:
  …"` so the panic surfaces in the REPL output instead of
  crashing the CLI.
- **REPL `/reconnect`, watch fsnotify pump, watch dispatcher**
  — three more REPL goroutines wrapped in `obs.SafeGo`; same
  defensive contract as the other long-lived goroutines.



Refinement-and-coverage pass on the v0.44 additions plus two
small panic-resilience extensions. Eight commits across three
themes.

### Added

- **`wiegand_decode` hex display + format hint.** The v0.44
  decoder gains two operator-friendly fields: `FacilityCodeHex`
  and `CardNumberHex` are now populated for every result so
  operators cross-referencing a card with hex-printed codes
  don't need to convert by hand. Plus a new `format_hint`
  param: when an operator's capture has noise (leading idle
  bits, trailing pad bytes), they can force a specific bit
  count and get a clear length-mismatch error rather than
  "unsupported bit count". The auto-detect path still works
  when format_hint is 0 or absent. (`internal/tools/wiegand.go`)

- **Richer unsupported-format error message.** Names every
  supported Wiegand format with its identifier (H10301, HID
  Corporate 1000, H10302/H10304) plus actionable guidance
  ("strip leading/trailing pad bits or pass format_hint")
  instead of just listing numeric bit counts.

### Fixed

- **Two more `go func()` → `obs.SafeGo` migrations.**
  - `mcpfed.Initialize` runs `runHealthLoop` per federated
    client; a panic in the watchdog (misbehaving server, JSON
    edge case) no longer crashes the whole agent.
    (`internal/mcpfed/federation.go`)
  - `flipper/transport/ble.go` BLE scan goroutines (one for
    target lookup, one for `--ble-discover`) — a panic from
    the upstream tinygo.org/x/bluetooth library's scan
    callback can no longer take down the agent.
    (`internal/flipper/transport/ble.go`)

  This brings the SafeGo discipline started in v0.42–v0.43
  to every long-lived goroutine in the codebase that wasn't
  already wrapped.

- **`mcpfed` containsFold reduced to a stdlib wrapper.**
  Dropped the hand-rolled equalFoldFast in favour of
  `strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))`.
  Same shape as the cleanups landed for audit_test.go,
  lineedit.go, and discover.go in v0.44.
  (`internal/mcpfed/managed.go`)

### Tested

- **`internal/iclass` public-API parsers.** 9 new tests cover
  both entry points operators use to feed loclass: hex input
  (Proxmark3 dumps, CFW iCLASS sniffer exfils) and binary
  files (sniffer hardware dumps). Includes a regression for
  the documented truncated-record-silently-dropped contract.
  (`internal/iclass/loclass_test.go`)

- **`internal/marauder` response-parsing helpers.**
  parseMarauderResponse and marauderPromptIndex were exercised
  only indirectly through Marauder.Exec. 7 tests pin the
  conditional echo strip, CRLF normalization, blank-line
  drop, empty-input no-op, and only-echo-line edge cases —
  plus a 5-case table for the prompt-offset helper.
  (`internal/marauder/parse_test.go`)

## [0.44.0] - 2026-05-09

New offensive primitive + test-coverage and stdlib-cleanup pass.
Seven commits across three small themes.

### Added

- **`wiegand_decode` tool — offline parser for sniffed
  access-control bitstreams.** Operators sniffing Wiegand reader
  signals (via ESPKey, RPI-RFID-Tool, or a Flipper wired to
  D0/D1) can now paste raw bitstreams and get structured
  (facility code, card number, parity-validity) fields back.
  Supports the four most common formats: 26-bit H10301, 34-bit
  HID standard, 35-bit HID Corporate 1000, 37-bit H10302 /
  H10304. Pure offline parser (Risk.Low, GroupHostTools); no
  Flipper required. Implements the highest-value gap from the
  v0.43 public-research review. (`internal/tools/wiegand.go`)

### Tested

- **`agent.truncatePreview` + `agent.extractBlocked`.** Two
  handoff helpers with no direct coverage despite carrying load-
  bearing behaviour. 6 hermetic tests including a UTF-8
  boundary case for the truncator and the JSON-shape
  discriminator branches in extractBlocked.
  (`internal/agent/handoff_test.go`)

- **`cmd/promptzero/setup.go::resolveConfirmRisk`.** First tests
  for setup.go. 6 cases covering defaults, flag-over-cfg
  precedence, --yolo escape hatch, "none" alias, level-table
  with whitespace/case tolerance, and the unknown-typo error
  path with safe-default fallback. (`cmd/promptzero/setup_test.go`)

### Cleaned up

- **Three hand-rolled stdlib reimplementations replaced.**
  - `internal/audit/audit_test.go` — dropped `contains` and
    `itoa` (used `strings.Contains` and `strconv.Itoa` inline).
  - `cmd/promptzero/lineedit.go` — dropped `hasPrefix` and
    `indexOf` ([]byte versions of stdlib `bytes.HasPrefix` /
    `bytes.Index`); call sites in the bracketed-paste detector
    now use stdlib directly.
  - `cmd/promptzero/discover.go` — dropped the ASCII-only
    `toLower` (now uses `strings.ToLower`) and `divider`
    (`strings.Repeat("-", n)`); `containsFold` body simplified
    via `strings.Contains(strings.ToLower(s), strings.ToLower(sub))`.
    Side benefit: BLE device names containing non-ASCII case
    now case-fold correctly where they didn't before.

  ~75 lines deleted across the three files; no behaviour change
  for the common ASCII paths.

## [0.43.0] - 2026-05-09

Panic-resilience pass. Four commits that close every remaining
"a panic crashes the whole agent" hazard in the request-handling
hot path. With v0.42's SafeGo discipline already covering
long-lived goroutines, this release covers the *synchronous* call
sites: tool dispatch, workflow phases, streaming callbacks, and
the security worker pools.

### Added

- **Tool dispatch recovers panics into structured errors.**
  `agent.dispatch` called `spec.Handler` directly. With 200+
  handlers registered any single nil-deref / parser edge case
  would crash the whole agent. A deferred recover (named-return-
  values pattern) now converts a panic into
  `"tool <name> panicked: <value>"` — the LLM sees a structured
  failure and can react / retry instead of the process exiting.
  (`internal/agent/agent.go`)

- **Workflow phases recover panics into failed-phase results.**
  `workflows.runPhase` called `fn()` directly; a panic in any
  phase (badge_walk, mousejack, garage_door, rolljam, etc.) would
  crash the agent. Now produces a structured failed phase
  (OK=false, Output names the panic, ElapsedMs still populated)
  so the workflow's caller can decide whether to bail or
  continue. Adds the package's first runner_test.go with 3 tests.
  (`internal/workflows/runner.go`)

- **Streaming callbacks recover panics.** The textDelta /
  streamErr / usage callbacks set via SetTextDeltaCallback /
  SetStreamErrorCallback / SetUsageCallback now go through three
  tiny `safeCall*` helpers that catch panics and log a warning
  instead of crashing the agent mid-stream. A buggy operator
  callback no longer takes the process down on a successful API
  call. (`internal/agent/agent.go`)

- **Security worker pools wrapped in obs.SafeGo.**
  `hash_crack_dictionary`, `port_scan_tcp`, and `http_path_scan`
  spawned worker goroutines as raw `go func()`. Each is now
  `obs.SafeGo("tools.<scanner>.worker", ...)` so a panic in any
  worker is recovered + logged with a stack trace. The deferred
  `wg.Done()` inside each func still fires during panic unwind
  so the WaitGroup balance is preserved.
  (`internal/tools/security.go`)

## [0.42.0] - 2026-05-09

Concurrency-safety pass. Seven commits across three cohesive
themes that harden every parallel cracking / scanning goroutine
in the agent.

### Fixed

- **Worker-count upper bounds.** Two cracking surfaces accepted
  unbounded `workers` parameters — an LLM tool call asking for
  `workers=10000` would spawn 10000 goroutines for a CPU-bound
  loop that saturates well below NumCPU. Both now cap at 64
  internally:
  - `hash_crack_dictionary` tool — `maxHashCrackWorkers = 64`
    (`internal/tools/security.go`)
  - `keeloq.BruteForce` library — `maxBruteForceWorkers = 64`,
    clamped at the library entry point so all callers
    inherit the bound. Adds
    TestBruteForceWorkersClampedAboveCap regression.
    (`internal/keeloq/bruteforce.go`)

- **Channel-send deadlocks.** Two scanner workers blocked on
  unguarded sends when the result channel filled up — workers
  couldn't finish, `wg.Wait()` hung, and the tools couldn't even
  be cancelled by the parent context. Both now use
  `select { case ch<-r: case <-ctx.Done(): return }`:
  - `http_path_scan` workers — fired when > 256 paths matched
    a wide wordlist scan (`internal/tools/security.go`)
  - `hash_crack_dictionary` workers — fired when multiple
    workers raced on the same hash before the
    delete-from-remaining landed and surplus duplicates filled
    the buffer. (`internal/tools/security.go`)

- **Raw goroutines wrapped in `obs.SafeGo` for panic recovery.**
  Three sites launched long-lived goroutines as raw `go func()`,
  so a panic in any of them would crash the whole agent
  process even though the work was non-essential:
  - `agent.maybeGenerateTitleLocked` — sidebar title
    generation, called once per session-save. A nil pointer in
    an SDK response would take down the agent.
    (`internal/agent/session.go`)
  - `web.handleScreenAcquire` — `streamFrames` +
    `heartbeatScreen` for the screen-mirror UI. An RPC frame
    decode panic would crash the web server (taking down every
    WebSocket client) just because one operator viewed the
    Flipper screen. (`internal/web/api_screen.go`)
  - `tools/mifare` — three crypto1 brute-force tools
    (`mfoc_attack`, `mfcuk_attack`, `mfkey32_recover`).
    (`internal/tools/mifare.go`)

  Each SafeGo call gets a descriptive name so the recovery log
  identifies the panic site without a full stack walk.

## [0.41.0] - 2026-05-09

Three small cohesive themes across seven commits: finishing the
v0.40 UTF-8-truncation pass, eliminating same-second collisions
in time-based ID generation, and bounding LLM-supplied limit
parameters on the audit / corpora / targetmem read paths.

### Fixed

- **3 more byte-index truncation sites walk back from UTF-8
  boundaries** — `report.shortEvidence` (verdict-evidence cell
  in /report), and two excerpt truncations in
  `validator/evilportal.go`. Same `b&0xC0 == 0x80` discipline
  as v0.40's clipTitle / capSize / audit.RecordCtx /
  verifyPayload. (`internal/report/report.go`,
  `internal/validator/evilportal.go`)

- **`generate.NewEvilPortal` html cap routes through capSize.**
  Was an inline `html[:20000]` slice; now delegates to the
  package's UTF-8-aware capSize helper from v0.40.
  (`internal/generate/generate.go`)

- **Session IDs use UnixNano so quick rotations don't collide.**
  Three sites generated session IDs as `session-<unix-seconds>`:
  `agent.SetSessionStore`, `agent.NewSession`, `audit.Open`. Two
  consecutive `NewSession()` calls in the same wall-clock second
  produced the same ID; since session.Save uses the ID as the
  filesystem path component, the second session would overwrite
  the first on disk. Same shape on the audit-log side.
  Switched all three to `UnixNano`. New regression test runs 50
  rapid `NewSession()` calls and asserts every ID is unique.
  (`internal/agent/session.go`, `internal/audit/audit.go`)

- **Workflow capture filenames use UnixNano.** Same fix shape
  in two more sites: `rolljam` press1/press2 SD captures and
  `garage_door` per-frequency triage captures. Two rapid runs
  in the same second would otherwise overwrite each other's
  saved data on the SD card.
  (`internal/workflows/rolljam.go`, `internal/workflows/garage_door.go`)

- **`audit_query` LLM-callable tool now caps `limit` at
  `MaxQueryLimit`.** REPL slash commands already capped at
  10000 to keep an operator typo from flooding SQLite, but the
  LLM-callable tool path didn't — `limit=999999` would load the
  whole audit DB into the tool-result block. Promoted
  `MaxQueryLimit` to an exported `internal/audit` constant; both
  surfaces now share it. (`internal/tools/audit.go`,
  `internal/audit/audit.go`)

- **Three corpora-search tools cap their `limit` param.**
  `ir_irdb_lookup`, `evil_portal_template_pick`, and
  `badusb_payload_search` accepted unbounded limits — an LLM
  call with `limit=1000000` would walk the entire operator
  corpus and serialise a multi-MB JSON. New
  `corpusMaxResults = 1000` constant + centralised
  `clampCorpusLimit` helper. (`internal/tools/corpora.go`)

- **`targetmem.Store.Recent(n)` caps at `MaxRecent`.** Clamping
  inside the Store so both REPL and tool paths inherit the
  bound without per-callsite duplication. New regression test
  seeds MaxRecent+5 rows + asks for 999999 + asserts the
  result length is exactly MaxRecent.
  (`internal/targetmem/targetmem.go`)

## [0.40.0] - 2026-05-09

UTF-8 + escape-sequence safety pass. Six commits, two themes:

1. Every `[:n]` byte-index truncation site in the codebase now
   walks back from UTF-8 continuation bytes so the output stays
   valid UTF-8 even when a multi-byte rune lands at the boundary.
2. The quarantine sanitiser now strips C1 escape-sequence bodies
   (OSC / DCS / PM / APC / SOS), not just the leading ESC byte.

### Fixed

- **Quarantine: OSC/DCS/PM/APC/SOS bodies were leaking through.**
  `sanitizeControlChars` stripped CSI escapes (`ESC [` colour /
  cursor sequences) and lone ESC bytes via the catch-all
  `otherControlsRE`, but the body of an OSC sequence
  (`ESC ] 0;<title>BEL`) would survive as readable text. Risks:
  attacker-controlled SSIDs, NFC tag URIs, or NDEF records
  flowing through quarantine could embed terminal-title-set or
  hyperlink payloads (OSC 8). Added `ansiC1RE` matching
  `ESC [\]PX^_]<body>(BEL|ST)` — runs before the byte stripper
  so the leading ESC is still present when the regex sees it.
  8 sub-cases pin the contract: title-set, hyperlink, DCS, APC,
  PM, SOS, unterminated fallback, mixed CSI+OSC.
  (`internal/agent/quarantine.go`)

- **`session.clipTitle` truncation split multi-byte runes.**
  Sliced sidebar titles by byte index, so a title with a
  multi-byte rune at the boundary produced invalid UTF-8 (renders
  as U+FFFD or drops the fragment in the operator's sidebar).
  Now walks back while the byte at the cut is a continuation
  byte (`b&0xC0 == 0x80`). ASCII inputs cut at exactly the cap.
  Mirrors the discipline already in `agent.truncateExcerpt`.
  (`internal/agent/session.go`)

- **`generate.capSize` truncation split multi-byte runes.**
  Bounds runaway LLM-generated content (DuckyScript payloads,
  captive-portal HTML) before it gets written to the Flipper.
  Same byte-level slice as clipTitle; same fix.
  (`internal/generate/generate.go`)

- **`audit.RecordCtx` output truncation split multi-byte runes.**
  Tool output > 65535 bytes was truncated by byte; if the cut
  landed on a multi-byte rune the stored audit row was invalid
  UTF-8 — the web UI / `/report` renderer would show U+FFFD or
  reject the row. (`internal/audit/audit.go`)

- **`agent.verifyPayload` input truncation split multi-byte
  runes.** 4000-byte cap on content sent to the LLM verifier;
  half-runes leaked into the verifier prompt. Refactored into a
  testable `truncateForVerifier` helper with the same walk-back.
  (`internal/agent/verify.go`)

### Tested

- **`config.Load` got its first 6 unit tests** — defaults when
  file missing, YAML parsing, malformed-YAML rejection,
  `~/.promptzero/config.yaml` fallback, env-var override
  (ANTHROPIC/OPENAI/WEB_TOKEN), and `RequireAPIKey`. The Load
  function is on every startup path but had zero direct
  coverage. (`internal/config/config_test.go`)

- **Each of the four UTF-8 truncation fixes adds a dedicated
  regression test** — places "é" (0xc3 0xa9) so that a natural
  byte-index cut would land on the continuation byte 0xa9 and
  asserts `utf8.ValidString(got)` plus the documented
  walk-back behaviour. ASCII paths pass byte-for-byte unchanged.

## [0.39.0] - 2026-05-09

Bug-fix + validator + test-coverage release. Headline is a real
operator-impacting bug in `/discover apps`; everything else
hardens or extends what v0.38.0 already shipped.

### Fixed

- **`/discover apps` returned no FAPs and garbage signal-file
  names.** Two parser bugs in `discover.ScanApps`:
  1. The FAP-scan branch matched `HasSuffix(line, ".fap")`, but
     `StorageList` output is `\t[F] mfkey32.fap 12345b` — every
     line ends in `<size>b`, never `.fap`. Result: zero FAPs
     ever returned, regardless of what was on the SD card.
  2. The signal-scan branch grabbed the whole trimmed line as
     the App.Name field, so a Sub-GHz capture appeared as
     `Name="[F] capture.sub 4096b"` and the constructed Path was
     also broken.

  Adds `parseStorageListFile` with quote-aware tail-stripping (a
  filename ending in literal "b" or containing internal spaces
  survives the strip) and 11 regression cases pinning every
  branch. (`internal/discover/discover.go`)

- **`mcpfed.ClientConfig.resolveEnv` returned non-deterministic
  child env.** Iterated `c.Env` via map randomisation, so the
  `[]string` passed to `exec.Cmd.Env` for spawned MCP child
  processes came out in a different order every call. Visible
  in `ps` listings; would defeat any future test asserting
  child env shape. Sorts keys alphabetically — same pattern
  applied to `containerbridge.buildDockerArgs` in v0.38.
  (`internal/mcpfed/config.go`)

- **`discover.ScanApps` returned non-deterministic slice.** The
  signal-library scan iterated a `map[string]string` of
  directory→type pairs, so even after FormatApps's
  alphabetical-by-Type sort the *raw* slice was shuffled each
  call. Replaced with an explicit alphabetical-by-type slice.
  (`internal/discover/discover.go`)

- **Two confirm-prompt sites in agent.go silently swallowed
  marshal errors.** `RunTool`'s confirm gate and
  `workflowConfirmHook` used `_ := json.Marshal(...)` so a
  non-marshalable param made the operator approve a black box.
  Now both warn via `obs.Default()` and substitute a
  `{"_marshal_error":"..."}` placeholder so the prompt always
  shows what's happening. (`internal/agent/agent.go`)

### Added

- **5 new BadUSB validator rules covering persistence + deeper
  credential-dump techniques** — extends the v0.37 catalogue:
  - `reg_save_sam_hive` (T1003.002): `reg save HKLM\\SAM` and
    paired SYSTEM / SECURITY hives (offline SAM cracking).
  - `net_user_add` (T1136.001): local backup-account creation.
  - `net_localgroup_admin` (T1078.003): privilege escalation
    via `net localgroup administrators <name> /add`.
  - `ssh_authorized_keys_append` (T1098.004): `>> ~/.ssh/
    authorized_keys` Linux SSH backdoor.
  - `sudoers_nopasswd_append` (T1548.003): `NOPASSWD:ALL`
    line in any context.

  Each rule is tagged with its MITRE technique ID in the
  operator-facing message. (`internal/validator/badusb.go`)

### Tested

- **`cost.Tracker` budget API** got its first 6 unit tests:
  no-budget passthrough, at-cap and above-cap detection, the
  once-only warn/hit fire-and-don't-re-fire contract,
  raising-resets-flags / lowering-doesn't-reset, and the
  `SetBudget(0)` disable path. The budget gate is checked at
  the top of every agent turn — running it through unit tests
  removed the only load-bearing surface that had no direct
  coverage. (`internal/cost/cost_test.go`)

- **`cmd/promptzero/discover.go` pure helpers** — 7 tests for
  `pickFlipperCandidate`, `containsFold`, `toLower`, `truncate`,
  `divider`. (`cmd/promptzero/discover_test.go`)

## [0.38.0] - 2026-05-08

Defensive correctness pass — three cohesive themes across nine
commits: HTTP response-body size caps on every operator-configurable
client, deterministic output on two map-iteration sites, and stack
traces on every `recover()` site in production code.

### Added

- **`obs.SafeGo`-style stack traces on every panic-recovery site.**
  v0.37.0 already added `runtime/debug.Stack()` to `obs.SafeGo`'s
  recovery log; v0.38 extends that discipline to the other three
  recover() sites in production code:
  - `audit.notify` — observer fanout. A buggy webhook / rules-engine
    observer now shows the panic frame in the log line; a new
    `TestObserverPanicDoesNotCrashRecord` pins the recover guard.
  - `runShutdownHooks` — first-ever `signals_test.go` covers both
    panic-doesn't-block-siblings and the 2 s per-hook timeout.
  - `eval.runOne` — scenario panics in the golden-evaluation
    harness now carry the stack in `Result.Err`.

  No API changes; every existing call site benefits automatically.
  (`internal/audit/audit.go`, `cmd/promptzero/signals.go`,
  `internal/eval/eval.go`)

### Fixed

- **HTTP response-body size caps on all four operator-configurable
  clients.** Each client previously used unbounded `io.ReadAll`,
  so a misconfigured `baseURL` / `whisperURL` / Flipper bridge
  pointing at a file server, paginated debug endpoint, or 5xx CDN
  page would buffer the entire body in memory. The agent's OOM
  vector dropped to zero with these four changes:
  - `internal/provider`: 16 MiB cap on Ollama + OpenAI-compat
    clients (with the package's first 8 tests).
  - `internal/voice`: 4 MiB cap on the Whisper transcription
    client.
  - `internal/flipper/transport/http.go`: 16 MiB cap on the
    UART-over-HTTP recv body, plus 8 KiB cap on the
    error-message body that `snippet()` was already truncating
    to 256 bytes anyway.

  Each fix has a regression test that streams oversized data
  through a stub server and asserts the cap fires with a clear
  "exceeded N-byte cap" error rather than a half-buffered JSON
  parse failure.

- **Deterministic output where Go's randomised map iteration
  was leaking through.** Two sites where the operator could see
  shuffled output run-to-run:
  - `discover.FormatApps` — section order shuffled because
    `range groups` iterated a `map[string][]App` directly. Fixed
    by sorting type keys; preserves entry order within each
    group. Adds the package's first 4 tests, including a 50-run
    determinism check.
  - `containerbridge.Run` — docker `-e KEY=VAL` flags came out in
    a different order every call, visible in `ps`/audit logs.
    Refactored argv construction into a private
    `buildDockerArgs` helper, sorted env keys, added 3 new
    tests (50-run determinism + safe-default --network none +
    full-feature wire-format pin).

### Tested

- 8 new tests in `internal/provider` (was zero) covering Ollama
  + OpenAI-compat happy paths, error responses, response-size
  cap, default base URL/model, OpenRouter constructor, and the
  size-cap floor.
- First test files for `internal/discover` (4 tests) and
  `cmd/promptzero/signals.go` (2 tests).
- New regression tests in `internal/audit` (1),
  `internal/voice` (1), `internal/flipper/transport` (1),
  `internal/containerbridge` (3), `internal/eval` (extends
  existing).

## [0.37.0] - 2026-05-08

Resilience + observability pass with new safety-rail rules. Two
new BadUSB validator rule families (defense evasion + credential
dumping), tolerant judge-output parsing, panic-recovery stack
traces, plus four "one bad row shouldn't break the whole listing"
fixes across the persona / session / snapshot / audit paths.

### Added

- **8 new BadUSB validator rules.** Defense evasion: `wevtutil cl`
  (Windows event-log clear, T1070.001), `Clear-EventLog` (same),
  `iptables -F` and `ufw disable` (Linux firewall flush, T1562.004).
  Obfuscation: `powershell -EncodedCommand` (T1027/T1059.001 — the
  base64-obfuscated payload pattern that's everywhere in real-world
  BadUSB scripts). Credential dumping: `sekurlsa::logonpasswords`
  (T1003.001) and `lsadump::dcsync` (T1003.006). Each rule is
  tagged with its MITRE technique ID in the user-facing message
  so the report is operator-readable.
  (`internal/validator/badusb.go`)

- **`obs.SafeGo` includes a stack trace in panic-recovery logs.**
  Every long-lived goroutine in PromptZero (rules dispatch, agent
  callbacks, ws.writer + ws.heartbeat, MCP federation, etc.) was
  already wrapped in SafeGo for crash safety, but the recovery log
  carried only the goroutine name and the recovered value — no
  stack — so debugging a real panic meant re-running with
  `GOTRACEBACK=all`. Now the log line carries `runtime/debug.Stack()`
  under the `stack` key. No API change; every call site picks up
  the new behaviour automatically. (`internal/obs/safego.go`)

### Fixed

- **`rules.parseVerdict` tolerates prose-wrapped JSON.** LLM judges
  sometimes return `Based on the output: {...}\n\nReasoning: ...`
  — valid JSON wrapped in prose. The strict json.Unmarshal call
  rejected the whole blob and the verdict downgraded to Unknown,
  losing the actual judgement. Now falls back to a quote-aware
  brace-balance scan that extracts the first `{...}` block and
  retries. Pure-prose responses (no object at all) still fall
  through to Unknown — existing TestLLMDetector_NonJSONFallsBack
  remains green. (`internal/rules/detector.go`)

- **`persona.LoadDir` doesn't lose siblings on one bad YAML.**
  Returned on first error, so a single malformed file in
  ~/.promptzero/personas/ silently disabled every other valid
  persona — operator's --persona switch would just stop finding
  profiles they knew they wrote. Now logs via `obs.Default().Warn`
  with the filename and underlying error, then continues to the
  next file. (`internal/persona/persona.go`)

- **`session.Store.List` logs failed loads.** Silently dropped any
  session whose Load failed, so a corrupt JSON file disappeared
  from /session list with no signal. Now per-file failures are
  logged via `obs.Default().Warn`; the skip behaviour is unchanged.
  Existing TestStore_List_SkipsCorruptEntry still passes.
  (`internal/session/session.go`)

- **`snapshot.Manager.List` logs corrupt meta files.** Skipped
  unreadable / unparseable .json meta files so a single corrupt
  row didn't break /rewind listing — but operators looking for
  why a snapshot they created was missing had no log line to point
  at the on-disk-but-broken file. Now both branches emit
  `obs.Default().Warn` with session_id + filename before
  continuing. (`internal/snapshot/snapshot.go`)

- **CI hotfix: gofmt detector_test.go.** Three CI runs failed in
  succession on a single comment-alignment issue I introduced in
  v0.37.0's tolerant-JSON test. Fixed via gofmt; root cause was
  that local validation was `go test` + `go vet` only, neither of
  which catches gofmt. Saved as a feedback memory so future loop
  iterations always run `task lint` before pushing.
  (`internal/rules/detector_test.go`)

### Tested

- **Coverage for `cmd/promptzero/upgrade.go` helpers.** Added 7
  hermetic unit tests for the security-load-bearing functions
  the upgrade path leans on (`normaliseTag`, `lookupChecksum`,
  `sha256File`, `extractTarGzEntry`), including zip-slip guards
  on absolute paths and `..` traversal. The helpers had no test
  coverage despite controlling what binary replaces the running
  one. (`cmd/promptzero/upgrade_test.go`)

- **Coverage for `workflows/mousejack.go`.** Was the only
  workflow without a *_test.go file. Adds four tests covering
  both refusal branches (nil Flipper, missing name, missing
  script) and the launch-false happy path that builds + writes
  the payload without launching the FAP.
  (`internal/workflows/mousejack_test.go`)

## [0.36.0] - 2026-05-08

Observability discipline pass — five small fixes that turn silent
error handling in the audit, snapshot, agent, and target-memory
paths into warn-and-recover. None change behaviour for the happy
path; they make corrupted inputs visible instead of vanishing.

### Fixed

- **`audit.RecordCtx` logs + recovers from input-marshal failures.**
  An unmarshallable tool input (channel, function, NaN, circular
  ref) used to produce an audit row with empty `input` and no
  signal. Now warns via `obs.Default()` and writes a
  `{"_marshal_error":"…"}` placeholder so the row stays parseable.
  (`internal/audit/audit.go`)

- **`audit.QuerySince` logs scan failures.** Every other audit
  query site (`Query`, `QueryBySession`, `QueryFiltered`,
  `TopTools`, `TopRisks`) emitted a warn before continuing past a
  bad row. `QuerySince` — which feeds the `/audit tail` live
  stream and the rules engine — silently dropped them. Now
  consistent. (`internal/audit/audit.go`)

- **`snapshot.Restore` validates the snapshot id.** Restore
  accepted any string and concatenated it into a filesystem path,
  so a caller bug or a malicious id (`../etc/passwd`,
  `..\\..\\foo`) could escape the snapshot directory. Now uses
  the same allow-list regex as `session` — letters, digits, `_`,
  `-`, `.`, max 128 chars, no path separators. Returns a typed
  error with the offending id quoted.
  (`internal/snapshot/snapshot.go`)

- **`agent.buildDeviceStateBlock` logs marshal failures.** When
  the device state block's `json.Marshal` failed it returned `""`
  silently, dropping the device-context preamble for that turn
  with no signal. Now warns via `obs.Default()` before falling
  back to empty. (`internal/agent/state_prompt.go`)

- **`targetmem` Lookup/Recent log facts-unmarshal failures.**
  Both sites silently swallowed `json.Unmarshal` errors on the
  `facts` column, so a corrupt or schema-incompatible row would
  return a `Target` with `Facts=nil` and no signal. Now logs via
  `obs.Default().Warn` with the row's identifier+kind+caller while
  still returning the row intact, so a single bad row doesn't
  break the whole listing. (`internal/targetmem/targetmem.go`)

## [0.35.0] - 2026-05-08

Startup-validation polish. Two bounded fixes that close silent
fallbacks in the persona and budget config paths.

### Fixed

- **Persona's typo'd `default_risk_threshold` produces a startup
  warning.** `resolveConfirmRisk` returns an error for unknown risk
  levels, but `setupRiskGate` silently dropped that error for the
  persona path. An operator typing `default_risk_threshold: critcal`
  (typo) got the global default with no signal. Now surfaced via
  `statusWarn` naming the persona and the bad value.
  (`cmd/promptzero/setup.go`)

- **Negative `--budget` / `cost.budget_usd` produces a startup
  warning.** Old code's `if flagBudget > 0` check let a negative
  value fall through silently — operator typing `--budget=-50`
  (typo) expected a $50 cap and got "no budget configured". Both
  flag and cfg fields now validate up front: negative values warn
  and clamp to 0 (which the existing `usdCap <= 0` check treats as
  "no budget"). (`cmd/promptzero/setup.go`)

## [0.34.0] - 2026-05-08

Web budget visibility + REPL guardrails. Three small, bounded
changes that close UX gaps the recent /budget + /audit work
exposed.

### Added

- **`/api/cost` surfaces a budget block when configured.** The
  endpoint exposed total + by_model + offline but had no way for
  the frontend to render the budget bar that the `/cost` CLI
  shows. New optional `budget` block with `cap_usd`, `spent_usd`,
  `remaining_usd` (clamped ≥0), and `percent`. Omitted entirely
  when no cap is set so the frontend can render "budget: disabled"
  without disambiguating 0/0 from genuine pre-spend state.
  (`internal/web/api.go`)

### Fixed

- **`/history` and `/audit query` capped at 10000 rows.** Old
  behaviour trusted any positive integer — `/audit query 1000000`
  (typo or stress test) could tie up SQLite for seconds and flood
  the terminal. Soft-cap with a one-line dim notice when clamped;
  default of 20 (when N≤0 or omitted) unchanged. Mirrors the
  v0.26 cap on `/audit find limit=`. (`cmd/promptzero/commands.go`)

### Changed

- **Closed stale `TODO(v0.5.1 risk-review)` marker.** The mfoc /
  mfcuk / mfkey32 risk classification was already encoded in the
  surrounding comment ("High because recovered keys enable
  cloning"); the open TODO suggested unfinished work where there
  was none. Replaced with a "review concluded" note referencing
  the rationale. (`internal/risk/risk.go`)

## [0.33.0] - 2026-05-08

Defensive correctness wave. Two bounded fixes that close
data-integrity gaps reachable from buggy callers or unauthenticated
paths.

### Security

- **`snapshot.Manager` rejects path-traversal session IDs.** Mirrors
  v0.26's session-store fix. `Store`, `List`, `Restore`, and `Purge`
  used the sessionID directly in `filepath.Join` with no
  sanitisation. The agent's auto-generated IDs are safe by
  construction and v0.26 added validation to `session.Store`, but
  the snapshot layer is reachable from any caller (mcpfed, /rewind,
  future features) — defence in depth requires the boundary check
  here too. Same allow-list:
  `^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`. Tests cover 8 hostile
  inputs across the 4 entry points (32 assertions).
  (`internal/snapshot/snapshot.go`)

### Fixed

- **`cost.AddUsageFull` clamps negative token deltas.** The original
  guard only no-op'd when ALL four counters were ≤0 — a mixed call
  like `(-1000, 50, 0, 0)` would decrement input tokens while
  incrementing outputs, corrupting both the running totals and the
  budget tracking they feed. Each component is now clamped to 0
  individually before the all-zero check; valid (non-negative)
  inputs are unchanged. (`internal/cost/cost.go`)

## [0.32.0] - 2026-05-08

Watcher polish + CI follow-through on the v0.31 toolchain bump.

### Fixed

- **Watch rules warn at startup when `persona:` references an unknown
  name.** A typo'd persona name silently no-op'd at fire time —
  the rule still fired but with the active persona, not the
  intended one. Operator never saw a signal that the typo was the
  reason their watch trigger wasn't switching modes. Now warned at
  startup alongside the existing pattern check; soft-fail preserved
  (the rule still fires) so a typo in one rule doesn't strand the
  others. (`cmd/promptzero/repl.go`)

### Build

- **CI pins Go to 1.25.10 across all workflows.** The `1.25`
  shorthand resolves to whatever's cached on the runner — today
  that's 1.25.9, which carries the CVEs cleared in v0.31.0. The
  go.mod toolchain directive can't help here: setup-go sets
  `GOTOOLCHAIN=local`, forcing the local Go regardless of the
  directive. Pinned ci, codeql, release, and coverage-diff to the
  specific patch so setup-go pulls 1.25.10 explicitly. As future
  patch releases land we bump the pin.
  (`.github/workflows/{ci,codeql,release,coverage-diff}.yaml`)

## [0.31.0] - 2026-05-08

Webhook delivery semantics fixed end-to-end. The rules engine's
`webhook:` action now actually delivers to the named subscription;
docs no longer ship example event names that fail v0.27's
validation. Also bumps the Go toolchain + `golang.org/x/net` to
clear four CVEs flagged by govulncheck on the release CI run.

### Security

- **Bumped Go toolchain to 1.25.10 + `golang.org/x/net` to v0.53.0.**
  govulncheck flagged four pre-existing CVEs whose disclosure
  landed since the last CI run: GO-2026-4982 / GO-2026-4980
  (`html/template` XSS bypasses), GO-2026-4971 (`net.Dial` NUL-byte
  panic on Windows), GO-2026-4918 (HTTP/2 infinite loop on bad
  SETTINGS frame). All four fixed by the version bumps; no
  source-level changes required.

### Fixed

- **Rule webhook actions deliver to the named subscription.** Real
  semantic bug. A rule's `webhook: ops-pager` action used to cast
  the name to `Event("ops-pager")` and run through the Events
  allowlist filter — ops-pager didn't receive (Events mismatch);
  permissive subscriptions received unrelated rule fires. Combined
  with v0.27's event-name validation (rejects unknown events), the
  operator could not configure a working rule webhook without
  bypassing the validator. Added `Dispatcher.FireByName(name,
  payload)` that targets exactly the named subscription, bypasses
  the Events filter, and stamps the envelope as `event=rule_fired`.
  `setupRules` now uses `FireByName`; `EventRuleFired` is in
  `knownEvents` so subscriptions can opt-in to receive only
  rule-driven payloads. (`internal/webhook/webhook.go`,
  `cmd/promptzero/setup.go`)

### Documentation

- **Example config files use canonical event names.** Both
  `config.example.yaml` and `examples/config.yaml` listed
  `events: ["risk.exceeded", "tool.completed"]` — neither match any
  real `Event` constant; both would fail v0.27 validation. Updated
  to `audit_critical` / `tool_finished` and added a comment block
  enumerating the full allowlist plus the new `rule_fired` event.

## [0.30.0] - 2026-05-08

Config-load validation tail. Three bounded fixes that close
silent-misconfiguration gaps in `/export` and the rules engine.

### Fixed

- **`/export training-set` validates options before truncating the
  destination.** Old code opened the path with
  `O_CREATE|O_TRUNC` then called `Export` which rejected unknown
  formats. An invalid `--format=` or `--min-level=` zero'd a valid
  pre-existing file before the error fired. New
  `trainset.ValidateOptions` runs the format/min-level allowlist
  check without filesystem touch; `handleExport` calls it ahead of
  the file open. (`internal/trainset/trainset.go`,
  `cmd/promptzero/commands.go`)

- **Rule engine `buildRule` rejects unknown action types.** A YAML
  typo like `type: webhok` was passed through to `Engine.fire` which
  only logged at warn the first time the rule matched an audit
  event — could be hours after startup. Now restricts
  `Action.Type` to `webhook|log|tool` at config load with a specific
  error citing the bad value and the allowed list.
  (`cmd/promptzero/commands.go`)

- **Rule engine `buildRule` requires kind-specific fields.**
  Validating the type wasn't enough: `type: webhook` with no
  `webhook:` field would fire `WebhookFire("", payload)`, which
  most dispatchers silently drop. Same for `type: tool` with no
  `tool:` field. Each kind now has its own required-field check
  with a specific error pointing at the missing key. Log type
  still allows empty fields (message templated from params).
  (`cmd/promptzero/commands.go`)

## [0.29.0] - 2026-05-08

Observability hardening wave. Four bounded fixes that turn silent
JSON marshal/encode failures into warn-level logs so misbehaving
callers stop disappearing into the void.

### Fixed

- **`web.respondJSON` logs encode failures.** The doc comment claimed
  marshalling failures "log on the server" but the code did
  `_ = json.NewEncoder(w).Encode(body)`. A handler that accidentally
  passed a non-encodable type would write headers, fail to write the
  body, and leave operators with a half-written response and no
  server-side breadcrumb. (`internal/web/api.go`)

- **`web.broadcast` and `web.sendTo` log marshal failures.** Both
  silently returned on `json.Marshal` errors, so a non-encodable
  payload disappeared with no signal — web UI showed nothing, the
  agent saw success, the operator had no trace. Now logs at warn
  with the top-level keys (avoiding dumping the full body which
  could be huge or secret-bearing). The intentional queue-overflow
  drop in `enqueue` is unchanged. (`internal/web/server.go`)

- **`HandoffArtifact.WithDeviceState` logs marshal failures.** The
  builder method silently dropped `DeviceStateAtCompact` on marshal
  errors, so `/session resume` would lose device state context with
  no signal — caller couldn't tell empty-by-design from
  marshal-failure. (`internal/agent/handoff.go`)

- **`toolUseInputJSON` logs marshal failures.** Returning nil on
  failure is the documented graceful behaviour for the session-save
  helper, but operators reviewing `/sessions` later had no way to
  tell whether a tool call's Input field was empty by design or
  dropped during marshal. Now logs the tool name + tool_use ID so
  the saved-session reviewer has a thread to pull.
  (`internal/agent/session.go`)

## [0.28.0] - 2026-05-08

REPL ergonomics + parser correctness wave. Four bounded fixes that
catch operator typos earlier and harden two latent display/query
bugs.

### Fixed

- **Typo'd slash commands no longer forwarded to Claude.** A line
  like `/budgett` (typo of `/budget`) used to fall through the
  dispatcher and get sent verbatim to Claude as a regular prompt —
  the model would dutifully try to interpret the broken command,
  burning a turn for no value. The dispatcher now catches anything
  shaped like `/<letters>` with a clear "unknown command — type
  /help" hint. A discriminator preserves pass-through for incidental
  leading slashes like `/dev/sda`, `/2 of these`, `/budget-cap`.
  (`cmd/promptzero/commands.go`)

- **`/audit find limit=` capped at 10000 rows.** Old behaviour
  accepted any positive int — `limit=1000000` (typo or stress test)
  tied up SQLite for seconds and flooded the terminal with rows the
  human would never read. Default of 100 unchanged when omitted;
  operators wanting more should `offset=` paginate.
  (`cmd/promptzero/commands.go`)

- **`parseWhen` rejects negative durations.** Go's `time.ParseDuration`
  accepts `-30m` as valid; the old code computed `time.Now() - (-30m)
  = future timestamp`. `/audit find since=-30m` then matched no past
  audit rows because the SQL clause was `timestamp >= <future>` —
  silent zero-row response with no signal that the input had no
  sensible meaning. Now errors with the correct shape.
  (`cmd/promptzero/commands.go`)

- **`formatPreviewValue` truncation is UTF-8-safe.** The high-risk
  confirmation preview clipped long input/output values with naive
  byte-slicing (`s[:69]`). A multi-byte rune (emoji, accented
  character) straddling the cut produced invalid UTF-8 — the
  terminal renders that as U+FFFD. New `truncDisplay` helper counts
  runes and only cuts at rune boundaries. Tests verify with
  `utf8.ValidString` so future regressions to byte-slicing are
  caught. (`internal/agent/confirm_preview.go`)

## [0.27.0] - 2026-05-07

Continuation of the validation hardening wave: every remaining
config-load DSL gets stricter parsing, plus defensive thread-safety
on a registry that's read from HTTP handler goroutines.

### Fixed

- **Campaign `step.timeout` validated at parse time.** The Runner's
  `time.ParseDuration` check at execution time silently fell back to
  no-timeout when the value couldn't parse — `timeout: 30 seconds`
  (English instead of Go syntax) produced unbounded execution with no
  warning. Fourth pass in `ParseYAML` now requires a positive Go
  duration. (`internal/campaign/campaign.go`)

- **Watcher rule patterns validated at startup.** A malformed pattern
  (e.g. `*[a.sub` with unmatched bracket) made `filepath.Match`
  return `ErrBadPattern` at runtime, which the watcher's matcher
  silently swallowed as no-match. Operators saw "watcher running"
  and "no events fired" with no signal that their pattern was the
  problem. New `watch.ValidatePattern`; `startWatch` skips malformed
  rules with a yellow warning so one bad rule doesn't strand the rest.
  (`internal/watch/watch.go`, `cmd/promptzero/repl.go`)

- **Webhook `ValidateSubscription` rejects unknown event names.** The
  events filter accepted any string from YAML — a typo like
  `tool_finsished` or wrong case like `TOOL_FINISHED` registered the
  subscription but never delivered. Validation now restricts to the 7
  canonical event names with a specific error listing the allowed set.
  Empty `events:` still means all-events. (`internal/webhook/webhook.go`)

### Changed

- **Persona `Registry` is goroutine-safe.** `byName` was a plain map
  with no synchronisation. Production reads from REPL + HTTP handler
  goroutines; today the happens-before is established by spawn order
  alone, but the new `sync.RWMutex` is defensive against a future
  hot-reload feature where Load could fire concurrently. Get/Names
  take RLock, Load takes Lock. New race-detector test covers the
  contract. (`internal/persona/persona.go`)

## [0.26.0] - 2026-05-07

Validation hardening wave. Every operator-facing DSL gets stricter
parsing so typos and traversal attempts fail loudly at parse time
instead of producing silent zero-row queries or escaping the session
directory. Web `/api/rules` now exposes the cooldown surface the
DTO already declared.

### Security

- **Session-store path-traversal protection.** `Store.Save/Load/Delete`
  used the session id directly in `filepath.Join` with no
  sanitisation. An id like `../etc/passwd` or `foo/bar` would
  resolve outside the session directory — a `/save "../../some/path"`
  from the REPL or a malformed `Load(id)` could read/write under a
  parent dir. Each entry point now validates against a strict
  allow-list (`[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}`) before touching
  the filesystem. The agent's auto-generated `session-NNN` ids
  match the pattern so no caller needs to change.
  (`internal/session/session.go`)

### Fixed

- **`/audit find risk=` validates and case-normalises.** Typos
  (`risk=danger`) and case mismatches (`risk=CRITICAL` against
  SQLite's lowercase-stored values) used to silently match zero
  rows. The parser now restricts to `low|medium|high|critical`
  (case-insensitive) and rejects anything else with the allowed
  list. (`cmd/promptzero/commands.go`)

- **`/attack set` validates the technique-id format.** Old behaviour
  passed args verbatim — `t1557`, `T155`, `BogusID` silently
  filtered every tool out so the operator's session was effectively
  gated to nothing. The new normaliser uppercases, trims whitespace,
  drops empty entries, and rejects anything that doesn't match the
  canonical `T####` or `T####.###` MITRE format.
  (`cmd/promptzero/commands.go`)

- **Web `/api/rules` populates `cooldown_remaining_ms`.** The DTO
  declared the field but the handler never wrote to it — every
  response carried 0 regardless of cooldown state. The web Cockpit
  now sees `cooldown - (now - lastFire)` for each rule with a
  non-zero cooldown that has fired at least once. Required adding
  `Cooldown` to `rules.Snapshot` (was internal to `Engine` only).
  (`internal/rules/rules.go`, `internal/web/api.go`)

### Added

- **`/rules` list shows last-fire recency.** Operators looking for
  "which rules are stale" / "did this rule fire after I deployed
  it" had no signal short of `/audit query` and pattern-matching
  the detector-verdict blocks. Each line now ends with `, last
  <duration> ago` when the rule has fired at least once. The
  `humanSince` helper truncates to a single unit (s/m/h/d) so
  the line stays compact even for high-fire rules.
  (`cmd/promptzero/commands.go`)

## [0.25.0] - 2026-05-07

Ergonomics + observability wave. Five hour-bounded fixes that land
on real-world operator complaints: the `/audit find` swap-trap, the
watcher missing files due to case mismatch, browser/editor temp
files dispatching as if they were content, multi-line output
corrupting markdown reports, and SQL scan errors going silent.

### Fixed

- **`/audit find` rejects swapped `since`/`until`.** since=1h means
  "1 hour ago"; until=24h means "24 hours ago". The naïve
  operator order silently produced a SQL clause that always
  returned 0 rows (`timestamp >= since AND timestamp <= until`,
  impossible when swapped). The parser now surfaces the swap with
  a specific error pointing at the bad bounds.
  (`cmd/promptzero/commands.go`)

- **Watcher pattern match is case-insensitive.** `Capture.SUB`
  silently slipped past `*.sub`. Default rules ship lowercase but
  files dropped from browsers, third-party tools, or some Flipper
  CFW SD-card writers carry mixed case. `match()` now lowercases
  both pattern and basename before comparing.
  (`internal/watch/watch.go`)

- **Watcher ignores expanded + case-insensitive.** Added `.swo`,
  `.bak`, `.tmp`, `.crdownload`, `.part`, `.partial`,
  `Thumbs.db`, `desktop.ini` to the ignore list. Suffix checks
  now match `.SWP`/`.Bak` regardless of case. The inline
  conditions were refactored into `ignoreSuffixes` slice +
  `ignoreBasenames` map so future additions are one-liners.
  (`internal/watch/watch.go`)

- **Report `mdEscape` collapses newlines.** A tool name, verdict,
  or risk string carrying an embedded `\n` broke every row in the
  Markdown table — one ill-behaved tool corrupting the whole
  engagement report. `mdEscape` now flattens `\r\n` / `\n` /
  `\r` to a single space, matching the per-cell guarantee
  `shortEvidence` already provides for the evidence column.
  (`internal/report/report.go`)

- **Audit row-scan failures log at warn instead of silently
  dropping.** Five SQL row-iteration sites in audit.go used
  `if err != nil { continue }` to skip rows whose `Scan` failed.
  Useful as a defensive pattern but it left operators blind to
  schema-drift or NULL-coercion bugs. Each call site now emits
  `audit_row_scan_failed` via `obs.Default().Warn` tagged with
  `where=<func>`. (`internal/audit/audit.go`)

## [0.24.0] - 2026-05-07

Validator + correctness wave. Five hour-bounded commits closing
real-world failure modes: three more silent-failure patterns the
EvilPortal validator missed, two campaign-YAML authoring traps that
slipped to runtime as misleading skips, a snapshot-rotation
file-removal ordering that could orphan data, end-to-end ctx
cancellation through the voice flow, and 16+ new LLM placeholder
patterns the pre-dispatch confidence scorer now catches.

### Fixed

- **EvilPortal silent-failure detection.** Three new critical rules:
  `ep_multiple_forms` (Marauder picks the first `<form>`
  indeterminately when more than one is present), `ep_form_onsubmit_blocker`
  (`onsubmit="return false"` / `event.preventDefault()` blocks
  default submission so credentials never reach `/get`),
  `ep_form_multipart` (`enctype="multipart/form-data"` —
  Marauder's GET handler only parses URL-encoded query strings).
  All three were "page renders, captures nothing" traps that LLM-
  generated portals could clear `/validate` with.
  (`internal/validator/evilportal.go`)

- **Campaign YAML rejects forward depends_on + cycles at validate
  time.** A step that depended on a successor previously slipped
  through and skipped at runtime with a misleading "dependency 'x'
  failed" message. Same for A → B → A cycles. Third validator pass
  walks each `depends_on` against declaration order; backward
  references fail the parse. (`internal/campaign/campaign.go`)

- **Snapshot rotation removes data before meta to avoid dangling
  pointers.** `Rotate()` removed the `.json` first and silently
  swallowed the error, then the `.bak`. Worst case: meta removal
  fails, data removal succeeds → orphan meta points at non-existent
  data; `List()` surfaces the entry, `Restore()` fails. Reordered:
  data first, meta second; both errors surface. (`internal/snapshot/snapshot.go`)

- **Voice flow honours caller context.** `Record` and `Transcribe`
  used `context.Background()` internally — a stuck mic driver or
  hung Whisper request had no cancellation path. New `RecordCtx`,
  `TranscribeCtx`, `TranscribeReaderCtx` accept a caller ctx; the
  REPL's voice-mode submit and the web `/api/audio` handler pass
  their session ctx so Ctrl+C / connection close aborts mid-flight.
  Old methods become deprecated thin wrappers calling
  `context.Background`. (`internal/voice/voice.go`,
  `cmd/promptzero/repl.go`, `internal/web/server.go`)

- **Confidence scorer catches more LLM placeholder templates.**
  The angle-bracketed `<your_url>`, `<insert_ip>`, `<target>`,
  `<value>` family; `changeme` / `change_me` / `insert_here`; runs
  of `xxxx` past the canonical "xxx"; `???`; `foo` / `bar` / `baz`;
  and datetime templates (`YYYY-MM-DD`, `HH:MM:SS`). 14 new
  test cases. (`internal/confidence/confidence.go`)

## [0.23.0] - 2026-05-07

Safety + operator-UX wave. Closes the v0.21 budget-enforcement gap,
gives operators an in-REPL surface for budget and saved sessions,
adds Windows audit-DB locking, hardens the BadUSB validator against
common LOLBAS techniques, and threads a `success` filter through the
rules engine. Eleven commits since v0.22.0; no breaking changes.

### Added

- **`/budget` REPL command.** `/budget` shows spend / cap / remaining /
  percent; `/budget set $X` extends the cap mid-session preserving the
  warn/hit callbacks wired at startup; `/budget {off,clear,disable}`
  turns the cap off. `/cost` now also renders the `budget=$spent/$cap
  (pct%)` block when a cap is set. (`internal/cost/cost.go`,
  `cmd/promptzero/commands.go`)

- **`/forget <id>` REPL command.** Wires the existing
  `Agent.DeleteSession` to operators — sessions could be listed,
  resumed, and saved but not deleted from the REPL. `/sessions` output
  ends with a `/resume <id>  /forget <id>` discovery hint.
  (`cmd/promptzero/commands.go`)

- **`keyboard_layout` parameter on `generate_badusb`.** DuckyScript
  payloads now respect the target's keyboard layout (gb/uk, de, fr,
  es, it, dk/no/sv/se, pt, br) — previous output was implicitly US
  and produced wrong characters on non-US targets. Generic fallback
  guidance for unknown layouts. (`internal/generate/generate.go`,
  `internal/tools/generate.go`)

- **Bridge state in `/api/device` JSON response.** Adds the
  `bridge: {active, reason?}` block so the web Cockpit can render a
  suspended-Flipper pill and the "via Flipper bridge" Marauder
  subtitle. Closes the SPEC.md §6.3 TODO. (`internal/web/api.go`,
  `internal/web/server.go`)

- **`Success` filter in rules engine.** `rules.Match` and the YAML
  `RuleMatchConfig.success` field accept a tristate (omit / true /
  false), mirroring `audit.Filter.Success`. Operators can now alert
  on every failed `wifi_handshake_capture` without hand-rolling an
  output_contains check tied to the tool's specific failure wording.
  (`internal/rules/rules.go`, `internal/config/config.go`)

### Fixed

- **Budget cap is enforced at dispatch.** v0.21 wired the 80%/100%
  callbacks as observe-only — the agent emitted a warning and kept
  spending. Now there's a pre-flight gate at the top of `Run()` that
  consults `cost.Tracker.BudgetExceeded()` and refuses new turns with
  the `ErrBudgetExceeded` sentinel error once the cap is reached.
  Operators bump the cap with `/budget set $X` to resume.
  (`internal/agent/agent.go`, `internal/agent/retry.go`,
  `cmd/promptzero/setup.go`)

- **Windows audit-DB file lock.** The Windows side of Finding #16
  was a stub that succeeded unconditionally — two PromptZero
  processes pointed at the same audit DB on Windows would race on
  the SQLite WAL. Implemented via `LockFileEx` with
  `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY`, matching
  the unix flock contract. (`internal/audit/lock_windows.go`)

- **BadUSB validator catches LOLBAS download/exec + Linux destructive
  patterns.** Eight new critical-severity rules: `dd_block_wipe`,
  `fork_bomb`, `chmod_777_root`, `certutil_download`,
  `bitsadmin_download`, `mshta_remote`, `regsvr32_squiblydoo`,
  `wmic_exec`. Payloads using these techniques previously cleared
  `/validate` as info-only. (`internal/validator/badusb.go`)

- **Bumped GitHub Actions past Node 20.** `upload-artifact@v5→v7`
  and `download-artifact@v5→v8` to clear the Node-24 deprecation
  banners ahead of the 2026-09-16 cutoff.
  (`.github/workflows/release.yaml`,
  `.github/workflows/coverage-diff.yaml`)

- **80%-of-budget banner referenced `/budget bump`.** That command
  doesn't exist — it's `/budget set $X`. Aligned the banner with the
  rest of the budget surface. (`cmd/promptzero/setup.go`)

### Documentation

- **README REPL slash-command list refreshed.** The list was last
  touched around v0.19 and had drifted: `/personas` (the actual
  command is singular `/persona`), no mention of `/budget`,
  `/forget`, `/sessions`, `/save`, `/resume`, `/audit`, `/history`,
  `/persona`, `/mode`, `/watch`, `/webhooks`, `/validate`,
  `/reconnect`, `/status`. Replaced with a five-group bulleted list
  mirroring `/help`. (`README.md`)

## [0.22.0] - 2026-05-06

Polish release. Lands the Tier-1 quick-wins cluster from the
2026-05-06 ecosystem-comparison review (themes D + F). Each item is
small individually; the bundle materially improves the operator
surface and closes two doc-hygiene items along the way.

### Added

- **Three readline-style keystrokes in the REPL line editor.** Ctrl+W
  deletes the word backward (matches bash `unix-word-rubout` —
  preserves leading whitespace so successive presses advance one
  word per stroke), Ctrl+K kills from cursor to end-of-line, Ctrl+R
  enters reverse-incremental history search with classic readline
  prompt rendering ("(reverse-i-search)`query': match"). Six new
  unit tests cover the contracts including the failed-match prompt
  variant, query backspace, and Esc-style cancel restoring the
  pre-search buffer. (`cmd/promptzero/lineedit.go`,
  `cmd/promptzero/repl.go`, `cmd/promptzero/lineedit_test.go`)

- **"Save PNG" button on the web screen-mirror panel.** One-click
  download of the current 128×64 frame as PNG; disabled when the
  canvas is offline. Useful for capturing evidence during an
  engagement without leaving the web UI.
  (`internal/web/static/app.js`)

- **Phone-as-remote responsive CSS.** `@media (pointer: coarse)`
  enforces 44×44 minimum tap targets (WCAG floor + Apple HIG), input
  font-size ≥16px (suppresses iOS Safari auto-zoom on focus), and
  `touch-action: none` on the screen-mirror canvas (so a tap-and-drag
  doesn't scroll the surrounding page). Three small rules ship the
  phone-as-remote use case without a dedicated mobile build.
  (`internal/web/static/app.css`)

- **`--web-share` flag.** Prints a copy-pasteable URL with the bearer
  token embedded so a teammate or the operator's phone can connect
  to the running `--web` server. Refuses to print when no auth token
  is set — sharing an unauthenticated URL by QR / DM / pasted-into-
  Slack is exactly the wrong default. (`cmd/promptzero/setup.go`,
  `cmd/promptzero/main.go`)

- **MAC-OUI attack-attribution table** in `internal/defense/`. A
  curated list of OUI prefixes for the SoC families commonly used by
  Flipper-class attackers (Nordic nRF52, Espressif ESP32, TI CC254x).
  `LookupOUI(mac)` returns a descriptive label; `IsKnownAttackOUI(mac)`
  returns the boolean. Used by the defensive classifier to enrich
  Match descriptions ("BLE spam from Espressif (ESP32 …)" instead of
  "BLE spam from AC:BC:DE:01:02:03"). Robust to MAC formatting:
  colons / dashes / dots / spaces / unseparated all canonicalise to
  the same uppercase 24-bit prefix. Four new tests.
  (`internal/defense/oui.go`, `internal/defense/oui_test.go`)

- **`badkb_run` Spec.** BadUSB over BLE HID — same DuckyScript syntax
  and pre-flight validator as `badusb_run`, routed via the BadBT
  loader app instead of USB HID. Requires Momentum / Unleashed /
  RogueMaster firmware (stock OFW lacks the BadBT app). Risk: High,
  same tier as `badusb_run` because the payload-class danger is
  identical — only the transport changes. Registered with the
  validator gate so a Critical-finding payload is refused regardless
  of which transport runs it. (`internal/tools/badusb.go`,
  `internal/risk/risk.go`)

### Changed

- **Catalogue de-listings.** Removed two ambiguous entries from
  `docs/awesome-flipper-zero-projects.md` flagged by the
  ecosystem-comparison review: row 258 (`flippercloud/flipper-mcp`,
  a SaaS feature-flag service) and row 475 (`DumpySquare/flipperAgents`,
  a NetScaler/F5 ADC manager). Neither is a Flipper-Zero project;
  the naming collisions were creating noise in the AIAgent category.

### Notes

- Registry size: 270 → 271 (added `badkb_run`).
- Validation: vet clean, lint 0 issues, test 54 packages pass /
  0 fail, govulncheck 0 vulnerabilities, binary +0.1% vs v0.21.
- One Tier-1 item from the ecosystem review (`proxmark3-to-flipper`
  vendor + `nfc_import_pm3` Spec) deferred — investigating + vendoring
  the third-party library is closer to half-day Tier-2 effort and
  would have padded this PR. Tracked for a follow-up release.
- The remaining ecosystem-review themes (A: provider-agnostic LLM /
  WiFi-MCP / autonomous campaign; C: Deps.FlipperB + nfc_relay_run)
  are each multi-week dedicated releases — see the synthesis at
  `~/ObsidianVault/agent/reviews/promptzero-2026-05-06-ecosystem/`.

## [0.21.0] - 2026-05-05

Reliability and reporting release. Closes the remaining
project-impacting work from the 2026-05-04 multi-angle review:
the API resilience pass (Tier-2 #15), session budget cap
(Tier-2 #13), and engagement report export (Tier-2 #16). Marketing
items (MCP-in-Claude-Desktop reframe, demo GIF, distribution
push) are tracked as a separate workstream.

### Added

- **API retry + backoff for transient Anthropic failures.**
  `streamOnceWithRetry` wraps the streaming Messages call with
  exponential backoff (1s → 2s → 4s, max 30s) for 429 / 500 / 502
  / 503 / 504 / 529 (Anthropic-overloaded). Permanent errors
  (4xx other than 429, malformed requests, auth failures)
  propagate immediately; ctx cancellation aborts mid-backoff. Up
  to 4 attempts (initial + 3 retries) before surfacing the last
  transient error. (`internal/agent/retry.go`,
  `internal/agent/retry_test.go`)

- **Per-attempt retry observer.** New `Agent.SetRetryNotifyCallback`
  surfaces each backoff to the operator on stderr — "Anthropic
  transient error (attempt 2/4) — retrying in 2s · 503 service
  unavailable" — so a recovering API outage doesn't look like a
  wedged session. Pairs with the existing offline-banner logic.
  (`internal/agent/retry.go`, `cmd/promptzero/setup.go`)

- **SIGHUP / SIGTERM signal handlers.** A terminal hangup
  (parent shell closes), `kill -TERM`, or container stop now
  triggers a clean shutdown: in-flight tool cancelled,
  registered shutdown hooks run, raw-mode terminal restored, UI
  torn down. Closes the SRE finding that an unpaired
  `assistant tool_use` block could survive a SIGHUP and break
  the next resume with HTTP 400. (`cmd/promptzero/signals.go`)

- **Shutdown hooks** for clean exit.
  `signalHandler.AddShutdownHook` registers a function to run on
  hard-exit. `cmd/promptzero/main.go` registers `marauderClose`
  (so a SIGTERM mid-attack stops the firmware before the
  process dies — closes the "Marauder keeps attacking after
  death" finding) and `auditClose` (so the SQLite WAL is
  flushed before exit). Each hook gets a 2s timeout so a
  misbehaving hook can't wedge process exit.
  (`cmd/promptzero/signals.go`, `cmd/promptzero/main.go`)

- **Session USD budget cap.** New `--budget <USD>` flag and
  `cost.budget_usd:` config field. The cost tracker fires a
  warn callback at 80% and a hit callback at 100% of the cap
  (each one-shot per session); operators see the warn / hit
  banners on stderr, and `tracker.BudgetExceeded()` is exposed
  for the agent's pre-dispatch refusal of new turns past the
  cap. Raising the cap mid-session resets the threshold flags
  so future thresholds re-fire. Five new tests cover the
  threshold logic. Closes the "hostile to hobbyists" finding
  from the product strategist review.
  (`internal/cost/cost.go`, `internal/cost/budget_test.go`,
  `cmd/promptzero/setup.go`, `internal/config/config.go`)

- **JSON renderer for `/report`.** New `JSONRenderer` produces a
  structured engagement-report dump (success/failure split,
  ATT&CK coverage, detector verdicts, per-tool counts, per-risk
  counts, total duration). Suitable for engagement-tracking
  systems, custom dashboards, programmatic verification. The
  in-memory `Summary` shape is unchanged — JSON-friendly schema
  remap happens inside the renderer. (`internal/report/report.go`,
  `internal/report/report_test.go`)

- **`/report json [save]`** REPL command. Existing markdown
  output stays the default; `json` flag swaps the renderer;
  `save` writes to `~/.promptzero/reports/<id>.json` with the
  same path-safety check as the markdown export.
  (`cmd/promptzero/commands.go`)

### Changed

- **Voice recording context timeouts.** `Engine.Record()` now
  enforces a 2-minute ceiling so a stuck mic / driver issue
  can't wedge the REPL indefinitely waiting on `rec` to detect
  silence that will never arrive. `Engine.RecordFixed(seconds)`
  uses `seconds + 10s` margin. Closes the SRE finding.
  (`internal/voice/voice.go`)

- **ATT&CK coverage table includes a visual heatmap column.**
  The markdown renderer now sorts techniques by frequency
  (highest first) and renders a Unicode bar chart (`█░░`)
  alongside the count, so "what we did the most of" jumps out
  of the report at a glance. Productises the audit moat
  identified by the product strategist. The hashcat-style
  fixed-width column stays clean across rows.
  (`internal/report/report.go`)

### Notes

- Validation: vet clean, lint 0 issues, test 54 packages pass /
  0 fail, govulncheck 0 vulnerabilities, binary +0.06% vs v0.20.
- This release closes the remaining project-impacting items
  from the multi-angle review. The strategic / multi-week items
  (audit-DB at-rest encryption, plugin model for tools,
  Ollama-only mode) are deferred and require their own design
  cycles. Marketing items (MCP-in-Claude-Desktop reframe, demo
  GIF, Reddit / Hackaday / Awesome-Lists distribution push,
  seeded "good first issue" issues) are intentionally a
  separate workstream.

## [0.20.0] - 2026-05-05

Operator-experience release. Acts on the Tier-1 quick wins and
high-priority Tier-2 features from the 2026-05-04 multi-angle review.
Strategic decisions: full mode stays the default (hobbyist-leaning,
red-team-friendly), Claude-first with persona-declared fallbacks for
other providers when policy refuses legitimate work.

### Added

- **Refusal detection + persona-declared provider fallback** for the
  generate_* tools. When Claude refuses a legitimate offensive
  payload synthesis, PromptZero detects the canonical refusal shape
  and retries through the fallback provider declared in the active
  persona's `provider:` map. Set `provider: generate: ollama` on a
  persona to route payload generation through a local Ollama
  instance on refusal. Result.Provider names whichever provider
  served the request. (`internal/generate/refusal.go`,
  `cmd/promptzero/setup.go`)

- **`explain_last_result` meta-tool.** Returns the most recent audit
  row(s) so the explorer / default persona can narrate what just
  happened in plain language. Pair with `count` to recap the last
  few actions for a learning walkthrough. Risk: Low.
  (`internal/tools/audit.go`)

- **`marauder_handoff_hashcat` tool.** The missing-link in the WiFi
  attack chain identified by the hardware-ecosystem reviewer.
  Converts a captured PMKID pcap (typically pulled from
  `/ext/marauder/pcaps/`) to hashcat-22000 format and emits a
  ready-to-run hashcat command line. Wraps `hcxpcapngtool` when
  installed; prints the install hint + eventual command when not.
  Risk: Medium (host-side only — no RF, no Flipper or Marauder
  writes). (`internal/tools/marauder_handoff.go`)

- **`explorer` persona** for newcomers and learners. Patient
  teaching tone, every action gets a "what / why / what next"
  explanation, terminology unpacked the first time it's used.
  Pairs with `--read-only` for a fully safe exploration session.
  (`examples/personas/explorer.yaml`)

- **GitHub issue + PR templates.** Bug-report template prompts for
  PromptZero version, OS, hardware, firmware, and reproduction
  steps. Feature-request template includes the authorised-use
  acknowledgement. PR template prompts for test plan + risk-
  classification reminder for new tools. The blank-issue path is
  disabled with steers to private security disclosure and
  Discussions for open-ended questions.
  (`.github/ISSUE_TEMPLATE/`, `.github/pull_request_template.md`)

### Changed

- **Default model routing per cost tier.** Pre-v0.20.0 the model
  resolution short-circuited every tier to the operator's base
  model — which routed every classify-tier call (router /
  reflexion / verifier / detector judge) to whatever the operator
  picked, almost always Opus. The new `defaultModelsByTier` map
  picks the right Anthropic family per tier: classify→Haiku,
  generate→Sonnet, plan→Sonnet, exploit→Opus. Persona overrides
  and base-model fallback both still take precedence. Closes the
  AI/ML reviewer's 5–20× overspend finding.
  (`internal/agent/models.go`)

- **Audit log query output now wraps in
  `<untrusted-audit-content>`.** `audit_query`, `audit_export`, and
  `audit_stats` previously returned unwrapped to the model. Audit
  rows can carry historical hardware-origin content (captured
  SSIDs, NFC URIs, evil-portal credentials), so unwrapped output
  was a laundering injection path — adversarial bytes from an
  earlier session could surface in a later turn's audit query and
  reach the model as instructions. The trust-boundary clause in
  the system prompt names both wrapper tags. Closes the threat-
  modeller finding. (`internal/agent/quarantine.go`,
  `internal/agent/prompts/trust_append.tmpl`)

- **Voice manual-confirm.** Transcribed voice input now drops into
  the input buffer for an explicit second-Enter confirmation
  rather than auto-firing the turn. A mis-heard word or stray
  Enter no longer dispatches an unintended request to the model.
  Operator-empath finding. (`cmd/promptzero/repl.go`)

- **`http_enum_common` default User-Agent depersonalised.** Changes
  from `PromptZero/0.5` to a generic Chrome string. The old
  default gave DFIR a free indicator-of-tooling marker on every
  recon scan; engagements that need attribution can still set it
  via the `user_agent` argument. Threat-modeller finding.
  (`internal/tools/security.go`)

- **System prompt now has a single source of truth.** `system.tmpl`
  was a duplicate of the default-builtin persona's system prompt;
  it's been removed. `BuildSystemPrompt` falls back to the
  registry's default-builtin SystemPrompt when called with `p ==
  nil`, eliminating the silent divergence between CLI and harness
  paths. (`internal/agent/prompts.go`, removes
  `prompts/system.tmpl`)

- **First-run hint surfaces buried features.** `/save`, `--watch`,
  `--read-only`, `--persona`, and `--mcp` now appear in the
  welcome banner so new users discover them without spelunking
  the source. Operator-empath + DevRel findings.
  (`cmd/promptzero/setup.go`)

- **`/rewind` error message.** Used to tell users to run
  `/session save <name>` (a command that doesn't exist). Now
  correctly points at `/save <name>`. (`cmd/promptzero/commands.go`)

### Notes

- Registry size: 268 → 270 (added `explain_last_result` +
  `marauder_handoff_hashcat`).
- Validation: vet clean, lint 0 issues, test 54 packages pass /
  0 fail, govulncheck 0 vulnerabilities, binary +0.06% vs v0.19.
- Follow-up Tier-2/3 items from the multi-angle review (API
  resilience pass with retry/backoff + signal handlers, audit-DB
  encryption, post-engagement PDF report, MCP-in-Claude-Desktop
  marketing reframe, distribution push) deferred to subsequent
  releases.

## [0.19.0] - 2026-05-04

Simplification release. Replaces the persona+mode safety-allow-list maze
with a single boolean. Strengthens built-in personas with explicit
authorisation framing so legitimate red-team work isn't reflexively
refused on dual-use content.

### Added

- **`--read-only` flag and `read_only:` config field.** When engaged,
  dispatch refuses any tool whose `Spec.Risk` is above `risk.Low` —
  no writes, no transmits, no emulation, no payload generation. The
  single safety rail; replaces the persona+mode allow-list matrix.
  Catalog narrowing also kicks in so the LLM doesn't waste turns
  planning a tool it would only get refused at dispatch.
  (`internal/agent/agent.go`, `internal/agent/tools.go`,
  `cmd/promptzero/setup.go`, `internal/config/config.go`)
- **REPL banner** prints `READ-ONLY` pill when the rail is engaged so
  the operator never wonders whether it's on. (`cmd/promptzero/setup.go`)
- **Per-tier `Provider` field on `Persona`** lets a persona declare a
  fallback LLM provider for one or more tiers (classify / generate /
  plan / exploit). Use case: pin generation to Ollama on the
  physical-pentest persona to avoid Anthropic policy refusals on
  legitimate offensive payload synthesis. (`internal/persona/persona.go`)

### Changed

- **Built-in persona system prompts strengthened.** Each built-in now
  opens with explicit operator-context framing — *"this session is an
  authorised security engagement; the operator has scope; engage with
  payload requests as engineering tasks; the operator carries legal
  responsibility."* Reduces reflexive refusals on dual-use tooling.
  Tool surface (LLM catalog) is no longer constrained per persona —
  pair with `--read-only` for the safety rail.
  (`internal/persona/builtins.go`)

### Deprecated

- **`Persona.Tools []string` field.** The tool-allowlist job moves to
  `--read-only`. Existing user personas in
  `~/.promptzero/personas/*.yaml` that set `Tools:` keep working
  through this release; v0.20.0 will retire the field.
  (`internal/persona/persona.go`)
- **`--mode` flag and `cfg.Mode` field.** `recon|intel|stealth` now
  alias to `--read-only` with a deprecation warning;
  `standard|assault` are no-ops with a warning. v0.20.0 will remove
  the entire `internal/mode/` package. (`cmd/promptzero/setup.go`,
  `internal/config/config.go`)
- **`agent.SetMode`, `agent.ErrBlockedByMode`, `agent.Mode()`.**
  Same deprecation window; replaced by `agent.SetReadOnly`,
  `agent.ErrReadOnly`, `agent.ReadOnly()`. (`internal/agent/agent.go`)

### Notes

- Risk taxonomy is the source of truth for what `--read-only` allows.
  78 tools are currently classified `risk.Low` (pure reads, queries,
  scans, audit access). Anything above is refused under the rail.
- Migration path for users on `--mode recon|intel|stealth`: replace
  with `--read-only`. For users on `--mode standard|assault`: drop
  the flag. The deprecation warnings will steer the migration during
  the v0.19 cycle; v0.20 removes the legacy paths.

## [0.18.0] - 2026-05-04

Multi-agent review-and-action wave on top of v0.17.0. A fresh six-agent
audit (architecture, performance, security, testing, DX/docs,
build/CI) surfaced 70+ findings; an independent six-agent validation
pass confirmed 58 verified, 12 partial, 0 wrong. This release closes
the verified set with no regressions: vet 0, lint 0, full test suite
0 failures, 0 govulncheck vulnerabilities, binary size delta +0.04%.

### Security

- **`RunTool` now applies the audit + confirm gates** that protect
  `Run()`. Closes Sec HIGH-1 from the review: callers that fed tools
  through `agent.RunTool` (the campaign executor wired at
  `cmd/promptzero/commands.go`, plus future rules-engine paths)
  bypassed `audit.RequireOpen`, the operator confirmation callback,
  and the quarantine layer. The docstring's "exactly as Run would"
  promise is now true. (`internal/agent/agent.go`,
  `internal/agent/runtool_test.go`)

- **`fap_build` deploy hardening.** `findFAP` now scans only the
  canonical `$absSrc/.ufbt/dist/` directory rather than the
  LLM-controlled `output_dir`; an adversarial invocation with
  `output_dir=/` can no longer harvest arbitrary `.fap` files from
  the host and push them to `/ext/apps/`. The deploy step now
  re-gates at `risk: high` via `confirmFAPDeploy` so the operator
  re-confirms the native-code write to the Flipper (`fap_build`'s
  parent risk is Medium; without this an "approve all" on a Medium
  tool would silently authorise a binary push). The confirmation
  dialog includes both source and destination paths so the operator
  can verify build provenance. Closes Sec HIGH-2.
  (`internal/tools/fap_build.go`, `internal/tools/fap_build_test.go`)

- **Approve-all now scopes to a risk ceiling.** When the operator
  says "approve all" on a Medium tool, a subsequent High tool in the
  same turn re-prompts. Critical is unconditionally gated as before.
  Closes Sec MED-3. (`internal/agent/agent.go`)

- **Voice recording uses `os.MkdirTemp` + `defer RemoveAll`.** The
  previous `/tmp/promptzero_voice.wav` was a predictable path with
  a window between Record and Remove during which a co-resident
  process could read or symlink-overwrite. Closes Sec MED-4.
  (`cmd/promptzero/repl.go`)

- **Web server bounds REST routes with `http.TimeoutHandler` (30s)**
  while WebSocket upgrade requests pass through unchanged. Slow-loris
  attacks against `/api/fs/upload` and friends can no longer pin a
  worker indefinitely. Closes Sec MED-5. (`internal/web/server.go`)

- **`webhook.ValidateSubscription` rejects loopback, RFC1918,
  link-local (incl. 169.254.169.254 cloud-metadata), and non-http(s)
  URLs at config-load time.** Webhook payloads carry tool
  inputs/outputs (potentially captured credentials) — a mistakenly
  internal target was an SSRF leak vector. Set
  `PROMPTZERO_WEBHOOK_ALLOW_INTERNAL=1` for homelab/on-prem
  deployments. Closes Sec MED-6. (`internal/webhook/webhook.go`,
  `internal/webhook/validate_test.go`, `cmd/promptzero/setup.go`)

### Architecture

- **`ToolGroup()` now consults the registry as the source of truth.**
  Previously the prefix-based switch in `internal/agent/router.go`
  could disagree with `Spec.Group` set in `internal/tools/*.go` —
  25+ tools were silently mis-classified (security tools fell to
  `meta.util` "always-on", crypto and GPS tools couldn't be narrowed,
  etc.). Persona-mode `Allows()` and dynamic-catalog narrowing now
  share a single classification path. New
  `TestToolGroup_AgreesWithSpecGroup` walks every registered Spec
  and pins the contract. Closes Arch #1. (`internal/agent/router.go`,
  `internal/agent/router_test.go`)

### Performance

Five low-risk allocation/I-O wins on hot paths. None change
observable behaviour:

- `buildTools()` is now `sync.Once`-cached. The 274-entry catalog
  (with JSON-schema unmarshals) was rebuilt every Run loop.
  (`internal/agent/tools.go`)
- `audit.notify()` short-circuits when zero observers are
  registered, skipping the slice copy on every dispatch.
  (`internal/audit/audit.go`)
- `audit.Stats()` collapses three SQLite round-trips into one
  conditional-aggregate query. (`internal/audit/audit.go`)
- `ValidateEvilPortal` hoists its five required-present regexps to
  package-level (`epRequiredRules`), matching the existing
  `epBadRules` convention. (`internal/validator/evilportal.go`)
- `voice.Engine.client()` is built once in `New()` rather than
  rebuilt per Transcribe. (`internal/voice/voice.go`)

### Testing

- **`internal/session` (file-based session persistence) and
  `internal/generate` (LLM-driven build/validate/deploy) now have
  test coverage.** Both packages were on the critical path with zero
  tests at the v0.17.0 baseline. 11 + 17 cases respectively cover
  round-trips, error paths, atomic-write semantics, fence-stripping
  edge cases, runaway-output caps, and mock-LLM-driven happy paths.
  No production code changed. (`internal/session/session_test.go`,
  `internal/generate/generate_test.go`)

- **Audit benchmark + `fap_build` tests committed to the tree** —
  previously untracked but already passing.
  (`internal/audit/audit_bench_test.go`, `internal/tools/fap_build_test.go`)

### Build / CI

- **govulncheck wired into CI and Taskfile** (`task vuln` runs
  locally; CI vuln job runs on every PR + main push). Baseline:
  zero vulnerabilities at the time of this release.
  (`.github/workflows/ci.yaml`, `Taskfile.yml`)

- **`actions/dependency-review-action` blocks PRs that introduce a
  Moderate-or-higher CVE in any dependency.**
  (`.github/workflows/ci.yaml`)

- **`install.sh` URL pinned to release artifacts.** README now
  recommends
  `https://github.com/xunholy/promptzero/releases/latest/download/install.sh`
  (immutable per release tag) instead of fetching from
  `raw.githubusercontent.com/.../main/install.sh`. The release
  pipeline cosign-signs `install.sh` alongside `checksums.txt` so
  consumers can verify the script before piping to `sh`. Closes the
  unsigned-installer gap. (`README.md`,
  `.github/workflows/release.yaml`)

### DX / Docs

- **New `CONTRIBUTING.md`** — package map, first-contribution flow,
  hardware-free harness pointer (`cmd/pzrunner`), commit/PR
  conventions, scope/review notes specific to a tool that drives
  RF + USB. Single largest onboarding gap from the DX review.

- **README cleaned up.** Tool-count consistency (TOC anchor,
  heading, BLE paragraph all agree at 268 to match
  `registry_size_test.go`); `pre-commit install` added to
  from-source quick-start; `promptzero --init` is now the
  recommended configure path with `cp config.example.yaml`
  demoted to "if you're hacking on PromptZero itself".

- **`examples/config.yaml` synced** from `config.example.yaml` — the
  Marauder BLE address-shape detection, bridge mode, hybrid mode,
  and `mcp_clients` block were missing from the examples copy.

- **Three actionable error messages** rewritten so operators can
  recover without spelunking the source: `repl.go` "raw mode"
  failure now explains the most common cause (pipe / file
  redirection); upgrade.go HTTP-status and `--version`-output
  errors include the URL/captured-output/expected-format.

### Notes

- **Tier-4 strategic items deliberately deferred.** The internal
  /tools dependency-inversion refactor and the Marauder transport
  unification onto `transport.Transport` carry inherent regression
  risk that "zero regressions in this release" cannot accommodate.
  Both are tracked for a future minor release.
- **Validation methodology**: 12 specialist agents in two passes
  (six review, six validate) executed against commit `2f7f3fc`. Per-
  domain reports were written to the operator's research vault and
  inform the action plan that produced this release.

## [0.17.0] - 2026-04-30

Safety, reliability, and DX hotfix wave following a multi-agent review of
v0.16.0. 17 commits across architecture, code quality, UX, security/safety,
and testing. No new tool Specs; no transport changes. Closes 14 prioritized
findings from the review (`docs/refactor/review-2026-04-30/` — synthesis
removed before release; reports preserved in git history at `2c10455..ffc76e9`).

### Security

- **MCP server consent gate.** Tool calls at `risk.High` and `risk.Critical`
  now refuse by default with a `mcp.NewToolResultError` and require explicit
  operator opt-in via `PROMPTZERO_MCP_ALLOW_HIGH=1` / `PROMPTZERO_MCP_ALLOW_CRITICAL=1`.
  All MCP tool calls — allowed or denied — are now recorded via
  `audit.RecordCtx`. Closes a CRITICAL bypass where MCP clients could call
  destructive tools (`wifi_deauth`, `flipper_factory_reset`, `glitch_fire`)
  with no consent and no audit. **Breaking for headless MCP integrations** —
  set the env vars to restore the previous behavior. (`internal/mcp/server.go`)

- **`generate_deploy_run` risk inheritance.** Spec is now `risk.Critical`;
  the handler now derives the inner action's risk via the same lookup as
  `resolveRunPayloadRisk` and surfaces a typed `WorkflowConfirm` per payload
  type (BadUSB / portal / Sub-GHz / IR / NFC) before `runPayload`. Previously
  one keystroke could deploy and fire a Critical inner action. (`internal/tools/generate.go`)

- **Web Marauder synth-panel consent + audit.** Every entry in the panel
  registry is now classified (Low / High / Critical). High and above route
  through the existing `s.confirms` channel for parity with the chat-driven
  confirm UX, with a server-issued nonce and 30 s expiry. Server-side
  `ConfirmDelayGate` mirrors the 2-second REPL delay so a malicious tab can
  not bypass. All commands — allowed or denied — write an audit row. Closes
  a CRITICAL bypass where a single WebSocket frame triggered RF transmit.
  (`internal/web/api_marauder.go`, `internal/web/static/app.js`)

- **2-second consent delay wired into REPL.** `ConfirmDelayGate` was defined
  in v0.3.0 but never instantiated outside tests. The REPL now constructs
  one per confirmation prompt and discards positive consent keystrokes
  (`y`, `all`, `confirm`) until the gate opens. Negative decisions
  (`n`, `r`, Esc, Ctrl+C) bypass the delay. (`cmd/promptzero/repl.go`)

- **BadUSB upload validator.** `/api/fs/upload` now runs `validator.Validate`
  on uploads targeting `/ext/badusb/*.txt`; SeverityCritical findings are
  refused with HTTP 422 unless the operator passes `?validator_bypass=true`.
  Audit level for badusb uploads bumped from `low` to `high`. (`internal/web/api_fs.go`)

- **Audit log fail-closed at dispatch.** New `audit.RequireOpen(l, level)`
  helper returns an error when `l == nil && level >= risk.High`. The agent
  dispatch path now refuses High and Critical tool calls when no audit log
  is initialized, with a synthetic tool_result so the model sees a clean
  refusal turn. Previously the agent failed open. (`internal/audit/audit.go`,
  `internal/agent/agent.go`)

- **Quarantine wraps tool errors and removes the `analyze_image` /
  `discover_apps` exemptions.** Both tools surface attacker-controllable
  text (image content / SD card filenames). Errors from hardware-origin
  tools are now wrapped on the same allowlist rule as successes — error
  messages can carry attacker-controlled text (e.g. an SSID in a Marauder
  connect failure). Structured-internal tools (audit_*, generate_*,
  workflows) remain exempt. (`internal/agent/quarantine.go`)

- **Workflow `gateSubtool` retrofit.** `WiFiTargetToHashcat` now routes its
  High-risk `wifi_sniff_pmkid` step through `gateSubtool`, mirroring the
  pattern from `badusb_profile` and `mousejack`. (`internal/workflows/`)

- **Web HTTP server hardened against Slowloris.** `ReadHeaderTimeout: 10s`
  and `IdleTimeout: 120s` set on `http.Server`; `ReadTimeout` /
  `WriteTimeout` left at 0 because WebSocket upgrades need long-lived
  reads/writes. `srv.Shutdown` errors now surface via `obs.Default().Warn`
  instead of being silently dropped. (`internal/web/server.go`)

### Added

- `obs.SafeGo(name, fn)` — goroutine wrapper with deferred `recover()` that
  logs panics via `obs.Default().Error` instead of crashing the process.
  Used in the rules engine, voice subprocess, all 8 WebSocket inbound
  goroutines, the WS writer/heartbeat, and the agent confirm callback.
  (`internal/obs/safego.go`)
- `audit.RequireOpen(l *Log, level risk.Level) error` — fail-closed helper
  used at the agent dispatch site. (`internal/audit/audit.go`)
- `internal/risk/risk_test.go` — table-driven tests for `Classify`,
  `AutoApprove`, `WantsDiff`, `Register` / `Unregister`. The package was
  previously at 0 % coverage; now 80 %.
- `internal/voice/voice_test.go` — `httptest`-based Whisper mock plus
  `Available()` no-`rec` test. Voice was 0 % coverage; now 55 %.
- `audit_test.go` table-test for `RequireOpen` covering nil + each risk
  level + open log.
- `marauder.TestStreamBackpressureExits` — backpressure regression test.
- `agent.TestAuditGate_RefusesHighRiskWithoutAuditLog` — locks in the new
  fail-closed contract.

### Changed

- **`task test` now sets `CGO_ENABLED=1` per-task** for `test`, `test:full`,
  and `test:eval`. Previously the global `CGO_ENABLED=0` collided with
  `-race` (which requires cgo) and the documented test command failed
  immediately on a clean checkout. Global env unchanged — host-build CGO=0
  remains intentional. (`Taskfile.yml`)
- **`task lint` precondition** errors with a friendly "run task dev:setup
  first" if `golangci-lint` is not on PATH.
- **`/help`** now lists the eight commands previously omitted: `/attack`,
  `/campaign`, `/rewind`, `/report`, `/stats`, `/cost`, `/debug`, `/rules`.
  (`cmd/promptzero/commands.go`)
- **`/tools`** gains pagination via `/tools page <n>`.
- **README tool count** updated from "160+ Tools" to the actual registry
  size (268+).
- **Audit log truncation** raised from 10 000 → 65 535 bytes per row so
  large tool outputs survive without premature loss. (`internal/audit/audit.go`)
- **Marauder TFT panel** is now gated server-side via a `marauder_available`
  field in the initial WS status payload (true only when `s.marauder != nil`
  and the device is connected). The frontend reveals the rail item only
  when the server confirms the bridge is up. Replaces the static
  `FEATURE_MARAUDER_ENABLED=false` flag. (`internal/web/static/app.js`,
  `internal/web/server.go`)
- **`internal/voice`** subprocess paths use `exec.CommandContext` and the
  Whisper HTTP call uses a dedicated `&http.Client{Timeout: 60*time.Second}`
  instead of `http.DefaultClient`. Voice can no longer hang indefinitely
  on a stalled mic or unreachable Whisper endpoint.

### Fixed

- **`marauder.Stream` no longer wedges** when the consumer is slow or stopped.
  The unbuffered `lines<-line` send under held mutex is replaced with a
  `select` that handles the `done`-channel cancellation (sends `stopscan`
  + returns) and a 2-second backpressure timeout (warns and returns).
  (`internal/marauder/marauder.go`)
- **MCP `Server.deps()` no longer NPEs on Bruce / Faultier / BusPirate
  Specs.** ~28 Specs (`bruce_*`, `glitch_*`, `buspirate_*`) now have their
  backends wired through. (`internal/mcp/server.go`)
- **Confirm-callback goroutine** at `internal/agent/agent.go:433` no longer
  crashes the process on a panicking ConfirmFunc — the `obs.SafeGo` wrapper
  recovers; the select falls through to ctx/timer and returns `DecisionDeny`.
- Eight bare WebSocket inbound dispatch goroutines (text, audio, reset,
  screen acquire/release, marauder acquire/release, marauder cmd) now
  recover panics. Same for the writer / heartbeat goroutines.
  (`internal/web/server.go`)
- `internal/rules` `RunTool` goroutine wrapped with `obs.SafeGo` —
  panicking tool callbacks no longer crash the daemon.

### Removed

- **`FEATURE_MARAUDER_ENABLED` static frontend flag** in
  `internal/web/static/app.js`. Replaced by the server-emitted
  `marauder_available` field above.
- **README "browser-based voice recording" claim.** The frontend has no
  `MediaRecorder` wired up; the server-side `handleAudio` exists but is
  unreachable from the UI today. v0.18 will implement properly; the
  misleading claim is removed in the meantime.
- **`analyze_image` and `discover_apps` quarantine exemptions** — both now
  go through the standard wrap. (`internal/agent/quarantine.go`)

### Migration notes

- **MCP integrators**: existing clients that called High or Critical tools
  will get a refusal until they set `PROMPTZERO_MCP_ALLOW_HIGH=1` /
  `PROMPTZERO_MCP_ALLOW_CRITICAL=1`. Audit captures both allowed and
  denied calls. The interactive elicitation path (mcp-go ≥ 0.30) is on
  the v0.18 plan.
- **Headless agents without an audit log**: if you call the agent dispatch
  path directly with `auditLog == nil` and a `risk.High`+ tool, you will
  now get a refusal instead of silent execution. Construct an
  `audit.Open(path)` (sqlite) or accept the refusal.
- **Web Marauder panel users**: rail item only appears when the device is
  detected and the bridge handshake completes. Set up the device first.

## [0.16.0] - 2026-04-29

### Added

- **37 new tool Specs closing the v0.14.0 audit gap analysis**
  (~/ObsidianVault/agent/integration-coverage-and-skills.md). Brings
  Marauder coverage from ~88 % to effectively complete and closes the
  largest aggregate Flipper gaps (Crypto enclave, GUI screen stream,
  RTC date, archive extract, destructive ops, power rails). Bringing
  the total registry to 268 tool Specs.

  **Marauder Specs (24)** — `internal/tools/wifi_v016.go`
    + `internal/marauder/commands_v016.go`:
    - `wifi_clone_sta_mac` (companion to wifi_clone_mac)
    - `wifi_info_ap` (per-AP detail)
    - `wifi_mactrack` (follower / probing detector)
    - `wifi_sigmon` (RSSI ticker)
    - `wifi_sniff_pinescan` (Hak5 Pineapple deauth fingerprint)
    - `wifi_sniff_multissid` (rogue multi-SSID radio)
    - `wifi_wardrive_start` / `_stop` / `_poi` (Wigle-CSV with GPS)
    - `gps_tracker_start` / `_stop` and `gps_poi` (start/mark/end)
    - `wifi_add_ap` / `wifi_add_station` (manual list injection)
    - `wifi_bt_spoof_airtag` (RF transmit; AirTag identity spoof)
    - `wifi_karma` (probe-targeted rogue AP)
    - `wifi_attack_quiet` / `_badmsg` / `_sleep` (WPA3-era disruption)
    - `wifi_evil_portal_set_html`, `_set_ap`, `_reset`, `_ack`
      (companion subverbs to existing start/stop)

  **Flipper Specs (16)** — `internal/tools/system_v016.go`
    + `internal/flipper/commands_v016.go`:
    - `crypto_encrypt` / `crypto_decrypt` / `crypto_has_key`
      (HMAC enclave; companion to existing crypto_store_key)
    - `gui_screen_stream` (PBM frame stream over RPC)
    - `flipper_date_get` / `_set` (RTC)
    - `flipper_storage_extract` (tar extract on SD)
    - `flipper_storage_format` (destructive — confirm:'YES_FORMAT')
    - `flipper_factory_reset` (destructive — confirm:'YES_FACTORY_RESET')
    - `flipper_backup_create`
    - `flipper_backup_restore` (destructive — confirm:'YES_RESTORE')
    - `flipper_power_off`
    - `flipper_power_5v` / `flipper_power_3v3` (GPIO rail toggles)

  Risk classification updated for every new tool in
  `internal/risk/risk.go` so the confirm gate fires consistently
  across CLI, REPL, web, and MCP. Registry-size test bumped from
  231 → 268 with a comment explaining the wave delta.

- **11 user-facing slash-command skills** filed in `~/.claude/skills/`
  (no release coupling — they live in user config). Wraps common
  Flipper / Marauder workflows that previously required manual chaining:
  `/recon-pass`, `/loot-pull`, `/firmware-snapshot`, `/badge-triage`,
  `/wifi-handshake`, `/garage-sweep`, `/hw-blackbox`, `/badge-walk`,
  `/marauder-init`, `/payload-deploy`, `/glitch-hunt`. Each declares
  its tool chain, prerequisites, and risk-gate behaviour.

### Notes

- Destructive Specs (`flipper_storage_format`, `flipper_factory_reset`,
  `flipper_backup_restore`) require an exact-string `confirm` arg in
  addition to the Critical risk-band confirmation gate. The literal
  token (`YES_FORMAT`, `YES_FACTORY_RESET`, `YES_RESTORE`) is
  documented in the Spec description and enforced by the handler.
  This is a belt-and-braces gate so even with `--yolo` (risk gate off)
  the tool can't be triggered by an LLM accident.

## [0.15.0] - 2026-04-29

### Changed

- **`wifi_random_mac` gains a `target` argument** — pass `'ap'` (default,
  preserves prior behaviour) or `'sta'` to randomise the station-mode MAC
  via the existing `Marauder.RandomStaMAC` client method. Closes the
  Phase-2 audit gap noted in the integration coverage report; brings the
  Spec in line with the firmware verbs `randapmac` + `randstamac`.

### Fixed

- **Stale `scanap` WS key on Marauder firmware ≥ v1.11.1.** Marauder
  upstream merged `scanap`/`scansta` into `scanall` in v1.11.1+ and
  removed the legacy verbs from `CommandLine.h`. The web Marauder synth
  panel still keys `scanap` and `scansta` (frontend / WS / tests), but
  now sends `scanall` on the wire for both keys. The AP/STA parser pair
  is preserved so the UI still gets filtered event streams per click.
- **`wifi_evil_portal_stop` mis-banded as High risk.** The stop verb
  only terminates an already-active TX (i.e. it de-escalates) — same
  shape as `wifi_stop_scan`. Demoted to Low and moved to the Low
  classifier in `internal/risk/risk.go`. `wifi_evil_portal_start`
  remains High.

## [0.14.0] - 2026-04-29

### Added

- **Synthesised Marauder TFT panel in the web UI.** New
  `internal/web/api_marauder.go` adds a WS command registry that maps
  stable client-side keys (`scanap`, `sniffbeacon`, `attack_deauth`,
  `blescan`, `gpsdata`, `led_set`, …) to Marauder CLI commands +
  per-line / block parsers in `internal/marauder/parsers/`, dispatched
  via Exec / Stream / Block modes. Holder semantics mirror the Flipper
  screen-mirror: one synth-panel hold per server, one streaming
  command per holder, automatic `stopscan` on cancel/disconnect.
  Companion frontend renders a 320×240 ILI9341-look TFT with the full
  firmware menu tree; synth panel is gated behind a JS feature flag
  (`FEATURE_MARAUDER_ENABLED = false`) until a reliable USB-UART
  bridge story is in place — research in this cycle confirmed the
  built-in `USB-UART Bridge` is a scene inside the GPIO app, not a
  loader-launchable target on any current firmware (Momentum,
  Unleashed, RogueMaster, OFW). Backend handlers stay wired so
  flipping the flag re-enables the full panel without further code
  changes.
- **Keyboard input for the Flipper screen mirror.** Arrow keys, Enter,
  and Backspace now drive the held RPC d-pad while the Flipper mirror
  is active and the operator is on the device screen — same WS frame
  shape (`screen_input`, `event_type: short`) as the on-screen d-pad
  click. Gated on `_currentScreen === 'device'` so navigating to
  Files / Audit during a mirror still scrolls those views normally.

### Fixed

- **Flipper mirror confirmation modal could stack indefinitely.** The
  inline `.fs-modal` is a sibling of the START MIRROR button (no
  fullscreen overlay, no pointer trap), so each extra click on START
  appended another prompt on top of the existing one. Added a
  re-entry guard in `showScreenConfirmModal` that focuses the
  existing modal instead of mounting another.

## [0.13.0] - 2026-04-28

### Added

- **Diff preview for medium-risk file writes.** When the agent is about
  to call a tool that writes a file (e.g. `storage_write`), the
  confirmation flow fetches the existing content via `Storage Read`,
  computes a unified line-diff (Myers algorithm, no new dep), and
  renders it in the confirmation modal (web UI: red/green styled
  `<pre>` block) and the REPL prompt (color-coded inline output).
  Tools opt in via the new optional `tools.Spec.WriteIntent
  func(args)(path, content string, ok bool)` field. Diff fetch is
  lazy — runs only when the confirmation gate is about to fire — so
  there's no extra Storage Read on every dispatch. Failure to read
  the existing file degrades gracefully: missing-file → empty old
  side; other errors → polite warning embedded in the Diff field.
  500-line / 64KB cap with a truncation marker keeps modal
  rendering bounded.
- **Direct BLE-to-Marauder transport (`--marauder-ble`).** Promptzero
  now supports standalone ESP32-Marauder devboards over BLE,
  bypassing the Flipper UART bridge entirely. Mirrors the proven
  Flipper BLE transport pattern: full 4-file build-tag dance
  (`!darwin || (darwin && cgo)` real impl, `darwin && !cgo` stub,
  plus darwin/other direct-connect helpers). Service UUID
  `4fafc201-1fb5-459e-8fcc-c5c9c331914b`, no flow-control credit
  characteristic (ESP32-Marauder firmware doesn't expose one —
  writes bounded by ATT MTU only). Mutually exclusive with
  `--marauder-bridge` (clear error if both are set). Reuses the
  existing `--ble-discover` for address resolution. New
  `marauder.transport: "ble"` config key.

### Changed

- **Phase B compat-layer migration.** 15 additional Flipper command
  methods migrated from inline `if f.IsBLE() {...}` branches to the
  `f.dispatch()` helper from Phase A: GPIOSet, GPIORead, LoaderOpen,
  LoaderClose, InputSend, the 9 storage CLI commands
  (List/Read/Remove/Mkdir/Stat/FSInfo/Rename/MD5/Tree), and
  PowerRebootDFU. The 9 sites that don't fit dispatch's
  `(string, error)` signature (USB-only methods returning
  bool/slice/error-only — DesktopIsLocked, StorageWriteCtx,
  LoaderList, etc.) stay on inline branches. Behavior preserved
  byte-for-byte; existing tests pass without modification.

### Fixed

- **Release workflow's darwin/amd64 build was pinned to the retired
  `macos-13` runner.** GitHub Actions removed `macos-13` from the
  hosted runner pool in late 2025; the matrix job sat in `queued`
  indefinitely, the gated release job never started, and v0.12.0's
  binaries never published. Switched to `macos-15-intel`, the
  current x86_64 macOS label. Also pinned `macos-latest` to the
  explicit `macos-15` (Apple Silicon) so a future runner-pool bump
  to macos-26 can't silently retarget the darwin/arm64 build.

## [0.12.0] - 2026-04-27

### Added

- **Operation modes (`--mode`).** Five named modes — `standard`,
  `recon`, `intel`, `stealth`, `assault` — gate the agent's tool
  surface against the existing `tools.Group` taxonomy. `Standard`
  preserves today's behavior (everything allowed); `Recon` is
  read-only/scan-only (no RF transmit, no writes); `Stealth`
  disables Marauder + Sub-GHz + NFC for minimal RF footprint;
  `Intel` adds analysis tools to the Recon baseline; `Assault`
  matches Standard but advertises explicit-TX intent. Switch via
  `--mode <name>` flag, `mode:` config key, or REPL `/mode <name>`
  slash command. Tools rejected by the active mode return a clear
  `ErrBlockedByMode` naming the tool and the mode.
- **Pipeline profiles (`--pipeline`).** Three named retry/timeout
  bundles — `fast` (lower latency, fewer retries), `balanced`
  (default — matches today's hardcoded constants byte-for-byte),
  `resilient` (more retries + longer delays for flaky links). Each
  profile carries CLI/RPC/file-write retry counts + per-op timeouts +
  reconnect-attempt delay. Switch via flag or `flipper.pipeline`
  config key. Existing per-op overrides (`flipper.exec_timeout`,
  `flipper.write_file_timeout`) still win when set explicitly.
  Manual selection only this round; auto-tune from observed
  success-rate is a follow-up.
- **Structured connection diagnostics report.** `flipper.ConnectURL`
  now returns a `*ConnectionReport` alongside the `*Flipper`
  capturing each connect step (`transport.open`, `transport.dial`,
  `handshake`/`rpc.open`, `detect_capabilities`) with
  PASS/WARN/FAIL/SKIPPED level + name + detail + elapsed. Default
  one-line `Flipper connected ...` UX is preserved; verbose mode
  (`PROMPTZERO_LOG_LEVEL=debug` or `PROMPTZERO_VERBOSE_CONNECT=1`)
  prints every check inline; `/api/device` adds a
  `connection_report` field for programmatic consumption.
- **Firmware compatibility / command-routing foundation.** New
  `internal/flipper/compat.go` defines `CommandRoute` (TextCLI /
  RPC / USBOnly), `CommandSupport`, and a single `RouteFor()`
  decision function that reads the existing `Capabilities`
  (FirmwareFork etc.) without duplicating detection. New
  `(*Flipper).dispatch(operation, support, viaCLI, viaRPC)` helper
  centralises transport-aware routing. `DeviceInfo`, `PowerInfo`,
  and `Reboot` migrated as proof; the remaining ~24 commands stay
  on inline `if f.IsBLE()` and will migrate in a follow-up.

- **Hybrid mode is fully functional: BLE Flipper + USB-bridged Marauder
  active simultaneously.** `LaunchBridge` on BLE drives the firmware into
  USB-UART bridge mode the canonical way: opens the GPIO app via
  `app_start_request`, then sends a single `gui_send_input_event(OK)`
  which selects the default-highlighted "USB-UART Bridge" menu item. The
  scene's `on_enter` calls `usb_uart_enable()` with default config
  (`gpio_scene_usb_uart.c:38`), flipping the Flipper's USB CDC into a
  UART passthrough to the Marauder. BLE keeps the Flipper CLI alive in
  parallel — `promptzero_flipper_connected=1` and
  `promptzero_marauder_connected=1` together. Replaces the never-working
  legacy `loader open "USB-UART Bridge"` shortcut on Momentum (that name
  is a menu label, not a registered launchable).
- **All 17 FAP launcher shortcuts now work over BLE.** `LoaderNFCMagic`,
  `LoaderMFKey`, `LoaderMifareNested`, `LoaderPicopass`, `LoaderSeader`,
  `LoaderT5577MultiWriter`, `LoaderSubGHzBruteforcer`,
  `LoaderSubGHzPlaylist`, `LoaderProtoView`, `LoaderSpectrumAnalyzer`,
  `LoaderSignalGenerator`, `LoaderNRF24Mousejacker`, `LoaderNRF24Sniffer`,
  `LoaderUARTTerminal`, `LoaderSPIMemManager`, `LoaderUnitemp`, plus the
  I2C scanner fallback — refactored to delegate to `LoaderOpen()` so the
  BLE-RPC dispatcher fires. Previously they called `f.Exec("loader open
  ...")` directly which would hit `ErrCommandRequiresUSB` on BLE.

### Fixed

- **MARAUDER status pill in the web UI updates within seconds of the
  bridge attaching.** `/api/device` was polled every 30 s, so the pill
  could stay grey for half a minute after a successful Marauder bridge
  launch (which completes ~5 s into startup). Drop the cadence to 5 s
  to match the server-side `deviceCacheTTL`, and re-poll on
  `visibilitychange` so a user returning to the tab sees a fresh state
  immediately instead of one stale frame.
- **Screen mirror survives navigation away from `/device`.** The
  auto-release in `activateRoute` was tearing down the holder whenever
  the user clicked Files / Audit / Settings. The keepalive timer is
  bound to `_screenState.isHolder`, not to the visible route, so the
  mirror's RPC stream can live across nav. Returning to `/device`
  rebinds the canvas and refreshes LIVE/HELD/OFFLINE without
  re-establishing the stream.
- **`classifyBridgeRejection` recognises Momentum's "Application X not
  found" response.** The legacy substring matchers ("app not found",
  etc.) missed the firmware's actual response shape, which let the
  bridge launcher false-success on Momentum and report a phantom
  Marauder connection. Added markers for the `Application "..." not
  found` shape so the failure surfaces as `ErrBridgeRejected` instead.

- **BLE-to-Flipper now works end-to-end via Protobuf RPC.** Flipper
  firmware exposes RPC, not text CLI, on its BLE Serial endpoint
  (`applications/services/bt/bt_service/bt.c` pipes inbound bytes
  straight into `rpc_session_feed`; no text CLI handler is wired).
  PromptZero now detects BLE transport at connect time, opens a
  persistent `rpc.Client` against the link with `WithSkipStartRPCSession`
  (no text preamble — the firmware is already in RPC mode), and routes
  every BLE-feasible operation through that client instead of through
  text-CLI `Exec`. Connect time is ~5 s on darwin (down from a 25 s
  timeout pre-fix). Verified end-to-end with `Unholy · Momentum mntm-dev`
  identification during capability detection.
- **30+ Flipper commands now route via RPC on BLE.** Domain coverage:
  - System: DeviceInfo, PowerInfo, Reboot, PowerRebootDFU.
  - Storage: List, Read, Write, Remove, Mkdir, Stat, FSInfo, FSInfoMap,
    Rename, MD5, Tree (StorageCopy is USB-only — no RPC verb).
  - GPIO: Set, Read.
  - Application: LoaderOpen, LoaderClose, NFCEmulate (transitively).
  - GUI: InputSend.
  - New BLE-only commands: `DesktopIsLocked`, `DesktopUnlock`,
    `PropertyGet`. These have no CLI equivalent on this firmware and
    return `ErrCommandRequiresUSB` on USB transports.
- **Clear `ErrCommandRequiresUSB` for non-RPC commands on BLE.** The
  56 commands without RPC verbs in firmware (sub-GHz, NFC, IR, RFID,
  iButton, BadUSB, Loader{List,Info,Signal}, etc.) return a wrapped
  error naming the operation and instructing the operator to attach
  the Flipper via USB instead of a generic "release the mirror"
  message. `errors.Is(err, ErrCommandRequiresUSB)` works for callers
  that need to distinguish.
- **`Flipper.LaunchBridge(ctx, command)` method.** Replaces the
  hard-coded `Exec("loader open ...")` in the Marauder bridge launcher
  with a transport-aware verb: USB sends the literal CLI text; BLE
  parses the `loader open "App Name" args...` shape and dispatches via
  `LoaderOpen` → `app_start_request` RPC.
- **`--ble-discover` flag.** Scans for nearby BLE peripherals and prints
  a table of name + address + RSSI, plus a copy-pasteable `ble://`
  command for the strongest-signal Flipper. Replaces the prior workflow
  of "run with `PROMPTZERO_LOG_LEVEL=debug` and grep the scan log" —
  the equivalent of `bleak --scan` or `core-bluetooth-tool devices`.
- **`ble://` URL accepts UUIDs and device names.** In addition to the
  existing hardware-MAC form (`ble://80:E1:26:69:6E:55`), the dialer
  now recognises CoreBluetooth identifier UUIDs
  (`ble://e127efc1-05ec-ce53-014e-b79fee9117fa`) and bare device
  LocalNames (`ble://Unholy`). Forms are picked by shape and route to
  different scan-match logic at runtime.

### Changed

- **`tinygo.org/x/bluetooth` upgraded v0.14.0 → v0.15.0.** v0.15.0's
  darwin notification + service-discovery fixes are what unblocked
  ATT-layer encryption negotiation on macOS — previously CoreBluetooth
  silently refused to deliver indications/notifications on Flipper's
  authenticated-read characteristics. With v0.14.0 the Ping handshake
  timed out after BLE link establishment; v0.15.0 round-trips it.
- **BLE Serial GATT layout corrected against firmware ground truth**
  (`flipperzero-firmware/targets/f7/ble_glue/services/serial_service.c`).
  Promptzero now resolves all four characteristics: `RX` (`...fe62`,
  host-writes, also exposed via the new `flipperBLERXCharUUID`),
  `TX` (`...fe61`, host-reads-via-indications), `FlowCtrl` (`...fe63`,
  host subscribes for uint32 BE buffer-credit updates from the
  firmware's `ble_svc_serial_notify_buffer_is_empty` publisher), and
  `Status` (`...fe64`, observation-only). Earlier code only knew
  about TX+RX and didn't subscribe to FlowCtrl, which caused the
  firmware's flow-control loop to silently throttle traffic.
- **CoreBluetooth UUID byte-order helper.** `cbgo` reflects custom
  service/characteristic UUIDs in their on-the-wire little-endian
  byte order on darwin (Linux/BlueZ presents them in canonical
  big-endian). The new `uuidsMatch` helper compares UUIDs in either
  endianness so the same hardcoded constants work cross-platform.
- **macOS BLE now uses the canonical CoreBluetooth pattern.** When
  given a UUID-form address, `bleTransport.establish` skips the scan
  entirely and calls `Adapter.Connect` with the stored identifier —
  which wraps `retrievePeripherals(withIdentifiers:)` per Apple's
  "Best Practices for Interacting with a Remote Peripheral Device"
  guide. Saves up to 30 s on every reconnect for paired Flippers.
  Falls back to a full scan if the CoreBluetooth peripheral cache no
  longer has the identifier (BT stack restart, etc.).
- **`bleTransport.mac` field renamed to `addr`** (with a sibling
  `addrKind` enum) to stop lying about what's stored — on darwin the
  value has always been a UUID, the type just claimed otherwise.
- **GitHub Actions bumped to Node 24-native majors across all four
  workflows.** GitHub-hosted runners no longer ship Node 20, so every
  affected action ran under the `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24`
  override with a deprecation warning. Bumps: `actions/checkout` v4→v5,
  `actions/setup-go` v5→v6, `actions/upload-artifact` and
  `actions/download-artifact` v4→v5, `actions/github-script` v7→v8
  (kept on v8 because v9 is ESM-only and would break the inline
  `require()` in coverage-diff), `golangci/golangci-lint-action` v7→v9
  (matches the pinned golangci-lint v2.11.4),
  `github/codeql-action/*` v3→v4, `anchore/sbom-action` v0→v0.24.0,
  `sigstore/cosign-installer` v3→v4 (cosign v3+ support),
  `softprops/action-gh-release` v2→v3. The redundant Node-24
  force-override env var was dropped from all four workflows.

### Fixed

- **`ble://<MAC>` URLs no longer hang on macOS.** macOS CoreBluetooth
  hides hardware MACs from apps for privacy and substitutes a per-Mac
  peripheral identifier UUID; `tinygo.org/x/bluetooth` reflects that
  on darwin. Before this change the dialer required `net.ParseMAC`
  format and the scan match did literal MAC-string comparison, so
  every `ble://<MAC>` URL on macOS scanned for 30 s and timed out
  with "no flipper found". Diagnosed via `PROMPTZERO_LOG_LEVEL=debug`
  scan results that returned UUIDs instead of MACs.

- **BLE works in released macOS binaries.** The release workflow now
  builds darwin targets on macOS runners with `CGO_ENABLED=1` instead
  of cross-compiling from Linux. Previously every macOS user who
  installed via the curl-piped `install.sh` got a binary where any
  `ble://` transport hit `transport/ble: darwin BLE requires a macOS
  build with CGO enabled` at runtime. The release pipeline is now a
  matrix-split build → aggregate-and-sign release flow.
- **Real BLE implementation now compiles on darwin.** `ble.go`'s build
  constraint changed from `!darwin` to `!darwin || (darwin && cgo)`,
  and `ble_darwin.go` is constrained to `darwin && !cgo`. A native
  macOS build with CGO links the full `tinygo.org/x/bluetooth` stack;
  CGO-disabled builds fall back to the existing stub. The transport
  test file gained a matching constraint so `go test` works on darwin
  with CGO enabled (it previously failed to build at all).

## [0.11.0] - 2026-04-27

### Added

- **Header session info pill.** The screen-title meta row now surfaces
  the active model and a running prompt-cache hit rate alongside the
  existing phase indicator — e.g.
  `claude-opus 4.7 · prompt-cache 87% · ready`. Operators can see at a
  glance which model is serving them and whether the cached prefix is
  being reused. The row stays hidden until the cache counters move so
  fresh sessions don't render an empty pill.
- **`/api/cost` cache fields.** The `total` block gains
  `cache_read_tokens`, `cache_creation_tokens`, and `cache_hit_rate`
  (0..1). The snapshot already tracked these — only the JSON
  projection was missing.

### Changed

- **Idle mascot redesigned as Gengar.** The 11×9 dolphin sprite is
  replaced with a 56×52 Gengar derived from the canonical Gen 4 HGSS
  sprite. Cells map to body / dim teeth / red eyes (a new "e" pixel
  class), so the eye region animates independently from the
  silhouette. Idle motion is layered: a continuous slow eye pulse
  plus random-jitter bursts for blink, glow, float, and laugh
  scheduled per-effect so motion never feels metronomic. Bursts
  respect `prefers-reduced-motion`.
- **Tool calls collapse by default.** Each tool entry in the agent
  scroll now renders inside a `<details>` element: the meta row
  (name + risk + status) is the always-visible `<summary>`, while
  the JSON input/output and any error bodies live inside a hidden
  content block that toggles on click. Native `<details>` handles
  a11y (keyboard + screen-reader) for free.

### Fixed

- **Stale streaming bubbles.** A new user message and the start of a
  tool call now both tear down any lingering blink-cursor bubble
  before proceeding. Previously, if the server didn't emit a clean
  `response`/`error` for the prior turn, the next `text_delta` would
  visually merge into the old bubble even though a tool had executed
  between them.

## [0.10.1] - 2026-04-27

### Fixed

- **`gofmt` violation in `internal/marauder/bridge_test.go`.** The
  initial v0.10.0 cut included hand-aligned method signatures that
  `gofmt -d` flagged on its second pass; CI's lint job rejected the
  commit. Functional behaviour is unchanged — release binaries
  shipped from v0.10.0 work — but anyone cloning at the v0.10.0 tag
  and running `task lint` would have hit a failure. v0.10.1
  re-bundles the same feature with the formatting fix.

## [0.10.0] - 2026-04-27

### Added

- **Marauder bridge mode (`--marauder-bridge`).** Drives the ESP32
  Marauder over the Flipper Zero's USB-UART Bridge app when the
  Marauder is physically stacked on the GPIO header — a single USB
  cable to the Flipper now serves both devices. The bridge app is
  launched via `loader open "USB-UART Bridge"` (override per
  firmware fork via `--marauder-bridge-command` or the
  `marauder.bridge_command` config field). While the bridge is
  active, `flipper_*` tools return `flipper offline (UART bridge
  active)` and the `/status` banner shows the suspension. Press
  BACK on the Flipper to exit; PromptZero does not auto-recover
  (manual restart).
- **Hybrid bridge mode (BLE + USB).** With
  `--transport "ble://AA:BB:CC:DD:EE:FF" --marauder-bridge
  --marauder-port /dev/ttyACM0`, the USB-CDC interface drives the
  Marauder while the BLE-side CLI stays alive — both devices
  usable concurrently. Requires native Linux or macOS (WSL2 does
  not expose Bluetooth).
- **`flipper.Suspend(reason)` / `IsSuspended` / `SuspensionReason`.**
  Public API for marking a Flipper handle inactive. Every CLI
  method (`ExecCtx`, `ExecLongCtx`, `StreamCtx`, `WriteFileCtx`,
  `Reconnect`) gates with `ErrFlipperSuspended` when set.
- **`marauder.ConnectViaFlipper`.** Helper that orchestrates the
  bridge launch, port reopen, and retry loop. Transport-aware:
  `serial` → suspend, `ble` → keep CLI alive, `http`/`mock` → refuse.

### Changed

- **`MarauderConfig`** gains `bridge`, `bridge_command`,
  `bridge_settle`, and `bridge_port_reopen_timeout` fields. Defaults
  applied at use-site (750ms settle, 5s reopen timeout, default
  bridge command for Momentum / Unleashed / RogueMaster / OFW 0.99+).
- **`--transport` flag help** updated to reflect that BLE is real
  and requires a native host (was "reserved; Phase-B").

## [0.9.4] - 2026-04-27

### Added

- **Collapsible grouped sidebar.** The flat MAIN MENU rail is now
  organised into three groups (SESSIONS / DEVICES / SYSTEM) with
  per-group expand/collapse and a global icons-only collapse toggle.
  Both states persist in `localStorage`
  (`promptzero_rail_collapsed`, `promptzero_rg_<group>_collapsed`).
- **Quick Actions popover.** New TX-line accessory (lightning button)
  opens a categorised list of shortcut prompts. Selecting one loads
  the prompt into the input for review/edit before transmit, rather
  than firing it directly. Risk pill shows on each item.
- **Full semver version on the web UI.** Boot splash and status-bar
  brand now show the full version (e.g. `v0.9.4`) instead of a
  hardcoded `v0.9` label. Rendered server-side via a tiny template
  pass over `index.html` so the version is correct on first paint —
  no JS round-trip, no flicker.
- **Version line on the CLI banner.** `printBanner` now prints
  `version.String()` (e.g. `v0.9.4 (abc1234 built 2026-04-27)`) below
  the tagline so the running build is visible at startup, not just
  via `--version`.

### Changed

- **Rail items reorganised.** Removed: Sub-GHz, RFID, NFC, IR,
  iButton, GPIO, BadUSB, Apps (these are driven by the agent /
  quick-actions, not standalone screens). Kept under DEVICES:
  Flipper Zero, Marauder, Files. Kept under SYSTEM: Audit Log,
  Report, Settings.

### Fixed

- **Persona banner no longer says "0 tools allowed" for the default
  persona.** An empty allowlist means *unrestricted* (all tools
  pass through `FilterTools`), not zero. Matches the wording already
  used by the `/persona` switch handler in `commands.go` —
  unrestricted personas show "all tools allowed", restricted ones
  show the count.

## [0.9.3] - 2026-04-27

### Changed

- **Mirror canvas now scales fluidly to fill the Device panel.** Was a
  fixed 512×256 (desktop) / 384×192 (mobile). Now uses container
  queries (`container-type: size` on `.screen-panel`) with
  `width: min(1024px, 100cqw, calc((100cqh - 170px) * 2))` so the
  canvas grows along whichever dimension is tighter while keeping the
  2:1 aspect ratio and reserving room for the status / buttons / hint
  below. Pixelated render preserved.

### Fixed

- **Device panel no longer scrolls.** The subscreen container is now a
  flex column (`display: flex; flex-direction: column`), and the
  `.screen-panel` switched from `height: 100%` to `flex: 1 1 auto`.
  Previously the panel sized against the full subscreen — including
  the ~40 px subscreen-header sibling — so total content exceeded the
  container by exactly the header's height, triggering a scrollbar
  that pushed the STOP MIRROR control out of view.
- **`BUILT BY XUNHOLY` credit no longer covered by scrollbar.** Right
  offset bumped 12 → 40 px (mobile 8 → 26 px) so it stays clear of the
  subscreen scrollbar on screens that legitimately scroll (Files,
  Settings) where the scrollbar sits at most ~22 px from the LCD edge.

## [0.9.2] - 2026-04-27

### Added

- **Dpad drives the live mirror via RPC** (`Gui.SendInputEventRequest`).
  When the operator holds the screen mirror, dpad presses are routed
  through the held RPC session as a new WS frame `screen_input
  {button, event_type}` — the dpad is no longer locked out while
  mirror owns the serial port. The dpad auto-hides outside mirror
  mode (it'd just 409 against the locked CLI input/send), and gets a
  bright orange tint + "MIRROR" badge while you're holding it.
  Each tap dispatches `PRESS → SHORT → RELEASE` to match what
  qFlipper sends — the firmware's RPC input handler does NOT
  synthesise SHORT from press/release the way the hardware path
  does, so apps subscribing to `InputTypeShort` need the explicit
  event.

- **Live LCD screen mirror in the web UI** (qFlipper-style). New
  **Device** rail item opens a panel that streams the Flipper's
  128×64 framebuffer to a Canvas at the device's native ~30 fps,
  upscaled with nearest-neighbour. Acquire is exclusive (one session
  at a time) and gated behind a confirmation modal warning the
  operator that all chat / file / input operations pause while the
  mirror is active. Auto-releases on navigate-away, browser close,
  or 30 s without a keepalive. Visibility-aware: rendering pauses
  when the tab is hidden but the lock stays held.
- **Flipper protobuf RPC client** (`internal/flipper/rpc/`). Vendors
  the upstream `.proto` files at a pinned commit (license noted in
  `LICENSE_NOTICE.md` — upstream is currently unspecified), generates
  Go bindings (committed under `pb/`), and implements the
  length-prefixed framing + a typed `Open` / `Close` / `Ping` /
  `StartScreenStream` / `StopScreenStream` surface. `Open` drains
  the firmware's CLI echo of `start_rpc_session\r` then verifies the
  RPC transition with a Ping handshake, so callers get a clean error
  instead of a misparsed first frame.
- **`*flipper.Flipper.EnterRPC`**: takes the flipper mutex, switches
  the transport into RPC mode, and returns the RPC client + a
  release closure that restores CLI mode and re-handshakes the
  prompt before unlocking. CLI methods (`ExecCtx`, `ExecLongCtx`,
  `StreamCtx`, `WriteFileCtx`) now reject with `ErrInRPCMode` while
  RPC is active so a stale concurrent CLI op can't corrupt the
  protobuf framing.
- **WebSocket `screen_*` taxonomy**: inbound `screen_acquire`,
  `screen_release`, `screen_keepalive`; outbound `screen_state`
  (broadcast on every transition with `holder_session_id` + `reason`),
  `screen_error`, plus binary `screen_frame` (1-byte format version +
  1024-byte packed framebuffer). Newest-frame-only forwarder on the
  server keeps input-to-render latency below one device frame even
  when the WS writer is slow.
- **Audit entries**: `web.screen.start` (medium risk),
  `web.screen.stop` (low risk).
- **Taskfile**: `proto:gen` and `proto:check` targets for protobuf
  binding regeneration.

### Changed

- `/api/fs/*`, `/api/input/send`, and `/api/device` now return 409
  Conflict with `{"error":"flipper screen mirror is active",
  "code":"mirror_active","retry_after_release":true}` while a mirror
  session is held. Frontend renders inline messages (no modals).
- Agent chat (`text` + `audio` WS frames) returns an `error` event
  to the originating session when mirror is active, instead of
  queueing a turn that would fail downstream.
- `/api/debug` snapshot includes a new `state.mirror_active: bool`
  field for diagnostic dumps.

### Fixed

- **RPC handshake retry loop** — `start_rpc_session\r` echo length
  varies between firmware builds and device states; a single 300 ms
  drain wasn't always enough and the first protobuf read could
  misparse. `Open()` now retries the Ping up to 5 times with a 150 ms
  drain between attempts.
- **Cross-platform build** — production handlers (`api_fs.go`,
  `api_input.go`, `api_screen.go`) carried `//go:build linux` tags
  inherited from the test pattern, breaking darwin/windows builds.
  Tags moved to test files only. `internal/flipper/mock` and
  `internal/testmocks` (Linux pty) and `cmd/webtest` (POSIX signals)
  now declare their constraints explicitly.
- **CLI 409 polling spam** — the frontend's 30s `/api/device` poll
  was logged by the browser as "failed resource load" while mirror
  was active. Skip the poll entirely while held; status arrives via
  `screen_state` WS frames anyway.
- **Arrow glyphs match** — left dpad arrow used U+25C4 (POINTER), all
  others used the TRIANGLE family. Normalised to `▲ ▼ ◀ ▶` so they
  read as the same icon set.

### Changed

- Settings rail icon swapped from sun-burst (circle + 8 radial lines)
  to a proper 8-tooth cog SVG.
- Category landing screen badge `RUN ▶` shortened to `RUN` — reads
  cleaner alongside the LOW/MED/HIGH siblings.
- Prompt bar prefix `promptzero>` shortened to `>` — brand already
  lives in the status bar.

## [0.9.1] - 2026-04-26

### Added

- **Direct Flipper navigation in the web UI** (qFlipper-style file
  browser + virtual D-pad), running alongside the existing chat. New
  rail item **Files** opens a two-pane SD-card browser with read-only
  preview of `.sub` / `.nfc` / `.rfid` / `.ir` / `.txt` formats; binary
  files render as base64. Action buttons in the preview (Replay, Emulate,
  Send, Run) synthesise a chat turn so the existing risk-confirm flow
  applies — no new risk surface. Upload, delete, mkdir, rename are gated
  behind in-pane confirms and audited as `web.fs.*`.
- **D-pad SCROLL ↔ DEVICE toggle**: the on-screen d-pad now optionally
  forwards button events to the Flipper via `POST /api/input/send`,
  audited as `web.input.send`. Default mode (`scrollback`) preserves
  the existing chat-navigation behaviour.
- **`/api/fs/*` endpoints**: `list`, `read` (256 KiB cap), `stat`,
  `upload` (1 MiB cap, configurable via `Server.SetMaxUploadBytes`),
  `delete`, `mkdir`, `rename`. All require bearer auth and reject paths
  outside `/ext`.
- **`/api/input/send`** for short-event button dispatch.
- **UI-context plumbing**: a new `ui_context` WebSocket frame tells the
  agent which file the operator is currently browsing; the agent prompt
  gains a `<ui-context view="..." path="..."/>` line so questions like
  "what is this?" land in the right context. View values are
  allowlisted server-side to prevent prompt-attribute injection.
- **Awesome Flipper Zero ecosystem index**
  (`docs/awesome-flipper-zero-projects.md`): flat catalog of every
  Flipper-Zero-adjacent repo discovered as of 2026-04-26, plus an
  appendix flagging adversarial bundles for the firmware-allowlist /
  payload-blocklist Specs.

### Changed

- **`--web` mode starts without a Flipper attached** so the operator
  can open the cockpit and plug the device in later. REPL and `--mcp`
  modes keep the original fatal connect behaviour.
- Web UI shell now fills the entire viewport on every breakpoint
  instead of the boxed `min(1280px, 96vw)` cap; bezel screws and the
  redundant "PZ" wordmark icon removed. Subtle "BUILT BY XUNHOLY"
  watermark added in the LCD bottom-right.
- Subsystem rail items (Sub-GHz, RFID, NFC, IR, iButton, GPIO, Bad
  USB, Apps, Marauder) now open a category landing screen listing
  likely tools/attacks. Low-risk read-only items (e.g. "List installed
  FAPs", "Read tag") show `RUN ▶` and dispatch immediately; med/high
  risk or items with `<placeholder>` parameters prefill the prompt
  for review.
- Every sub-screen (settings root + children, audit, report, files,
  category) now has an on-screen `◀ BACK` button. Files screen back
  walks up the directory tree before exiting; settings children pop
  to the settings menu first.
- Sub-screen rail items now use the LCD palette on hover (legible
  against the orange background), and all chevrons normalised to the
  same Unicode glyph and 8 px size.

### Removed

- **PromptZero Companion FAP**: dropped the on-device status renderer
  (`fap/companion/`, `internal/flipper/companion/`,
  `cmd/install-companion-fap/`, `bin/fap/`, `setupCompanion`,
  `Server.SetCompanion`, `CompanionConfig`, the `fap:companion:*`
  Taskfile targets). The Flipper CLI refuses commands while any FAP is
  open ("this command cannot be run while an application is open"), so
  a host that drives the device over CLI cannot also have an on-device
  companion app running. The risk-confirm gate now lives only in the
  REPL/web surfaces.

## [0.9.0] - 2026-04-26

First tagged release since v0.5.0. Collapses four development tranches
(v0.6 OSS-expansion → v0.9 web redesign) into a single semver release;
the per-tranche labels in commit subjects remain as historical markers.

### Added — v0.9 web redesign

- **Flipper-themed web UI** (`internal/web/static/`): rewritten with a
  hardware-shell layout — bezel chrome, dot-matrix LCD scrollback, side
  rail, and chunky d-pad. Reactive across desktop / tablet / phone with
  safe-area insets, hover-none and reduced-motion paths, ≥44 px touch
  targets, and iOS zoom suppression. All agent-originated content goes
  through `createElement` + `textContent`; no `innerHTML` carries
  untrusted data.
- **Typed `/api/device` sections** for the new status bar: `flipper`,
  `marauder`, `ble`, `sd` (uint64 bytes), `battery.percent` (numeric).
  Existing string-shaped fields preserved for back-compat.
- **PromptZero Companion FAP** (`fap/companion/`,
  `internal/flipper/companion/`, `cmd/install-companion-fap/`):
  optional Flipper application that renders agent events on the device
  LCD and lets OK/Back answer the high-risk confirm gate. NopSink is
  the default — operators without the FAP run unchanged.
- **Marauder firmware lazy-probe**: non-blocking goroutine populates
  `marauder.firmware` after connect; first `/api/device` returns empty,
  subsequent return populated.
- **canbus tool**: expanded coverage and first unit test file.

### Fixed — v0.9

- crypto1 polish: small bug fixes and expanded fixtures across mfcuk,
  mfkey32, mfoc, and RecoverFast (iterations on the v0.7 native ports).
- Faultier client + tool spec touch-ups (faultier, firmware_extract,
  mifare, spec).

### Added — v0.6 OSS-expansion: outbound federation + cracker primitives

Driven by a multi-agent dev team: 1 lead + 3 parallel engineers (Crypto1,
KeeLoq, pcap) + cross-cutting wiring on the lead thread. ~7000 LOC
across 9 new packages.

- **`internal/mcpfed/`** (new) — outbound MCP client federating external
  servers as native Specs. Stdio/HTTP/SSE transports, sandbox profiles
  (none/docker/bwrap/firejail) wired via `transport.WithCommandFunc`,
  prefix `__` namespacing within Anthropic's 64-char tool-name limit,
  schema pass-through via `mcp.Tool.RawInputSchema`, MCP annotation →
  `risk.Level` mapping (DestructiveHint→Critical, ReadOnlyHint→Low,
  OpenWorldHint→+1 tier), one-shot retry on `ErrTransportClosed` plus
  background health pings. Boot integration in
  `cmd/promptzero/setup.go:setupMCPFederation`; config block in
  `config.example.yaml` under `mcp_clients:[]` with six high-leverage
  examples (FuzzingLabs hub, pm3-mcp, Hashcat-MCP, BloodHound-MCP-AI,
  Burp, GhidraMCP). Operator guide:
  `docs/integrations/mcp-federation.md`.

- **`internal/keeloq/`** (new) — pure-Go KeeLoq cipher
  (32-bit block, 64-bit key, 528 rounds, NLFSR with S-box 0x3A5C742E),
  CPU brute-force sharded across `runtime.NumCPU()` (~12M keys/sec on a
  16-core host), and a manufacturer-key dictionary covering HCS-200/300/360/410.
  Specs: `keeloq_decrypt` (Low), `keeloq_dictionary` (Medium),
  `keeloq_bruteforce` (Critical). Closed-loop verified plus published
  test vector cross-checked against an independent Python reference.

- **`internal/pcap/`** (new) — pure-Go libpcap classic writer +
  radiotap-header builder (link-types 1/105/127). Closes the WiFi
  capture → hashcat chain in `workflow_wifi_target_to_hashcat`.

- **`internal/defense/`** (new) — Wall-of-Flippers heuristic classifier
  for BLE advertisements. Detects Apple Continuity spam (action types
  outside the published set), Microsoft Swift Pair malformed payloads,
  Samsung sentinel model-id, Google Fast Pair repeated-byte signatures,
  and Flipper service UUID 0xFE60. Stateful `Tracker` adds high-frequency
  MAC-rotation detection. Spec: `defense_classify_advertisement` (Low).

- **`internal/containerbridge/`** (new) — shared sandboxed `docker run`
  runner powering three new Specs:
  - `urh_decode_sub` (Low, GroupFlipperSubGHz) — PentHertz/urh-ng SubGHz
    classifier across 327 known protocols.
  - `firmware_extract` (Medium, GroupFlipperHW) — onekey-sec/unblob
    recursive firmware extractor.
  - `fap_build` (Medium, GroupGen) — flipperdevices/ufbt SDK build with
    optional Flipper-side deploy.

- **`internal/tools/corpora.go`** (new) — three read-only Specs that
  search operator-curated asset directories (no third-party content
  bundled — license clarity + staleness avoidance):
  - `ir_irdb_lookup` — Lucaslhm/Flipper-IRDB layout.
  - `evil_portal_template_pick` — HTML/JS templates by brand+language.
  - `badusb_payload_search` — Ducky-script grep by goal keyword.
  Default paths from `PZ_IRDB_DIR`, `PZ_EVIL_PORTAL_DIR`, `PZ_BADUSB_DIR`.

### Changed

- **`internal/risk/`** — added `Register/Unregister` runtime overlay so
  federated MCP tools (and any post-init Spec) publish risk levels
  without touching the static `toolLevels` map. `Classify` consults the
  overlay first; static fallback unchanged.
- **`internal/config/`** — added `MCPClients []yaml.Node` field for raw
  federation config. Decoded by `mcpfed.ParseClientConfigs` so config
  remains independent of the federation runtime.

### Registry

- 188 → 198 Specs (+10 native + N federated at runtime).

### Hardware backends (Wave 0b / 3c / 3d / 3e / 4a / 4b)

Six new device backends added — all written against documented
upstream protocols, no bench validation in this session, users
exercise on real hardware:

- **HTTP transport** (Wave 0b) — `internal/flipper/transport/http.go`.
  Targets jblanked/FlipperHTTP-compatible servers. Long-poll recv +
  streaming POST send + bearer-token auth + custom-path overrides.
  `http://host:port[/?token=...&send_path=...&recv_path=...]` URL
  scheme parallel to `serial://` and `ble://`. Decouples agent from
  physical USB session.

- **Faultier glitcher** (Wave 3c) — `internal/faultier/` (329 + 170 +
  222 + 208 + 353 LOC across client/protocol/mock/protocol_test/
  client_test). Six Specs in `internal/tools/faultier.go`:
  `glitch_arm` / `glitch_fire` / `glitch_set_pulse` / `glitch_sweep` /
  `glitch_disarm` / `glitch_status`. Wire protocol mirrored from
  hextreeio/faultier-python.

- **CANbus** (Wave 3d) — `internal/tools/canbus.go`. Six Specs:
  `canbus_init` / `canbus_sniff_start` / `canbus_sniff_stop` /
  `canbus_inject` / `canbus_replay` / `canbus_info`. Bridges to
  ElectronicCats/flipper-MCP2515-CANBUS .fap via the existing
  `flipper_raw_cli` mechanism.

- **Bus Pirate 5** (Wave 3e) — `internal/buspirate/` (engineer-written
  client/parser/mock with comprehensive tests). Seven Specs in
  `internal/tools/buspirate.go`: `buspirate_mode` / `buspirate_i2c_scan` /
  `buspirate_spi_dump` / `buspirate_uart_bridge` / `buspirate_voltages` /
  `buspirate_pin_set` / `buspirate_pin_read`. PIO-driven I2C up to
  500 kHz, much faster than Flipper GPIO bit-banging.

- **Bruce ESP32** (Wave 4a + 4b absorbed) — `internal/bruce/`. Twelve
  Specs in `internal/tools/bruce.go`: `bruce_capabilities` /
  `bruce_wifi_scan` / `bruce_wifi_5g_scan` / `bruce_wifi_deauth` /
  `bruce_evil_twin` / `bruce_zigbee_scan` / `bruce_lora_scan` /
  `bruce_ir_send` / `bruce_ir_receive` / `bruce_badusb_run` /
  `bruce_nfc_read` / `bruce_raw_cli`. Boot-banner parser detects
  ESP32-C5 (HasFiveGHz=true), M5Stack family (Cardputer / M5Stick /
  T-Display / CYD), and IR hardware presence. Evil-M5Project hardware
  uses a Bruce-compatible serial dialect, so it's covered by the same
  backend.

### MIFARE Classic key recovery (Wave 1a + 1c)

`internal/crypto1/` filled in end-to-end:
- `Init`, `Crypt`, `EncCrypt`, `CryptFeedback`, `Prng`, `clockLFSR`
  — all clean-room implementations of the Garcia et al. ESORICS 2008
  algorithm.
- Filter functions `fa` / `fb` / `fc` and bit helpers wired per the
  paper's tap arrangement.

`internal/crypto1/mfkey32.go`:
- `Recover` / `RecoverWithRange` — Courtois-style LFSR rollback against
  two captured authentication exchanges. Closed-loop verified with
  three synthetic key vectors.
- `AuthEncrypt` — simulates the reader-side auth so callers can produce
  test vectors without hardware.

`internal/tools/mifare.go` rewired:
- `mfkey32_recover` returns `status="found"` with the recovered key.
  Default 16-bit search range completes in ~70 ms; operators pass
  `search_range_bits` up to 48 for full keyspace.
- `mfoc_attack` and `mfcuk_attack` return `status="live_nfc_required"`
  with an error pointing operators at the federated `pm3-mcp` MCP
  server (their canonical libnfc form requires live NFC reader access
  which the Flipper's USB CLI doesn't expose).

`internal/tools/hardnested.go` (Wave 1c) — `mifare_hardnested_host`
Spec wraps `nfc-tools/mfoc-hardnested` in a sandboxed container for
Plus / EV1 hardened-nonce key recovery. Default image
`ghcr.io/nfc-tools/mfoc-hardnested:latest`; operators override via
`HARDNESTED_IMAGE` env or `image` argument.

### Boot integration

`cmd/promptzero/setup.go` gains `setupBruce` / `setupFaultier` /
`setupBusPirate` parallel to `setupMarauder`, all wired into
`cmd/promptzero/main.go`'s startup sequence. `internal/agent/agent.go`
gains `SetBruce` / `SetFaultier` / `SetBusPirate` setters and
forwards the new clients into `a.deps()` so handlers see them via
`tools.Deps.{Bruce,Faultier,BusPirate}`.

`internal/config/config.go` adds `BruceConfig`, `FaultierConfig`, and
`BusPirateConfig` types under `bruce:` / `faultier:` / `buspirate:`
YAML keys.

### Registry

- 198 → 230 Specs (+32 native Specs in this batch).
- All 32 new Specs explicitly classified in
  `internal/risk/risk.go`'s `toolLevels` map.
- `TestRegistrySize` / `TestRegistryCoverage` / `TestRiskCoverage`
  green; full module passes `go test -race -short ./...`.

### Deferred to v0.6.1+

- Wave 1b — pure-Go `mfoc_attack` / `mfcuk_attack` offline
  implementations with state-propagation across nested authentications.
  Today operators handle this via federated `pm3-mcp` for the live
  case, or pre-process captures into mfkey32 tuples and call
  `mfkey32_recover` directly.
- `mfkey32_recover` partial-state-enumeration optimization — current
  impl is O(2^32) within the configured `search_range_bits` budget
  and adequate for the common case (default keys, low-entropy keys);
  full 2^48 needs the Garcia §4 filter-selectivity technique to be
  agent-fast.
- Pure-Go `mifare_hardnested_host` reimplementation (the ~2 kloc
  bitslice optimisation in `nfc-tools/mfoc-hardnested`). Container
  bridge ships today.

## [0.5.0] - 2026-04-25

v0.5 opens the offensive-capability expansion track. This release
absorbs attack-tool coverage from established pentest projects as
**native Go code** — no outbound MCP federation, no runtime deps on
external tools, `go build` still produces a single binary. Five
shipping deliverables across research, firmware introspection,
offline key recovery, host-side security recon, and CI tooling.

Driven end-to-end by a 12-agent development team: 1 architect + 4
parallel researchers + 5 parallel engineers (2 retries after the
first pair stalled) + 1 tester + 1 security reviewer, orchestrated
through the same wave + hardware-gate pattern that shipped v0.4.

### Added — offensive capabilities

- **`firmware_introspect` Spec** (Low risk, `GroupFlipperSystem`) —
  capability oracle. Returns the connected Flipper's fork
  (OFW/Unleashed/Momentum/Xtreme/RogueMaster), version band, commit,
  build date, and a 23-flag feature bitmap the LLM consults before
  any fork-gated tool call. Eliminates trial-and-error on heterogeneous
  firmware. Backed by 15 real `device_info` fixtures (3 per fork) and
  expanded detection rules for 8 new capabilities beyond the v0.4 set.

- **`iclass_loclass_recover` Spec** (High, `GroupFlipperNFC`) — pure-Go
  port of the loclass attack against HID iCLASS Elite (High Security).
  Recovers per-site `Kcus` from 8 captured reader-authentication
  exchanges. Algorithm from García/de Koning Gans/Verdult/Meriac
  ESORICS 2012; clean-reimpl, not a source-port. All 5 published
  sub-primitive vectors (Hash0, Hash1, Hash2, PermuteKey, DoReaderMAC)
  pass. Offline only — no card I/O.
  New package: `internal/iclass/` (1,296 LOC).

- **4 Tier-1 host-side recon Specs** in new `internal/tools/security.go`
  (group: `GroupSecurity`):
  - `hash_identify` (Low) — heuristic hash-format detection for
    MD5/SHA-1/SHA-256/SHA-512/NTLM/bcrypt/Argon2 etc.
  - `hash_crack_dictionary` (Critical) — pure-Go offline dictionary
    attack. Algorithms include NTLM (MD4 of UTF-16LE) and bcrypt.
  - `port_scan_tcp` (High) — TCP connect scan via `net.Dial` with
    concurrency cap and per-port timeout.
  - `http_enum_common` (High) — directory/file enumeration against
    HTTP servers with built-in wordlist corpus.

- **`internal/wordlists/`** — embedded password + directory wordlist
  subsets (SecLists top-N + dirb common.txt subset). Exposed as MCP
  resources (`promptzero://wordlists/...`) and consumable by the
  Tier-1 recon Specs.

- **`mfoc_attack`, `mfcuk_attack`, `mfkey32_recover` Specs** (High,
  `GroupFlipperNFC`) — registered as **stubs** for v0.5. Handlers
  return a structured "scheduled for v0.5.1" message with operator
  workaround (use `loader_mfkey` FAP for in-device mfkey32; use
  `nfc_dump_protocol mfc` for capture). The 34 KB algorithm
  reference at `docs/refactor/mifare-algorithms.md` is the
  substantive v0.5 contribution here; v0.5.1's wave-2 lands the
  `internal/crypto1/` impl + replaces the stub Handlers.

### Added — tooling & research

- **`cmd/coverage-diff`** — scrapes awesome-flipperzero lists
  (djsime1, RogueMaster, xMasterX, jamisonderek, UberGuidoZ), parses
  tool/verb names, diffs against `internal/tools/` Spec names, outputs
  a markdown report of what's available upstream that PromptZero
  doesn't yet expose. New GitHub workflow runs it weekly with
  `continue-on-error: true`.

- **Research corpus** at `docs/refactor/`:
  - `firmware-matrix.md` (48 KB) — per-fork `device_info` field
    reference, CLI verb diff, version-band regexes, capability
    bitmap; flags 5 errors in the architect's initial runbook.
  - `mifare-algorithms.md` (34 KB) — Crypto1 LFSR tap resolution
    (conflict between mfoc and proxmark3 was notation-only, not
    algorithmic), filter truth tables, 5 test vectors.
  - `iclass-loclass-algorithm.md` (24 KB) — loclass sub-primitive
    vectors and synthetic fixture path (avoids GPL provenance on
    iceman's `iclass_dump.bin`).
  - `mcp-feature-extraction.md` (50 KB) — capability inventory for
    4 reference MCPs (mcp-security-hub, pentest-mcp, Hashcat-MCP,
    pm3-mcp), Tier 1/2/3 triage for future ports.
  - `v0.5-runbook.md` (34 KB) — per-engineer assignments, capability
    bitmap design, Crypto1 cipher contract, license posture
    classification.

### Changed

- **Capability bitmap** in `internal/flipper/capabilities.go` expanded
  from the v0.4 baseline. Three `Stock` defaults corrected (research
  caught 3 wrong values in the v0.4 code):
  - `PowerInfoCmd` stock default flipped to `info power` (no modern
    fork uses `power_info` as a top-level verb).
  - `SubGHzRxRawHasFilePath` stock default flipped to `false` (every
    modern fork streams `subghz rx_raw <freq>` to stdout).
  - `NFCFlaggedArgs` gated on `FirmwareAPIMajor` (modern OFW
    dev/1.x ships flagged NFC CLI).

- **MCP server** (`internal/mcp/server.go`) gains `promptzero://` URI
  resource scheme for embedded wordlists, plus a documentation
  block clarifying the `_confirmed` ↔ Risk-tier equivalence that
  operators migrating from pm3-mcp expect.

### Deferred to v0.5.1

- **Crypto1 cipher full implementation** — the v0.5 wave's most
  algorithmically tight scope; two engineer attempts did not converge
  against the 5 test vectors within the engineering window. The
  skeleton + vectors + algorithm doc ship in v0.5; the impl moves to
  v0.5.1 via interactive vector-driven debugging.
- **Mifare offline crackers** (mfoc/mfcuk/mfkey32 full Handlers)
  unblock once Crypto1 lands.
- **loclass synthetic capture generator CSN selection** — end-to-end
  round-trip test is skipped in v0.5 (`TestLoclassEndToEnd`). The
  actual attack works on real 8-capture input; only the fixture
  generator's Swende-optimal CSN search needs the v0.5.1 followup.
- **`mifare_hardnested_recover`** — seed direction at Meijer-Verdult
  2015 WOOT paper (table-free statistical variant, ~10× slower but
  pure-Go friendly with no 250 GB precomputed tables).

### Tool registry

Registry size: 184 → **188** Specs. Net: +1 firmware_introspect, +4
Tier-1 security, +3 Mifare stubs, +1 iclass_loclass_recover.

### Verified

- `task test:full` — every package passes with `-race`
- `task lint` — 0 issues
- All 4 hardware harnesses green (`hwtest` 23/23, `mifaretest` 12/12,
  `webtest` 9/9, `clitest` 5/5) against real Flipper Zero Momentum
  mntm-dev.
- Default persona unrestricted — every new Spec accessible.
- `TestRiskCoverage` enforces 100% risk-classification coverage of
  the 188 Specs.

## [0.4.1] - 2026-04-24

Patch release: fixes a session-killing bug in conversation-history
compaction that affected any operator running long sessions where the
first prompt invoked a tool (the common case).

### Fixed

- **`compactHistoryLocked` orphaned tool_use at messages.1** when
  `a.history[1]` was an assistant message containing a `tool_use` block
  and `a.history[2]` was the matching user `tool_result`. The hardcoded
  anchor `a.history[:2]` discarded the `tool_result` on first compaction
  (history > 100 entries), leaving the orphan in place. The Anthropic
  API then rejected every subsequent turn with HTTP 400:

      messages.1: `tool_use` ids were found without `tool_result`
      blocks immediately after: toolu_XXXX. Each `tool_use` block
      must have a corresponding `tool_result` block in the next
      message.

  The bug was reproduced by a 35-prompt CLI smoke test (`cmd/cliyolo`)
  that hit it at prompt 24/35 once the live session crossed
  maxHistory. Fix: extend the anchor end forward (up to 8 entries) when
  the last anchor message has a `tool_use`, swallowing the matching
  `tool_result`. Fall back to dropping the anchor entirely if the
  pairing is malformed (defensive).

### Added

- **`cmd/cliyolo`** — PTY-driven CLI runner with a 35-prompt
  non-destructive test set covering every Flipper subsystem (system,
  storage, hardware, NFC, SubGHz, IR, RFID, iButton, audit, BadUSB
  validate, workflow, storage round-trip). Exits non-zero on
  regression so it's CI-ready. Used to prove the fix end-to-end.
- **`cmd/cliprobe`** — minimal one-shot PTY probe used during
  diagnosis. Useful for triaging future REPL issues without burning
  through the full harness.
- Two regression tests in `internal/agent/history_test.go`:
  - `TestCompactHistoryLocked_AnchorWithToolUseExtended` — pins the
    cliyolo failure shape (first turn invokes a tool, history saturates,
    no orphan in compacted result).
  - `TestCompactHistoryLocked_AnchorMalformedDropsAnchor` — confirms
    the drop-anchor fallback when the pairing is broken.

### Verified

- All 4 hardware harnesses pass (`hwtest`, `mifaretest`, `webtest`,
  `clitest`) on a real Flipper Zero (Momentum mntm-dev).
- `cliyolo` 35/35 PASS in 19 minutes against the live device.
- `task test:full` — every package passes with `-race`.
- `task lint` — 0 issues.

## [0.4.0] - 2026-04-24

Tool-registry refactor. Every tool used to live in three places —
`internal/mcp/server.go` (MCP `s.add()`), `internal/agent/tools.go`
(Anthropic schema declaration), `internal/agent/agent.go` (dispatch
switch case) — and drift between those layers caused real
user-facing bugs (device_info vs system_info naming drift,
storage_write registered in MCP but undispatched in the agent,
nfc_dump_protocol sending the wrong protocol token to Momentum).

This release collapses those three paths into a single
`internal/tools` registry. Every tool now lives in exactly one
`Spec{}` definition; both MCP and the agent dispatcher consume the
same registry. Adding a new tool is one edit instead of three;
naming drift, risk drift, and "MCP missing what agent has" become
structurally impossible.

### Changed

- **`internal/tools` is now the single source of truth for every
  tool.** 179 Specs split across 33 files by category
  (`system.go`, `storage.go`, `subghz.go`, `ir.go`, `nfc.go`,
  `rfid.go`, `ibutton.go`, `badusb.go`, `js.go`, `fileformat.go`,
  `wifi.go`, `marauder.go`, `nrf24.go`, `loader.go`, `hw.go`,
  `audit.go`, `target.go`, `vision.go`, `rag.go`, `generate.go`,
  `build.go`, `workflows.go`). Each Spec carries Name, optional
  Aliases, Description, Schema, Required, Risk, Group, AgentOnly,
  and Handler. The agent's `dispatch()` and the MCP server's
  registration both iterate `tools.All()`.
- **`Spec.Aliases` handles synonym tools.** `device_info` is the
  canonical name; `system_info` is registered as an alias. Both
  resolve to the same Handler via `tools.Get`. The MCP adapter
  advertises both names; the agent's Anthropic schema declares
  both.
- **`Deps` is the dependency bag both modes inject.** `Flipper`,
  `Marauder`, `Audit`, `Config` are always wired; the LLM-only
  facilities (`Generator`, `GenLLM`, `Vision`, `Snapshot`,
  `SessionID`, `RAG`, `TargetMem`, `WorkflowConfirm`) are nil for
  MCP mode. `AgentOnly: true` Specs are excluded from the MCP
  surface; they're the only handlers permitted to dereference the
  LLM-only fields.
- **`Deps.SnapshotBeforeWrite` lifted as a helper** so handlers
  that clobber SD content (`storage_write`, `storage_copy`,
  `storage_rename`, `fileformat_edit`, all `*_build`,
  `generate_*`, `nfc_read_save`, `run_payload`,
  `generate_deploy_run`) call one method instead of duplicating
  the snapshot-then-write dance per handler.
- **`Deps.RequireMarauder` lifted as a helper** for WiFi tool
  nil-tolerance.

### Added

- **`storage_write` is now exposed to the LLM via the agent.**
  Previously only MCP clients could call it; the agent could only
  write structured payloads via `generate_*` / `*_build`. The
  bare-bytes write path closes that gap. Risk: Medium.
- **Hardware integration harnesses under `cmd/`** (`hwtest`,
  `mifaretest`, `webtest`, `clitest`) used by the orchestrator
  between every wave of the migration. The harnesses ship with the
  repo and remain reusable for future changes.
- **48 KB migration runbook** at `docs/refactor/registry-migration.md`
  with the full pre-refactor inventory, per-wave tool assignments,
  worked migration template, edge-case coverage, and acceptance
  criteria.

### Fixed

- **`device_info` ↔ `system_info` naming drift.** The MCP
  catalogue used `device_info`; the agent dispatch only matched
  `system_info`. The registry's alias mechanism fixes this — both
  names now resolve.

### Removed

- **All `s.add()` calls in `internal/mcp/server.go`.** Server
  shrunk from 1,204 to 276 lines.
- **All `case "<name>":` branches in `internal/agent/agent.go`'s
  `dispatch()`.** Function shrunk from a 700-line switch to a
  4-line registry lookup. Whole file shrunk from 2,927 to 1,233
  lines.
- **All hand-written `tool()` declarations in
  `internal/agent/tools.go`.** File shrunk from 825 to 145 lines;
  Anthropic schema is now derived from the registry.

## [0.3.3] - 2026-04-23

Scanner-loop fix for Momentum firmware. The v0.3.2 work got the loop
iterating correctly but still reported "no tag detected" on a card
that was clearly in range, because the parser and detection signal
were tuned for the older firmware output shape that includes a
`UID:` line. Momentum's scanner subcommand emits only
`Protocols detected: Mifare Classic` (no UID/ATQA/SAK) — the loop
kept retrying until timeout looking for a UID that will never appear
at this layer.

### Changed

- **Scanner-loop detection signal now matches Momentum's shape.**
  `looksLikeNFCDetection` recognises both the older
  `UID:` / `UID =` form AND the newer `Protocols detected:` /
  `Protocol detected:` form. The loop breaks immediately on either
  so live scan time drops from the full 8 s timeout budget to
  ~1.2 s when a card is present.
- **`ParseNFCDetect` fills `Type` from `Protocols detected:`** when
  no explicit `Type:` line is present. Callers see
  `Detected=true` with a concrete protocol family even on firmware
  that doesn't emit UID from scanner alone.

### Fixed

- **NFC use case reported "no tag detected" on a card in range.**
  Root cause: older detection signal only accepted `UID:` as a
  "card present" marker. Now fixed — live-Flipper `task usecases
  -- -category=nfc` run with a Mifare Classic on the reader
  reports `detected Mifare Classic` in 1.2 s.
- **`nfc_read_save` handler was silent about the Momentum UID gap.**
  Now returns an actionable message pointing at
  `nfc_dump_protocol` + `loader_mfkey` when scanner detected a
  Classic family but didn't provide UID, so operators know the
  next step instead of staring at a half-done scan.

### Verified

- `task test:full` — every package passes with `-race`
  (new `TestParseNFCDetect_MomentumProtocolOnly` locks the parser
  against this regression).
- `task eval` — **12/12 scenarios** pass.
- `golangci-lint run ./...` — 0 issues.
- Live-Flipper `task usecases` with Mifare Classic on reader:
  **pass=16 skip=3 fail=0** (unchanged counts, NFC detection
  latency 8.7 s → 1.2 s, correct protocol family reported).

## [0.3.2] - 2026-04-22

Two live-Flipper session bugs caught by a new operator-task harness —
both classes of "the tool returned success but did the wrong thing",
which is the category of failure that most reliably makes the agent
thrash. Fixed at the primitive layer so every tool inherits the
improvement.

### Added

- **`cmd/flipper-usecases` — operator-task runner.** Complementary to
  `flipper-validate`: that binary tests primitives one-by-one; this
  one tests *intent*, running realistic short natural-language
  prompts ("scan this NFC card" / "what's on my Flipper" / "listen
  on 433 MHz for 3 seconds") and reporting concise results. 19 use
  cases across health / storage / nfc / rfid / subghz / ir / bt /
  apps / feedback / deliberate-skip categories. Runs against a live
  Flipper via the existing serial transport — no LLM required. New
  `task usecases` target.

### Fixed

- **NFC subshell exit left the CLI in the `[nfc]>:` context.** After
  `NFCDetect` returned (especially on the no-detect path), subsequent
  `subghz rx` / `ir rx` / `bt hci_info` commands were rejected by the
  subshell with "could not find command" — yet primitives leaked the
  rejection text as successful empty output, so the agent saw
  `success=true` and retried downstream operations on corrupted state.
  Fix: belt-and-braces exit sequence (Ctrl+C → exit → CR round-trip
  → optional retry) that verifies the main shell is responsive
  before returning.
- **`Exec` / `ExecLongCtx` treated "could not find command" output as
  a silent success.** Every primitive above these now surfaces a
  structured `cli rejected "<verb>": <rejection-text>` error when
  the firmware didn't recognise the command — so the agent (and the
  use-case runner) see the real state instead of an empty-but-OK
  response.
- **`flipper-usecases` SD-info summary showed 0 GB** because the
  runner read `fs["total"]` / `fs["free"]` while `StorageFSInfoMap`
  emits `totalSpace` / `freeSpace`. Now reads the correct keys.

### Verified

- `task test:full` — every package passes with `-race` (two new
  `TestExec_UnknownCommandSurfacesAsError` /
  `TestExec_EmptySuccessStaysSuccess` regression locks).
- `task eval` — **12/12 scenarios** pass (unchanged from v0.3.1).
- `golangci-lint run ./...` — 0 issues.
- Live-Flipper `task usecases` run against Momentum firmware:
  **pass=16 skip=3 fail=0** across all nine non-skip categories.
  Before this release the same run returned incorrect data on
  SD info, IR, BT, apps, and SubGHz duration — all now correct.

## [0.3.1] - 2026-04-22

Quality-raising tranche (Batches A–G) plus two direct operator-feedback
fixes that landed after the live-Flipper run. The broad theme: stop the
agent from thrashing on tasks an operator can do manually in seconds.

### Added

#### Quality layers
- **Extended thinking + prospective reflection** (Batch A). Persona YAML
  gains a `thinking:` map with per-tier token budgets (Sonnet/Opus).
  Critical-risk tools get a Haiku-backed pre-dispatch critique appended
  as `<prospective-critique>` so the main model can back off before
  transmitting.
- **Per-tool context sheets + target memory** (Batch B). `internal/toolctx`
  bundles compile-time cheat sheets auto-appended to tool descriptions
  (Princeton TE timing, ATQA/SAK layouts, BadUSB delay rules, and more).
  `internal/targetmem` persists per-target facts (BSSIDs, UIDs, freq
  tuples) across sessions via SQLite; new `target_remember` /
  `target_recall` / `target_forget` tools.
- **Verify-everywhere on parametric builders** (Batch C). `subghz_build`
  / `rfid_build` / `ir_build` / `nfc_build` now run the Haiku verifier
  on the output bytes before the SD-card write. High/critical verdicts
  block unless `verify_bypass=true`. New RFID verifier prompt added.
- **BM25 documentation RAG** (Batch D). `internal/rag` with embedded
  corpus and `docs_search` tool. Pure-Go lexical retrieval — no
  embedding service required. Tokeniser splits snake_case tool names
  so `pmkid` matches `wifi_sniff_pmkid`.
- **Adversarial scenarios + confidence scoring** (Batch E).
  `internal/confidence` pre-dispatch scorer abstains on missing
  required keys or placeholder values (TODO / fixme / `<fill_in>`).
  Three new eval scenarios (confidence, prompt-injection quarantine,
  placeholder vocabulary).
- **Fine-tuning dataset export** (Batch F). `internal/trainset` +
  `/export training-set <path>` in the REPL. JSONL and OpenAI chat
  formats. `--success-only` and `--min-level` filters.
- **Fine-tune operator runbook** (Batch G). `docs/fine-tuning.md` —
  Axolotl QLoRA config, hardware sizing, vLLM serving recipe, explicit
  reminder that a local fine-tune does not replace the safety stack.

#### NRF24 Mousejack toolkit (end-to-end)
Research-first delivery: Momentum firmware has no nrf24 CLI; everything
routes through the Sniffer + Mousejacker FAPs. This release builds the
full toolkit around that surface.

- `nrf24_sniff_start` (Medium) — launches the NRF24 Sniffer FAP.
- `nrf24_list_targets` (Low) — parses `/ext/apps_data/nrfsniff/addresses.txt`
  with case normalisation and malformed-line warnings.
- `nrf24_payload_build` (Medium) — synthesises DuckyScript for
  `/ext/mousejacker/<name>.txt` with a mousejack-specific 5000 ms DELAY
  cap (2.4 GHz injection loses sync on longer pauses). Runs the BadUSB
  static validator — same lexical surface, free destructive-pattern
  detection.
- `nrf24_mousejack_start` (Critical) — launches the Mousejacker FAP.
- `workflow_mousejack` — composes list_targets → build_payload →
  re-gate FAP launch via `ConfirmSubtool` → launch. Approving the
  composite no longer silently approves keystroke injection.

#### NFC scan-and-save
- `nfc_read_save` (Medium) — the missing "scan this fob" tool.
  Composes `NFCDetect → DeviceType mapping → BuildNFC → verify → write`
  to `/ext/nfc/scanned_<uid>.nfc`. Type mapping covers NTAG213/215/216,
  Classic 1K/4K, Ultralight, DESFire. Classic-family tails the output
  with a pointer at `loader_mfkey` + `loader_mifare_nested` so the
  model proposes key-recovery rather than stopping at UID-only.

#### Campaigns, Eval, and Operator UX
- **Campaigns** (`workflow_*` composite) — declarative multi-step
  engagements with dependency gating and when-clauses.
- **Golden eval harness** — `task eval` runs 12 scenarios covering
  handoff, snapshots, ATT&CK constraints, detectors, tool errors,
  campaigns, confidence, prompt-injection quarantine, placeholder
  vocabulary, mousejack payload validation, NRF24 target parsing,
  and NFC read-save file shape.
- **WPA3 / SAE capture path** — `wifi_sniff_sae` tool wrapping the
  Marauder's raw sniff with a 60 s default and the
  deauth → capture recipe documented in-result.
- **SubGHz multi-band sweep** — `subghz_freq_sweep` generates one
  bruteforce .sub per frequency (315/433.92/868/915 MHz) in one call.
- **MIFARE attack-chain grounding** — cheat sheets for `loader_mfkey`,
  `loader_mifare_nested`, `loader_nfc_magic`, `loader_picopass`,
  `loader_seader`. The primitives already existed; the model now has
  cached guidance on when to chain each.

### Fixed

- **NFC `scanner` subcommand is one-shot on Momentum** — previously
  `NFCDetect` ran it once (~1 s) and returned "Target lost" if the
  card wasn't already on the reader when the call fired. Now loops
  the subcommand inside the nfc subshell until detection or the
  caller's timeout budget is exhausted, matching the on-device Read
  button's UX.
- **`nfc_read_save` success=true on no-detect** — used to return the
  helper string with `err=nil`, so audit recorded success and the
  agent retried forever. Now returns an error on no-detect; audit
  shows `success=false` and the agent surfaces a clean prompt to
  the operator instead of thrashing.
- **Quarantine bypass via `fileformat_read`** — SD-card file values
  are attacker-writable; the read path now wraps output in
  `<untrusted-hardware-output>`.
- **`wifi_deauth` description contradicted its Critical risk tier** —
  replaced "No restrictions" with "AUTHORIZED LAB/PENTEST USE ONLY"
  + FCC 47 CFR § 15 pointer.
- **Workflow per-primitive re-gating** — composite workflows like
  `workflow_badusb_target_profile` no longer silently approve the
  internal `badusb_run` call. `ConfirmSubtool` hook re-asks via the
  same idle-timeout confirm path.
- **`Run()` held `a.mu` across the 5-minute confirm gate** — added
  `turnMu` for turn serialisation; `a.mu` is released around
  `confirmWithIdleTimeout` so `SetPersona` / `RunTool` / status
  readers can proceed during operator idle.
- **`requiredKeys` rebuilt the tool catalog on every dispatch call** —
  2-5 ms tax per tool call eliminated via `sync.Once` cache.
- **RAG index lazy-init held `a.mu` for the 100-500 ms corpus build** —
  moved outside the lock via double-check locking.
- **`--min-level=<typo>` silently dropped the filter** in the
  trainset exporter. Unknown levels now reject up front instead of
  mapping to the zero value.
- **`targetmem` and `confidence` packages shipped as orphans** —
  `targetmem` now wired via CLI setup + three live tools; `confidence`
  runs in `executeTool` before `dispatch` and abstains on weak inputs
  with a `low-confidence input` tool error.
- **Snapshot retention was unbounded** — `snapshot.Manager.Rotate`
  trims per-session history to `DefaultRetention = 100` entries,
  invoked lazily from `storeSnapshot`.
- **NFC verifier too lenient** — prompt now catches SAK/DeviceType
  mismatch, MIFARE Classic sector-trailer Access Bits errors,
  missing/zero KeyA/KeyB, block-count overflow, NDEF-on-Classic.

### Verified

- `task test:full` — every package passes with `-race`.
- `task eval` — **12/12 scenarios** pass.
- `golangci-lint run ./...` — 0 issues.
- Live Flipper validator (Momentum firmware, real Mifare Classic
  on the reader): **39 pass / 0 fail / 8 skip**. `NFCDetect(8s)`
  returns `Protocols detected: Mifare Classic` in ~9 s wall-clock.

## [0.3.0] - 2026-04-22

Landmark release — every item in the P0 and P1 tranches of
`docs/specs/roadmap.md` is delivered. Major additions span agent
reliability, operator UX, report generation, snapshot-based undo,
and MITRE ATT&CK-aware tooling.

### Added

#### Agent reliability (P0)
- **Anthropic prompt caching** on the system prompt + tool catalog
  (`cache_control: ephemeral`). Sessions longer than 3 turns drop
  ~70–90% input-token cost and 1–2 s first-token latency. Cache
  hit-rate visible via `/stats cache`.
- **Cost-tier per-tool model routing.** Personas declare
  `models: {classify: haiku, generate: sonnet, plan: sonnet,
  exploit: opus}` in YAML; the agent picks the right tier per call.
- **`flipper.state` oracle** injected on every turn as a
  `<device-state>` JSON block so the model stops burning tool calls
  on "what's connected?" / "what mode are you in?" questions.
- **Dynamic tool-catalog narrowing (opt-in)** via Haiku-tier router
  that picks relevant tool groups; 60–80% fewer tool-description
  tokens on scoped turns. Falls back to full catalog on any router
  failure. Enable with `EnableDynamicCatalog`.
- **Reflexion-on-error loop** — tool failures trigger a classify-
  tier self-critique appended inside `<reflection>` tags. Capped
  at 3 reflections per user turn.
- **Prompt-injection quarantine** — hardware-returned output (WiFi
  SSIDs, NFC tag URIs, storage reads, etc.) wrapped in
  `<untrusted-hardware-output>` tags; ANSI / control-byte
  sanitisation; system-prompt clause tells the model to treat those
  blocks as data, never instructions.

#### Quality + differentiation (P1)
- **MITRE ATT&CK integration.** New `internal/attack` package with
  14 curated techniques and 30+ tool-to-technique mappings.
  Audit entries tag every tool call with the ATT&CK path.
  Per-session constraint via `/attack set T1557.004 T1499`.
- **Structured handoff artifact.** Each session autosave captures
  `{findings, open_threads, blocked, device_state_at_compact}` so
  `/session resume` prepends the handoff as a `<handoff-resume>`
  user message and the model picks up exactly where it left off.
- **`/rewind` SD snapshots.** Every SD write (fileformat_edit,
  storage_copy / rename, generator deploys, parametric builders)
  snapshots the pre-write content. Supports `/rewind <id>`,
  `/rewind <n>` pop-N-count, `/rewind list`, and dry-run.
- **Detector abstraction.** `rules.DetectorEngine` runs
  LLM-as-judge detectors concurrently after each tool call.
  Built-in detectors: `wifi_deauth_success`,
  `pmkid_capture_validity`, `nfc_clone_fidelity`. Verdicts
  surface as `<detector-verdict>` JSON in tool output and in
  `/report` output.
- **Session `/report` generator.** `internal/report` package
  renders a Markdown engagement report with risk-tier breakdown,
  tool usage table, MITRE ATT&CK coverage heatmap (with deep
  links), detector verdicts, and timeline. Save with
  `/report <session-id> save`.
- **OpenTelemetry GenAI exporter.** Honours
  `OTEL_EXPORTER_OTLP_ENDPOINT`; emits `gen_ai.*` spans per agent
  turn + child tool-call spans with input/output/cache token
  attributes. Noop when unset.
- **Parametric file builders.** New tools `subghz_build`,
  `rfid_build`, `ir_build`, `nfc_build`, and
  `subghz_bruteforce_generate` synthesise correctly-framed
  Flipper files from typed parameters. NFC UID byte-length
  validated against device type.
- **Boxed TX preview + `[R]evise`.** High/critical confirm
  prompts render a Unicode-boxed preview with frequency-in-MHz
  annotations. Operator presses `r` to enter a revision prompt;
  the agent skips the tool and re-plans with the operator's
  edit. Backed by a 2s enforced delay gate.
- **Few-shot examples** on high-priority tool descriptions
  (`subghz_transmit`, `subghz_receive`, `nfc_emulate`,
  `rfid_write`, `badusb_execute`, `wifi_evil_portal_start`).
- **Chain-of-verification** on `generate_*` tools. A Haiku-tier
  verifier checks the generated content for known failure modes
  (evil-portal form action, BadUSB OS mismatch, out-of-band
  SubGHz frequency, etc.). Blocks deploy at severity high/critical
  unless the operator passes `verify_bypass`.
- **Deterministic response parsers** for Marauder
  `scanap` / `list -a` / `list -c`, Flipper `nfc_detect`,
  `storage info`, and `subghz rx`. Model sees structured JSON
  instead of free-form output.
- **Structured `ToolError`** replacing the free-form
  `"error: ..."` string. Carries `code`, `tool`, `message`,
  `excerpt`, `remediation`, `retryable`, and optional
  `device_state` at failure time.

#### REPL + observability
- `/rewind`, `/report`, `/attack`, `/stats` slash commands.
- Cache hit-rate + cache-read / cache-creation tokens in
  `cost.Snapshot` and `/cost` output.
- OpenTelemetry traces with `gen_ai.*` attributes.

### Changed

- `ConfirmFunc` return type widened from `Decision` to
  `ConfirmResponse{Decision, Revision}` to carry revision text
  alongside the decision. All in-tree callers updated (REPL, web,
  e2e tests).
- `Agent.SetUsageCallback` now receives a `Usage` struct with
  cache tokens alongside input / output totals.
- `fileformat_edit`, `storage_copy`, `storage_rename`, and every
  `generate_*` path snapshot their destination before writing so
  `/rewind` can restore.

### Fixed

- NFC UID byte-length mismatch in `BuildNFC` (4-byte UID on NTAG215
  would previously produce a syntactically valid but semantically
  wrong file; now rejected with a clear error).
- UTF-8-safe truncation in `ToolError.Excerpt` and
  `HandoffArtifact` previews — multi-byte runes no longer split.
- `snapshotBeforeWrite` propagates caller `ctx` so the warn-log
  carries the turn's trace ID.
- Path-traversal guard on `/report <id> save` — session IDs are
  restricted to alphanumeric + `_-`.

### Security

- Hardware-returned strings sanitised + wrapped in
  `<untrusted-hardware-output>` tags before reaching the model,
  closing a class of prompt-injection vectors where a malicious
  SSID / NFC URI could direct the agent.
- 2 s enforced confirm-delay on high-risk actions (Warp-style).

### Removed

- **BREAKING:** MQTT bridge and the `mqtt:` config block. No surveyed
  competitor shipped an equivalent and every use case MQTT covered here
  is already handled by webhooks or audit consumers. Drops the
  `github.com/eclipse/paho.mqtt.golang` dependency, the `/mqtt` REPL
  command, the `promptzero_mqtt_publishes_total` metric, and the `mqtt`
  rule-action kind + `topic` field. Migrate any MQTT subscribers to
  webhook subscriptions (`webhooks:` in config) — same payloads, same
  lifecycle events.

### Added

- Bearer-token auth on `/api`, `/metrics`, and `/ws`. Set `web.token` in
  config or `PROMPTZERO_WEB_TOKEN` in the environment; HTTP callers send
  `Authorization: Bearer <token>` and the browser passes `?token=<token>`
  on the WebSocket URL. Leaving the token empty preserves the old
  no-auth behaviour; the server prints a red warning when that combines
  with a non-loopback bind.
- `web.cors_origins` allow-list for the WebSocket Origin header. Empty
  (default) means same-origin only — the previous `*` wildcard is gone.
- `GET /api/auth` — open endpoint reporting `{"required": bool}` so the
  browser shell knows whether to prompt for a token before opening the
  WebSocket.

### Changed

- Default Claude model bumped from `claude-sonnet-4-6` to `claude-opus-4-7`
  for the agent and the vision analyzer. Existing `model:` values in
  user config override the default; cost pricer already knew about
  opus-4-7 so no math surprises.

## [0.1.0] - 2026-04-18

### Added

- Flipper Zero capability-gap primitives (42 new operations) with mock-backed tests.
- Operator-mode persona registry and `/persona` slash command.
- Filesystem-triggered agent mode via repeatable `--watch` paths.
- Audit query DSL: `/audit find`, `/audit tail`, `/audit top`.
- Composite workflows: `hw_recon_blackbox_device`, `nfc_badge_pipeline`,
  `garage_door_triage`, `phys_pentest_badge_walk`, `badusb_target_profile`,
  `rolljam_lab_demo`, `wifi_target_to_hashcat`.
- Structural read/edit/diff for Flipper `.sub`, `.nfc`, `.ir`, `.rfid` files.
- Outbound HTTP webhooks covering tool, risk, workflow, and audit events.
- Publish-only MQTT bridge for state and event streams.
- Structured `slog` logging with correlation IDs across REPL, agent, and audit.
- `/debug` slash command and Prometheus `/metrics` endpoint.
- Token cost tracking with offline-mode detection.
- Reactive rules engine subscribed to the audit observer.
- BadUSB sandbox preflight validator surfacing Critical/Warn/Info findings.
- BLE transport scheme reserved as a Phase-B stub.
- `--marauder-port` flag for overriding the Marauder serial device.

### Changed

- Flipper package refactored onto a `Transport` interface with a concrete
  serial implementation.
- Pty-based mock migrated to the new `Transport` interface.
- **License: MIT → AGPL-3.0-or-later.** Aligns with the offensive-security
  tooling norm (Metasploit, Nuclei, etc.) so downstream hosted services
  must publish modifications. No change for end users running locally.

### Fixed

- CI green: resolved remaining `gofmt`, `staticcheck`, and `unused` findings
  surfaced by `golangci-lint`.

### Security

- Marauder CLI invocations now sanitise user-supplied strings before shelling
  out.
- BadUSB preflight flags unsafe payloads before execution.

[Unreleased]: https://github.com/xunholy/promptzero/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/xunholy/promptzero/releases/tag/v0.3.0
[0.1.0]: https://github.com/xunholy/promptzero/releases/tag/v0.1.0
