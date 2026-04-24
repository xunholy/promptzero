# MCP feature extraction — v0.5 reference-MCP harvest

**Owner:** Research (task #5).
**Consumer:** Task #10 (MCP Engineer) lands the Tier-1 ports as native
PromptZero Specs in `internal/tools/security.go`.
**Scope:** PromptZero is **not** federating outbound MCP. Every port
below is a clean-reimpl pure-Go Spec, registered through
`internal/tools/registry.go` and surfaced to MCP clients automatically
via `internal/mcp/server.go`'s registry adapter (no edits to that
file). Anything that would require shelling out to a binary at runtime
is in §5 (deferred).

---

## Contents

- §1 — Per-MCP capability inventory (4 references)
- §2 — Pattern catalogue (architectural lessons we should adopt)
- §3 — Tier 1 — must land in v0.5 (concrete Spec proposals)
- §4 — Tier 2 — stretch candidates
- §5 — Tier 3 — explicit deferrals
- §6 — Patterns the architect did NOT pre-call (research delta)

---

## 1. Per-MCP capability inventory

### 1.1 — `FuzzingLabs/mcp-security-hub`

**Shape.** Aggregator: 38 sub-MCPs ship as Docker containers, each
wrapping one upstream binary. The hub itself does not implement any
algorithm — every verb is `subprocess.run("<binary> ...")` with arg
splatting. STDIO + HTTP transports. **No MCP resources, no MCP
prompts.** Tool annotations follow the MCP 2024-11 schema
(`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`).

**Verb inventory** (canonical names; the hub ships 300+ tools, this
table covers the families that overlap with PromptZero's blast
radius):

| Sub-MCP | Verb | Description | Args | External binary | Pure-Go portable? | Risk proposal |
|---|---|---|---|---|---|---|
| nmap-mcp | `nmap_scan` | Port scan / OS fingerprint | `target`, `ports`, `flags[]` | `nmap` (yes) | Wrapper-only (full feature parity needs nmap; basic TCP-connect is portable → see Tier 1 `port_scan_tcp`) | High |
| nmap-mcp | `nmap_script_scan` | NSE script run | `target`, `scripts[]` | `nmap` (yes) | No (NSE is Lua-on-nmap-runtime) | Critical |
| masscan-mcp | `masscan_scan` | Internet-scale SYN scan | `range`, `rate`, `ports` | `masscan` (yes) | No (raw sockets + custom TCP stack) | Critical |
| whatweb-mcp | `whatweb_fingerprint` | HTTP banner + tech ID | `url` | `whatweb` (yes) | Partial (banner grab is trivial; signature DB is the value) | Medium |
| nuclei-mcp | `nuclei_scan` | Template-based vuln scan | `targets[]`, `severities[]`, `templates[]` | `nuclei` (yes) | Partial — see Tier 2 (`http_cve_probe`) for a small subset | High |
| sqlmap-mcp | `sqlmap_scan` | SQLi automation | `url`, `data`, `risk`, `level` | `sqlmap` (yes) | Partial — basic boolean-blind probe is portable; full sqlmap is not | Critical |
| ffuf-mcp | `ffuf_fuzz` | HTTP fuzzer | `url`, `wordlist`, `threads` | `ffuf` (Go binary, yes) | Yes — see Tier 1 `http_enum_common` | High |
| radare2-mcp | `r2_analyze` | Binary RE | `file`, `commands[]` | `radare2` (yes) | No (would need re-implementing r2's analysis) | High |
| binwalk-mcp | `binwalk_extract` | Firmware carving | `file` | `binwalk` (yes) | Partial (Go ports of binwalk exist; large lift) | Medium |
| yara-mcp | `yara_scan` | Pattern match | `file`, `rules` | `yara` (yes) | Yes — `hillu/go-yara` exists, but it cgo-wraps libyara → still wrapper. Pure-Go reimpl is large. | Medium |
| capa-mcp | `capa_analyze` | Capability detection | `file` | `capa` (yes) | No (depends on FLIRT-style sigs) | Medium |
| trivy-mcp | `trivy_scan` | Container/IaC vuln scan | `target`, `format` | `trivy` (Go binary, yes) | Wrapper-only | Medium |
| gitleaks-mcp | `gitleaks_scan` | Secret detection | `repo`, `config` | `gitleaks` (Go binary, yes) | Yes (regex+entropy; small lift) | Medium |
| searchsploit-mcp | `exploitdb_search` | Exploit-DB lookup | `query` | local Exploit-DB clone | Yes — JSON snapshot lookup | Low |
| hashcat-mcp | (mirrors §1.3) | — | — | `hashcat` (yes) | Partial — Tier 1 `hash_crack_dictionary` covers the common case | Critical |
| ghidra-mcp | `ghidra_analyze` | Headless decompile | `file`, `script` | `ghidra` + JVM (yes) | No | High |
| prowler-mcp | `prowler_audit` | AWS/GCP/Azure CIS audit | `provider`, `checks[]` | `prowler` (yes) | No (cloud SDK matrix) | Medium |
| boofuzz-mcp | `boofuzz_run` | Network fuzzer | `target`, `protocol` | `boofuzz` (yes) | No (large) | Critical |
| medusa-mcp | `medusa_brute` | Network credential brute | `target`, `service`, `userlist`, `passlist` | `medusa` (yes) | Partial (per-protocol Go libs exist; risky surface) | Critical |

**Error shape.** Each sub-MCP returns the binary's stdout + stderr
inline plus `isError: bool` (the MCP-go convention). No structured
parse — the model is expected to read stderr.

**Resources / prompts.** None at the hub level. A handful of
sub-MCPs (e.g. nuclei-mcp) expose template directories as MCP
resources but the pattern is inconsistent.

**Take-away for PromptZero.** The hub is a **negative example** for
us — its wrapper-only architecture is exactly what the user told us
to avoid. We harvest verb names + arg shapes, not implementations.

---

### 1.2 — `DMontgomery40/pentest-mcp`

**Shape.** Single-process Node/TypeScript MCP. Three transports
shipped in one binary: `stdio` (default), `http` (Streamable HTTP —
recommended), `sse` (deprecated). Bearer-token + OIDC/JWKS auth on
HTTP/SSE transports. **No** MCP resources or prompts; engagement
records are surfaced via the `listEngagementRecords` /
`getEngagementRecord` / `createClientReport` tool family.

**Verb inventory** (18 tools):

| Verb | Description | Args | External binary | Pure-Go portable? | Risk proposal |
|---|---|---|---|---|---|
| `nmapScan` | Network port/OS scan | `target`, `ports`, `flags[]` | `nmap` (yes) | Partial — Tier 1 `port_scan_tcp` covers the common case | High |
| `runJohnTheRipper` | Offline cracking (john) | `hashFile`, `wordlist`, `format` | `john` (yes) | Partial — see Tier 1 `hash_crack_dictionary` | Critical |
| `runHashcat` | GPU-accelerated cracking | `hash`, `mode`, `wordlist` | `hashcat` (yes) | Partial (GPU acceleration not portable) | Critical |
| `gobuster` | Directory/DNS brute | `url`, `wordlist`, `mode` (dir/dns/vhost) | `gobuster` (Go binary) | **Yes** — exact match for Tier 1 `http_enum_common` (and Tier 2 `dns_enum_common`) | High |
| `nikto` | Web-server scanner | `target`, `plugins[]` | `nikto` (yes) | No (large signature DB) | High |
| `subfinderEnum` | Passive subdomain discovery | `domain`, `recursive` | `subfinder` (Go) | **Yes** — see Tier 2 `dns_enum_common` (active variant) | Medium |
| `httpxProbe` | Live host probe | `targets[]`, `statusCode`, `title` | `httpx` (Go) | Yes — net/http only | Medium |
| `ffufScan` | HTTP fuzzer | `url`, `wordlist`, `threads`, `extensions[]` | `ffuf` (Go) | Yes — same as `gobuster` (Tier 1 candidate) | High |
| `nucleiScan` | Template-based vuln scan | `targets[]`, `severity[]`, `templates[]` | `nuclei` (Go) | Partial — Tier 2 `http_cve_probe` is a tiny subset | High |
| `trafficCapture` | Packet capture | `interface`, `count`, `bpf` | `tcpdump` + libpcap (yes) | No (libpcap not portable in pure-Go for live capture) | High |
| `hydraBruteforce` | Network credential brute | `target`, `service`, `userlist`, `passlist` | `hydra` (yes) | Partial (per-protocol; risky surface) | Critical |
| `privEscAudit` | LinPEAS / WinPEAS-style audit | `os`, `mode` | OS-specific scripts | No | Medium |
| `extractionSweep` | SQLi data extraction | `url`, `risk`, `level` | `sqlmap` (yes) | Partial — Tier 2 `sqli_boolean_probe` is the minimal subset | Critical |
| `generateWordlist` | Wordlist creation (custom rules) | `seedWords[]`, `rules` | none | **Yes** — pure transformation | Low |
| `listEngagementRecords` | Pull all execution records | none | none | **Yes** — pattern PromptZero should adopt (see §2) | Low |
| `getEngagementRecord` | Fetch single record | `recordId` | none | Yes | Low |
| `createClientReport` | Assemble report from records | `recordIds[]`, `title`, `sowMode` | none | Yes (template engine) | Low |
| `cancelScan` | Terminate active scan | `scanId` | none (process-mgmt) | Yes — pattern to adopt for our long-running tools | Low |

**Error shape.** Every tool returns
`{ content: [...], isError: true|false }`. Errors are descriptive
strings ("model self-correction" pattern). Schema format is JSON
Schema 2020-12, generated from Zod definitions.

**Annotations.** Every tool ships with the full annotation set
(title, readOnlyHint, destructiveHint, idempotentHint,
openWorldHint). Same shape we already emit in
`internal/mcp/server.go`. ✅ Parity.

**Take-away for PromptZero.** The **engagement-record /
cancel-scan** pattern is the single most-portable architectural
idea here. We already have `internal/audit/` (call log). The
`listEngagementRecords` / `getEngagementRecord` /
`createClientReport` triad maps onto our audit DSL almost
verbatim — see §2 and §6.

---

### 1.3 — `MorDavid/Hashcat-MCP`

**Shape.** Python MCP, single binary, STDIO transport only. Wraps
the `hashcat` CLI. Configurable safe directories via
`HASHCAT_SAFE_DIRS` env var (allow-list of paths the model can
reference). **No** MCP resources / prompts beyond the wordlist
directory env var (which is config, not a real MCP resource).

**Verb inventory** (9 tools):

| Verb | Description | Args (inferred from README) | External binary | Pure-Go portable? | Risk proposal |
|---|---|---|---|---|---|
| `smart_identify_hash` | Heuristic hash-format ID with confidence | `hash` (string) | none (regex+length+charset) | **Yes** — exact match for Tier 1 `hash_identify` | Low |
| `crack_hash` | Single-hash crack | `hash`, `mode` (hashcat -m), `attack` (a0/a1/a3), `wordlist`, `mask?`, `rules?` | `hashcat` | Partial — Tier 1 `hash_crack_dictionary` covers the dictionary-attack case (no GPU, no mask, no rules — those defer) | Critical |
| `crack_multiple_hashes` | Batch crack | `hashes[]`, `mode`, `attack`, `wordlist` | `hashcat` | Partial — same coverage as above; multi-hash is a loop | Critical |
| `auto_attack_strategy` | Pick attack chain heuristically | `hash` or `hashes[]` | `hashcat` | Partial (the heuristic is portable; the underlying crack isn't fully) | Critical |
| `benchmark_hashcat` | Run `hashcat -b` | `mode?` | `hashcat` | No (GPU benchmark) | Low |
| `get_gpu_status` | nvidia-smi / OpenCL probe | none | nvidia-smi | No (hw-specific) | Low |
| `analyze_cracked_passwords` | Password-policy analysis on `.potfile` | `potfile` | none | **Yes** — pure data analysis (entropy, length dist, charset) | Low |
| `generate_smart_masks` | Mask synthesis from corpus | `samples[]` | none | Yes (charset histogram → mask string) | Low |
| `estimate_crack_time` | Wall-clock estimate from H/s + space | `mode`, `keyspace`, `device` | hashcat speed table | Yes (lookup table — but the table is a hashcat artefact, license-flagged → we'd ship our own) | Low |

**Algorithm coverage in `crack_hash`** (relevant for our Tier 1
port — these are the families we MUST support natively):
- `-m 0` MD5, `-m 100` SHA-1, `-m 1400` SHA-256, `-m 1700` SHA-512
- `-m 1000` NTLM, `-m 3000` LM
- `-m 500` md5crypt, `-m 1800` sha512crypt, `-m 7400` sha256crypt
- `-m 3200` bcrypt, `-m 22000` WPA-PBKDF2-PMKID+EAPOL

Of these, the **Tier 1 `hash_crack_dictionary` baseline** covers
MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, sha256crypt,
sha512crypt — all available in Go stdlib + `golang.org/x/crypto`.
WPA / md5crypt / LM are deferred to Tier 2.

**Error shape.** Stdout from `hashcat` is returned verbatim with a
`success: bool` flag. No structured parse.

**Take-away for PromptZero.** This is the **richest verb-list
source** for our v0.5 hash family. The `smart_identify_hash` and
`analyze_cracked_passwords` verbs are pure-Go ports with zero
external deps — both Tier 1 candidates. `generate_smart_masks` is
genuinely useful but defer to v0.5.x (mask attacks aren't in our
v0.5 roadmap).

---

### 1.4 — `mplogas/pm3-mcp`

**Shape.** Python MCP wrapping the iceman Proxmark3 client
(`pm3`). Each tool spawns `pm3 -p $PORT -c "<cmd>"` as a one-shot
subprocess except for sniffing (which holds the device + streams
output until button-press). **No persistent shell.** No MCP
resources or prompts. Three-tier safety classification baked in:
`read-only` (auto-execute), `allowed-write` (logged), and
`approval-write` (requires `_confirmed: true` in the args).

**Verb inventory** (28 tools):

| Verb | Description | Args | PM3 cmd | Pure-Go portable? | Risk proposal | Overlap with PromptZero |
|---|---|---|---|---|---|---|
| `connect` | Validate device + create engagement folder | `project_path?` | `hw status` | N/A (pm3-specific) | Low | We already have `device_info` (Flipper) — pm3 is a different transport |
| `disconnect` | Finalize log | none | (cleanup) | N/A | Low | — |
| `hw_status` | Device info, firmware, key dicts | none | `hw status` | N/A | Low | — |
| `detect_tag` | Auto LF/HF tag | none | `detect` | N/A (pm3 hw) | Low | We have `nfc_detect` |
| `hf_info` | ISO14443A info | none | `hf info` | N/A | Low | We have `nfc_dump_protocol` |
| `lf_info` | LF protocol ID | none | `lf search` | N/A | Low | We have `rfid_read` |
| `read_block` | MIFARE single block | `block`, `key` | `hf mf rdbl` | N/A (hw) | Medium | We have `nfc_mfu_rdbl` (Mifare Ultralight only — no classic-rdbl yet) |
| `dump_tag` | Full dump | `tagType` | `hf mf dump` | N/A | Medium | We have `nfc_read_save` |
| `autopwn` | Dictionary + darkside + nested + hardnested | none | composite | **Algorithms = yes** (mfoc/mfcuk are Tier-1 v0.5 ports; hardnested defers to v0.5.1) | Critical | Already covered by tasks #7 (mfoc/mfcuk) |
| `darkside` | PRNG-weakness key recovery | none | `hf mf darkside` | **Yes** — task #7 lands `mfcuk_attack` | Critical | ✅ already in scope |
| `nested` | Nested attack (weak PRNG) | known sector+key | `hf mf nested` | **Yes** — task #7 lands `mfoc_attack` | Critical | ✅ already in scope |
| `hardnested` | Hard PRNG | known sector+key | `hf mf hardnested` | **Defer to v0.5.1** per runbook §A.2 | Critical | Explicitly out-of-scope for v0.5 |
| `chk_keys` | Sector dictionary check | `keyfile` | `hf mf chk` | **Yes** — pure crypto1 + dict iteration | High | New: see §4 stretch (`mifare_dict_check`) |
| `desfire_info` | DESFire info | none | `hf desfire info` | No (DESFire crypto is its own animal; not in v0.5) | Medium | — |
| `desfire_apps` | DESFire app enum | none | `hf desfire enum` | No | Medium | — |
| `desfire_files` | File listing | `appId` | `hf desfire file list` | No | Medium | — |
| `iclass_info` | iCLASS info | none | `hf iclass info` | N/A (hw read) | Low | — |
| `iclass_rdbl` | iCLASS block read | `block` | `hf iclass readbl` | N/A | Medium | — |
| `iclass_dump` | iCLASS dump | none | `hf iclass dump` | N/A | Medium | — |
| `iclass_chk` | iCLASS key dict check | `keyfile?` | `hf iclass chk` | Yes (same shape as MIFARE chk) | High | Tier 2 stretch |
| `iclass_loclass` | loclass key recovery | none | `hf iclass loclass` | **Yes** — task #8 lands `iclass_loclass_recover` | High | ✅ already in scope |
| `iso15693_info` | ISO15693 info | none | `hf 15 info` | N/A (hw) | Low | — |
| `iso15693_rdbl` | ISO15693 read | `block` | `hf 15 rdbl` | N/A | Medium | — |
| `iso15693_dump` | ISO15693 dump | none | `hf 15 dump` | N/A | Medium | — |
| `sniff_start` | Begin sniff (streaming) | none | `hf sniff` | N/A (hw) | High | We have `wifi_sniff_*` for WiFi; no NFC sniff yet |
| `sniff_stop` | Retrieve buffer | none | `data save` | N/A | Medium | — |
| `mf_wrbl` | MIFARE block write | `block`, `key`, `data`, `_confirmed` | `hf mf wrbl` | N/A | Critical | We have `nfc_mfu_wrbl` (Ultralight only) |
| `mf_restore` | Full dump restore | `dumpFile`, `_confirmed` | `hf mf restore` | N/A | Critical | — |
| `iclass_wrbl` | iCLASS write | `block`, `data`, `_confirmed` | `hf iclass writebl` | N/A | Critical | — |
| `iso15693_wrbl` | ISO15693 write | `block`, `data`, `_confirmed` | `hf 15 wrbl` | N/A | Critical | — |

**Error shape.** Returns parsed structured data from the pm3 text
output via a `parser.py` heuristic. Failures bubble as Python
exceptions (mapped to MCP error responses by the SDK).

**Resources / prompts.** None. The "engagement folder" idea
(per-session directory holding command logs + artefacts) is
similar to pentest-mcp's engagement records but file-system-based
instead of in-memory.

**Take-away for PromptZero.** The MIFARE / loclass crypto verbs
are already covered by tasks #7 and #8. The novel additions
worth porting are the **`_confirmed` two-step write pattern**
(§2) and `chk_keys` / `iclass_chk` (Tier 2 — pure-Go dictionary
check against captured nonces, reusing `internal/crypto1` from
task #7).

---

## 2. Pattern catalogue

Patterns observed across the four references; each entry rates
adoption value for PromptZero.

### 2.1 — Engagement records + report generation

**Source:** pentest-mcp (full triad), pm3-mcp (folder-based
variant).

**Pattern.** Every tool invocation is auto-tagged with a
record-id, persisted alongside its inputs/outputs/timestamp.
Three companion tools surface the records: `listEngagementRecords`,
`getEngagementRecord`, `createClientReport`. The report tool
accepts a list of record-ids + a scope-of-work mode and emits a
structured artifact.

**PromptZero status.** We already have `internal/audit/` (call
log + query DSL) doing 80% of this. Verbs `audit_query`,
`audit_export`, `audit_stats` cover the read side. We do **not**
have `createClientReport`-equivalent.

**Recommendation.** **Adopt, low-cost.** Add an
`audit_report` Spec (Tier 2 stretch — see §4) that takes a
DSL filter expression + a template name and emits a markdown
pentest report. Reuses the existing query DSL; new code is just
templating.

### 2.2 — `_confirmed`-style two-step writes

**Source:** pm3-mcp (every destructive verb requires
`_confirmed: true` in args).

**Pattern.** Destructive tools take an explicit
`{"_confirmed": true}` flag in addition to their normal args.
Without it, the call returns `{"requires_confirmation": true,
"preview": "..."}`. With it, the destructive op runs.

**PromptZero status.** We classify by Risk and the agent prompts
the operator before Critical-tier calls. MCP clients see the
`destructiveHint: true` annotation but enforcement is at the
client, not the server.

**Recommendation.** **Do NOT adopt as a tool-arg convention.** Our
risk-tier + annotation approach is cleaner — adding `_confirmed`
to schemas would break the registry shape contract (runbook §G).
But we should **document the equivalence** in the MCP server
README so MCP clients understand how to gate Critical-tier calls
client-side.

### 2.3 — Cancellable long-running scans

**Source:** pentest-mcp (`cancelScan(scanId)`), pm3-mcp
(`sniff_start` / `sniff_stop`).

**Pattern.** Long-running scans return immediately with a
`scanId`; a separate verb (`cancelScan` or `sniff_stop`) signals
termination. Output is buffered server-side and retrieved on
stop.

**PromptZero status.** We have a few long-runners
(`subghz_rx_raw`, `wifi_sniff_*`, `subghz_freq_sweep`) but they
all run synchronously to completion (with `timeout_ms` ceilings).
No cancellation surface.

**Recommendation.** **Adopt, but defer to v0.6.** The MCP
2024-11 spec has cancellation via the request-id / `notifications/
cancelled` channel — we should plumb context-cancellation through
mcp-go's request handler chain rather than inventing a new tool
verb. Out of scope for v0.5; file a follow-up.

### 2.4 — Async / streaming responses (SSE, partial outputs)

**Source:** pentest-mcp ships SSE transport (deprecated upstream
but functional); none of the reference MCPs return **partial**
outputs — SSE is used as a transport, not a streaming output
mechanism.

**PromptZero status.** stdio only. Our long-runners block until
done.

**Recommendation.** **Skip for v0.5.** The pattern is
under-developed in the reference MCPs; the operator pain is real
but the v0.5 deliverable is verb-coverage, not transport
expansion. Re-evaluate when MCP 2025-xx finalizes streaming.

### 2.5 — MCP resources for wordlists / config files

**Source:** Hashcat-MCP exposes `HASHCAT_SAFE_DIRS` (env var,
not real MCP resources). Some sub-MCPs in mcp-security-hub
(nuclei-mcp) expose template directories as resources.

**PromptZero status.** We have no MCP resources.

**Recommendation.** **Adopt, narrow scope.** When we land Tier 1
`http_enum_common`, expose the bundled wordlist as an MCP
resource (`promptzero://wordlists/common.txt`) so MCP clients
can introspect what's available without invoking a tool.
Implementation cost: ~30 LOC in `internal/mcp/server.go`. Worth
doing in v0.5.

### 2.6 — MCP prompts for capability families

**Source:** None of the four reference MCPs ship MCP prompts
beyond the connection banner. mcp-security-hub has a "tool list"
endpoint at the resource level but no curated prompt templates.

**PromptZero status.** `registerPersonaPrompts` already exposes
each operator persona as a prompt (~12 prompts). We could add
per-family triage prompts (e.g. `prompt_hash_triage`,
`prompt_recon_blackbox`).

**Recommendation.** **Adopt, low-cost, opportunistic.** Architect
mentioned this as a stretch in runbook §B.4. If task #10 has
bandwidth after Tier 1, add 2-3 prompts for the new hash + recon
families. Not blocking.

### 2.7 — Per-tool annotations (read-only / destructive / open-world)

**Source:** pentest-mcp ships the full MCP 2024-11 annotation
set on every tool. mcp-security-hub also annotates. Hashcat-MCP
does not (older SDK). pm3-mcp uses its own three-tier safety
classification orthogonal to MCP annotations.

**PromptZero status.** Already implemented in
`internal/mcp/server.go::add` (lines 94-108). ✅ Parity with
pentest-mcp.

**Recommendation.** **No change needed.** We're already at the
state of the art on this axis.

### 2.8 — Structured error shape with model-self-correction hints

**Source:** pentest-mcp returns
`{ content, isError: bool }` with descriptive error strings
designed for model self-correction. mcp-security-hub returns
stdout/stderr verbatim. Hashcat-MCP returns `success: bool`.

**PromptZero status.** We use mcp-go's
`mcp.NewToolResultError(...)` (server.go:115, 120, 124) which
produces `isError: true` with a string. ✅ Parity.

**Recommendation.** **No change needed.**

### 2.9 — Schema generation from typed definitions (Zod)

**Source:** pentest-mcp uses Zod → JSON Schema 2020-12. Type
safety + auto-generated schemas.

**PromptZero status.** Hand-written JSON Schema strings in each
Spec.

**Recommendation.** **Defer to v0.6+.** Replacing hand-written
schemas with a Go reflect-based generator is a registry-shape
change (runbook §G prohibits these in v0.5). Worth revisiting
once the Spec count stabilises.

---

## 3. Tier 1 port candidates — full Spec proposals

Four ports the engineer copy-pastes into
`internal/tools/security.go`. All are pure-Go, zero runtime deps,
and additive (no overlap with the 179 existing Specs verified
against the live `tools.Names()` list).

### 3.1 — `hash_identify`

**Source:** Port from `MorDavid/Hashcat-MCP::smart_identify_hash`.

**Algorithm.** Heuristic detector based on hash length + character
set + structural hints (e.g. `$2a$` → bcrypt, `$1$` → md5crypt,
all-hex 32 chars → MD5/NTLM/MD4, etc.). Classifier returns ranked
list of candidate types with confidence scores. Inspired by
`name-that-hash` (Python, MIT) and hashcat's `--example-hashes`.

**Spec proposal:**

```go
var hashIdentifySpec = Spec{
    Name: "hash_identify",
    Description: "Heuristic hash-format identification. Returns " +
        "ranked candidates with confidence (0.0-1.0). Pure offline; " +
        "no network or hashcat dependency. Use before " +
        "hash_crack_dictionary.",
    Schema: []byte(`{
        "type":"object",
        "properties":{
            "hash":{"type":"string","description":"The hash string to classify"}
        },
        "required":["hash"]
    }`),
    Required: []string{"hash"},
    Risk:     risk.Low,
    Group:    GroupSecurity,
    Handler:  hashIdentifyHandler,
}
```

**Output shape:**
```json
{
  "candidates": [
    {"name":"NTLM",        "mode":1000, "confidence":0.55},
    {"name":"MD5",         "mode":0,    "confidence":0.30},
    {"name":"MD4",         "mode":900,  "confidence":0.15}
  ],
  "input_length": 32
}
```

**Supported families** (initial set — engineer extends as needed):
MD5/NTLM/MD4 (32-hex), SHA-1 (40-hex), SHA-256 (64-hex), SHA-512
(128-hex), bcrypt (`$2[aby]$`), md5crypt (`$1$`), sha256crypt
(`$5$`), sha512crypt (`$6$`), Argon2 (`$argon2id$`),
SCRAM-SHA-256, MySQL323 (16-hex), MySQL4.1+ (`*` + 40-hex),
LM (32-hex split — paired with NTLM), LDAP `{SSHA}` /
`{SHA}` / `{MD5}`.

**Risk:** Low (info-only, offline).

**Test vectors** (engineer pastes into `hash_identify_test.go`):
| Input | Expected top candidate |
|---|---|
| `5f4dcc3b5aa765d61d8327deb882cf99` | MD5 (`password`) |
| `e10adc3949ba59abbe56e057f20f883e` | MD5 (`123456`) |
| `8846F7EAEE8FB117AD06BDD830B7586C` | NTLM (`password`) |
| `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` | SHA-1 (`hello`) |
| `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy` | bcrypt |
| `$6$saltsalt$lDjgtCdjy...` | sha512crypt |

**Edge cases.**
- Input with `:` separators (e.g. `user:hash`) — split first, classify only the hash side.
- Mixed-case (NTLM is upper, MD5 conventional lower) — informs ordering, not exclusion.
- 32-hex with low entropy → bias toward NTLM over MD5 (NTLMs concentrate ASCII bits).

---

### 3.2 — `hash_crack_dictionary`

**Source:** Port from `MorDavid/Hashcat-MCP::crack_hash` (dictionary
attack only — masks/rules defer to v0.5.x).

**Algorithm.** For each hash in the input set, iterate the
wordlist; for each word, hash it under the requested algorithm and
compare. No GPU, no rules engine, no rainbow tables. Pure stdlib
+ `golang.org/x/crypto`. Concurrent: N goroutines (default
`runtime.NumCPU()`), each pulling words from a channel.

**Spec proposal:**

```go
var hashCrackDictionarySpec = Spec{
    Name: "hash_crack_dictionary",
    Description: "Offline dictionary attack against a hash corpus. " +
        "Pure-Go implementation (MD5, SHA-1, SHA-256, SHA-512, NTLM, " +
        "bcrypt, sha256crypt, sha512crypt). No GPU, no rules engine. " +
        "Use hash_identify first to pick the algorithm.",
    Schema: []byte(`{
        "type":"object",
        "properties":{
            "hashes":{"type":"array","items":{"type":"string"},
                "description":"Hash strings to crack"},
            "algorithm":{"type":"string","enum":[
                "md5","sha1","sha256","sha512","ntlm",
                "bcrypt","sha256crypt","sha512crypt"],
                "description":"Hash algorithm name (output of hash_identify)"},
            "wordlist":{"type":"string",
                "description":"Path to a newline-separated wordlist file"},
            "max_words":{"type":"integer","minimum":0,
                "description":"Cap on words tried (0 = no cap)"},
            "timeout_ms":{"type":"integer","minimum":1000,
                "description":"Wall-clock ceiling (default 60000)"},
            "workers":{"type":"integer","minimum":1,
                "description":"Goroutine count (default NumCPU)"}
        },
        "required":["hashes","algorithm","wordlist"]
    }`),
    Required: []string{"hashes","algorithm","wordlist"},
    Risk:     risk.Critical,
    Group:    GroupSecurity,
    Handler:  hashCrackDictionaryHandler,
}
```

**Output shape:**
```json
{
  "cracked": [
    {"hash":"5f4dcc3b5aa765d61d8327deb882cf99", "plaintext":"password"},
    {"hash":"5d41402abc4b2a76b9719d911017c592", "plaintext":"hello"}
  ],
  "uncracked": ["e10adc3949ba59abbe56e057f20f883e"],
  "algorithm": "md5",
  "words_tried": 14344392,
  "duration_ms": 12345,
  "wordlist": "/path/to/rockyou.txt"
}
```

**Risk:** Critical. Offline cracking is the canonical "operator
intends real damage" tool; lives alongside `subghz_bruteforce`
and `loader_subghz_bruteforcer` in the existing risk taxonomy.

**Algorithm support — initial implementation hints:**
- `md5`, `sha1`, `sha256`, `sha512`: stdlib `crypto/md5`,
  `crypto/sha1`, `crypto/sha256`, `crypto/sha512`. Compare hex.
- `ntlm`: MD4 of UTF-16LE plaintext. MD4 lives in
  `golang.org/x/crypto/md4`. UTF-16LE encode via
  `unicode/utf16`.
- `bcrypt`: `golang.org/x/crypto/bcrypt::CompareHashAndPassword`.
- `sha256crypt` / `sha512crypt`: implementations from
  `github.com/GehirnInc/crypt` (BSD-3) — but per user directive
  prefer in-house; clean-reimpl from RFC-style spec
  (Drepper 2007). ~150 LOC each.

**Test vectors** (one per algorithm, well-known):
| Hash | Algorithm | Plaintext | Wordlist |
|---|---|---|---|
| `5f4dcc3b5aa765d61d8327deb882cf99` | md5 | `password` | tiny fixture |
| `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` | sha1 | `hello` | tiny fixture |
| `8846f7eaee8fb117ad06bdd830b7586c` | ntlm | `password` | tiny fixture |
| `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy` | bcrypt | `password` | tiny fixture (slow!) |

**Edge cases.**
- bcrypt is intentionally slow (~100 ms / hash on modern CPU at
  cost factor 10). Cap `workers = min(NumCPU, 4)` for bcrypt to
  avoid pathological CPU saturation.
- Wordlist may be larger than memory (rockyou is 14M lines, ~133
  MB). Use `bufio.Scanner` with a 1 MB buffer and stream — never
  `io.ReadAll`.
- NTLM plaintexts may be non-ASCII; encode via UTF-16LE as
  Windows does, not UTF-8.
- `timeout_ms` enforced via `context.WithTimeout` plumbed through
  the worker channel. Workers select on `ctx.Done()`.

---

### 3.3 — `port_scan_tcp`

**Source:** Port from `mcp-security-hub::nmap-mcp` (subset) and
`pentest-mcp::nmapScan`. Pure TCP-connect scan; no SYN raw
sockets (those need root + raw socket portability — defer to
v0.6).

**Note on overlap.** We already ship `wifi_port_scan` (Marauder-
side, executed on the ESP32 over WiFi). This new Spec is the
**host-side** variant: scans from the operator's machine over
its own network stack, not via the ESP32. Different transport,
different blast radius.

**Spec proposal:**

```go
var portScanTCPSpec = Spec{
    Name: "port_scan_tcp",
    Description: "Pure-Go TCP connect scan from the operator's host. " +
        "No raw sockets (no root needed). Distinct from wifi_port_scan, " +
        "which scans from the Marauder ESP32. Use this for direct-network " +
        "recon when the operator is on the same network as the target.",
    Schema: []byte(`{
        "type":"object",
        "properties":{
            "target":{"type":"string",
                "description":"Hostname, IPv4, or IPv6 address"},
            "ports":{"type":"string",
                "description":"Comma/range list, e.g. '22,80,443,8000-9000' (default 'top1000')"},
            "timeout_ms":{"type":"integer","minimum":100,
                "description":"Per-connection timeout (default 1000)"},
            "concurrency":{"type":"integer","minimum":1,
                "description":"Parallel dials (default 64; cap 256)"},
            "wall_timeout_ms":{"type":"integer","minimum":1000,
                "description":"Total scan ceiling (default 60000)"}
        },
        "required":["target"]
    }`),
    Required: []string{"target"},
    Risk:     risk.High,
    Group:    GroupSecurity,
    Handler:  portScanTCPHandler,
}
```

**Output shape:**
```json
{
  "target":"192.168.1.10",
  "open":   [22, 80, 443, 8080],
  "closed": 996,
  "filtered": 0,
  "duration_ms": 4321,
  "ports_scanned": 1000
}
```

**Risk:** High. Active port scan; same tier as `wifi_port_scan`
in our existing taxonomy (line 135 of `risk.go`).

**Implementation hints.**
- `net.Dialer{Timeout: ...}.DialContext(ctx, "tcp", JoinHostPort)`
- Worker pool: `concurrency` goroutines pulling from a
  `chan int` of port numbers.
- "top1000" port list: ship a static array based on nmap's
  `nmap-services` top-1000 (the **list** is public-domain;
  service-name labels are nmap's). We embed only the integers.
- IPv6 support: `net.Dial` handles IPv4 + IPv6 transparently;
  bracket the address (`[::1]:80`) when joining. `net.JoinHostPort`
  does this correctly.
- Distinguish closed (RST) from filtered (timeout): a
  `*net.OpError` with `Op == "dial"` and an `"i/o timeout"` →
  filtered; ECONNREFUSED → closed. Anything else → bucket as
  filtered with a warning.

**Edge cases.**
- Localhost / loopback should be allowed (pentest labs).
- RFC 1918 + RFC 4193 ranges should NOT be auto-blocked — but
  the High risk classification means the operator gets prompted.
- DNS resolution failures → return early with structured error,
  don't dial 1000 NXDOMAIN attempts.
- Concurrency cap of 256: above this, modern Linux file-descriptor
  limits + ephemeral-port exhaustion become real issues for the
  operator's own host.

**Test vectors / fixtures.**
- Spawn an `httptest.NewServer` in a test, scan its port; assert
  it appears in `open`.
- Scan a known-closed port (allocate-then-close a `net.Listen`
  socket); assert it appears in `closed`.
- Scan localhost with a 100 ms wall-timeout; assert duration is
  bounded.

---

### 3.4 — `http_enum_common`

**Source:** Port from `pentest-mcp::gobuster` (dir mode) and
`mcp-security-hub::ffuf-mcp`. Wordlist-driven HTTP path
enumeration.

**Spec proposal:**

```go
var httpEnumCommonSpec = Spec{
    Name: "http_enum_common",
    Description: "Wordlist-driven HTTP path enumeration. Pure-Go; " +
        "ships with a small built-in common-paths wordlist (subset of " +
        "SecLists). Use http_enum_common before web exploitation " +
        "to map the attack surface.",
    Schema: []byte(`{
        "type":"object",
        "properties":{
            "base_url":{"type":"string",
                "description":"Base URL, e.g. 'https://target/'"},
            "wordlist":{"type":"string",
                "description":"Path to a wordlist (default: built-in common.txt)"},
            "extensions":{"type":"array","items":{"type":"string"},
                "description":"Extensions to append, e.g. ['php','html','bak']"},
            "match_codes":{"type":"array","items":{"type":"integer"},
                "description":"HTTP status codes to report (default [200,204,301,302,307,401,403])"},
            "concurrency":{"type":"integer","minimum":1,
                "description":"Parallel requests (default 20; cap 100)"},
            "timeout_ms":{"type":"integer","minimum":100,
                "description":"Per-request timeout (default 5000)"},
            "wall_timeout_ms":{"type":"integer","minimum":1000,
                "description":"Total ceiling (default 120000)"},
            "user_agent":{"type":"string",
                "description":"Override User-Agent header"}
        },
        "required":["base_url"]
    }`),
    Required: []string{"base_url"},
    Risk:     risk.High,
    Group:    GroupSecurity,
    Handler:  httpEnumCommonHandler,
}
```

**Output shape:**
```json
{
  "base_url": "https://target/",
  "found": [
    {"path":"/admin/",     "status":401, "size":234},
    {"path":"/.git/HEAD",  "status":200, "size":23},
    {"path":"/robots.txt", "status":200, "size":67}
  ],
  "requests_made": 4823,
  "duration_ms": 12340,
  "wordlist": "builtin:common.txt",
  "extensions": ["php"]
}
```

**Risk:** High. Active enumeration; matches `wifi_arp_scan` /
`wifi_ping_scan` tier in our existing taxonomy.

**Wordlist sourcing.**
- Built-in wordlist: a curated 1000-entry subset of
  SecLists' `Discovery/Web-Content/common.txt`. SecLists is
  MIT-licensed in aggregate; the `common.txt` file specifically
  is derived from dirb's `common.txt` which is GPL-2.0. **To
  stay AGPL-clean we ship our own list** (engineer assembles
  from CC0-only sources: nginx default error pages, Apache
  default paths, well-known RFC paths like
  `/.well-known/security.txt`, common framework conventions).
  Target ~500 entries; embed via `//go:embed`.
- Operator-provided wordlists via the `wordlist` arg take
  precedence.
- **MCP resource**: also expose the built-in wordlist as
  `promptzero://wordlists/common.txt` (see §2.5 pattern adoption).

**Implementation hints.**
- `net/http.Client{Timeout: ...}` with a custom `Transport`
  setting `MaxIdleConnsPerHost` to `concurrency`.
- Disable redirects (`CheckRedirect: func(...) error { return
  http.ErrUseLastResponse }`) — we want the redirect itself as
  a finding, not the destination.
- Worker pool same shape as `port_scan_tcp`.
- Skip TLS verification by default (`InsecureSkipVerify: true`)
  — pentest targets often have invalid certs; this is a
  recon tool. Document the trade-off in the description.

**Edge cases.**
- Target may rate-limit (429) — back off but don't fail the
  scan; report 429 as a special status with a count.
- Soft-404 detection: many apps return 200 for arbitrary paths
  with a "not found" body. Heuristic: probe a known-random path
  first (`/promptzero-canary-${random}`), capture its response
  size; filter findings whose size matches within ±5%.
- Path canonicalisation: strip leading `/` from wordlist
  entries; ensure exactly one `/` between base and entry.
- IPv6 base URLs (`https://[::1]/`) — `net/url` handles this.

**Test vectors.**
- `httptest.NewServer` returning 200 for `/admin` and 404 for
  everything else; assert `/admin` appears in `found`.
- Soft-404 server returning 200 with constant body for all
  paths; assert findings is empty (canary filtering works).
- Server with 5s sleep on `/slow`; assert per-request timeout
  fires and scan continues.

---

## 4. Tier 2 stretch candidates

Pure-Go-portable, larger lift than Tier 1, valuable but not
v0.5-blocking. Engineer picks in priority order if Tier 1 lands
ahead of schedule.

### 4.1 — `cve_lookup`

- **Source.** Mirrors `mcp-security-hub::cve-search` capability;
  also useful as input to `nucleiScan` triage.
- **Behaviour.** Local lookup against a bundled CVE snapshot
  (NVD JSON 2.0 monthly drop, filtered to last N years). Returns
  CVSS, CWE, summary, references, affected CPE list.
- **Args.** `{"cve":"CVE-2024-12345"}` or
  `{"product":"openssh","version":"9.0"}`.
- **Complexity.** Medium. Snapshot ingestion is straightforward
  (NVD JSON 2.0 schema is stable). Storage: per runbook §E
  the snapshot ships **alongside** the binary (not embedded —
  ~2 GB full, ~200 MB if filtered to last 3 years).
- **Value.** High — every recon engagement needs CVE triage.
- **Risk:** Low (offline lookup).
- **Recommendation.** **Defer to v0.5.x.** The bundling/distribution
  story (where does the snapshot live, how does the operator
  refresh it) deserves a separate design pass that wasn't in
  scope for this research.

### 4.2 — `dns_enum_common`

- **Source.** Mirrors `pentest-mcp::subfinderEnum` + gobuster's
  DNS mode. Brute-force subdomain discovery via
  `net.LookupHost`.
- **Args.** `{"domain":"example.com", "wordlist":"<path|builtin>",
  "concurrency":20, "timeout_ms":3000}`.
- **Complexity.** Small. Same shape as `http_enum_common` but
  without HTTP semantics — just DNS resolution.
- **Value.** Medium-high. Active subdomain enumeration is a
  staple of recon.
- **Risk:** Medium. DNS is less noisy than HTTP probing but
  still active recon.
- **Recommendation.** **Port in v0.5 IF Tier 1 lands early.**
  Genuinely small lift (~150 LOC + tests), high payoff.

### 4.3 — `tls_certinfo`

- **Source.** Generic — every recon MCP has a variant.
- **Behaviour.** Dial `host:port`, complete TLS handshake,
  return parsed x509 chain (subject, issuer, SANs, validity,
  fingerprints, signature algorithm, key strength).
- **Args.** `{"host":"example.com", "port":443,
  "server_name":"<sni override>"}`.
- **Complexity.** Small. `crypto/tls` + `crypto/x509` do all the
  work.
- **Value.** Medium. Useful triage tool; mostly defensive.
- **Risk:** Low. Single TLS handshake; no offensive payload.
- **Recommendation.** **Port in v0.5 IF Tier 1 lands early.**
  ~100 LOC.

### 4.4 — `mifare_dict_check`

- **Source.** `pm3-mcp::chk_keys` — but offline (against a
  captured nonce dump rather than a live tag).
- **Behaviour.** For each sector in a dump file, iterate a
  candidate-key wordlist, verify via `internal/crypto1.Cipher`
  (lands as part of task #7), report which keys recover which
  sectors.
- **Args.** `{"dump":"<path>", "keys":"<wordlist path|builtin>",
  "sectors":[0,1,...], "key_type":"A|B|both"}`.
- **Complexity.** Small — once `internal/crypto1` lands (task
  #7), this is a tight loop on top of it. Built-in wordlist =
  the canonical list of 200ish well-known MIFARE keys.
- **Value.** High for the operator's NFC workflow — it's the
  cheap first pass before paying mfoc nested cost.
- **Risk:** High (offline key recovery; same tier as
  `mfoc_attack`).
- **Recommendation.** **Port in v0.5 if task #7 finishes early
  enough to expose `internal/crypto1`.** Otherwise defer to
  v0.5.1.

### 4.5 — `audit_report`

- **Source.** `pentest-mcp::createClientReport` pattern (§2.1).
- **Behaviour.** Filter audit log entries via the existing DSL
  + render through a markdown template; emits a self-contained
  pentest report.
- **Args.** `{"filter":"<DSL expr>", "template":"summary|full|
  custom", "output":"<path?>"}`.
- **Complexity.** Small (templating on top of existing audit
  query infrastructure).
- **Value.** High — closes the operator's "now turn this into a
  deliverable" loop.
- **Risk:** Low (pure data export).
- **Recommendation.** **Port in v0.5 if bandwidth allows.**

### 4.6 — `http_cve_probe` (a tiny Nuclei-like template engine)

- **Source.** `mcp-security-hub::nuclei-mcp` (subset).
- **Behaviour.** Hand-curated set of HTTP CVE probes (~20–30 of
  the highest-impact public CVEs with stable detection
  signatures: Log4Shell pre-auth check, CVE-2021-26084 Confluence
  OGNL, etc.). Each probe is a Go function, not a YAML template.
- **Args.** `{"target_url":"...", "probes":["log4shell",
  "confluence-ognl", ...]}`.
- **Complexity.** Medium. The engine is small but the curated
  probe set is the long-tail work.
- **Value.** Medium — narrower than nuclei but immediately
  actionable.
- **Risk:** Critical (active vuln probing).
- **Recommendation.** **Defer to v0.6.** Maintaining the probe
  set is ongoing work; not v0.5-shaped.

### 4.7 — `sqli_boolean_probe`

- **Source.** `mcp-security-hub::sqlmap-mcp` (deepest subset).
- **Behaviour.** Boolean-blind SQLi probe against a single
  parameter: send `' AND 1=1`, `' AND 1=2`, compare responses;
  binary search to confirm.
- **Args.** `{"url":"...", "parameter":"id", "method":"GET|POST",
  "true_marker":"<regex>"}`.
- **Complexity.** Medium-high. The probe core is small but the
  positive-detection logic (DOM diffing, length comparison) has
  a long tail.
- **Value.** Medium. Useful when sqlmap-the-binary isn't an
  option.
- **Risk:** Critical.
- **Recommendation.** **Defer to v0.6.** Too easy to land
  half-broken; full sqlmap dwarfs us in detection quality.

### Stretch summary table

| Name | Complexity | Value | Recommendation |
|---|---|---|---|
| `cve_lookup` | Medium | High | Defer to v0.5.x (bundling design needed) |
| `dns_enum_common` | Small | Medium-high | **Port in v0.5 if time** |
| `tls_certinfo` | Small | Medium | **Port in v0.5 if time** |
| `mifare_dict_check` | Small | High | **Port in v0.5 if task #7 lands early** |
| `audit_report` | Small | High | **Port in v0.5 if time** |
| `http_cve_probe` | Medium | Medium | Defer to v0.6 |
| `sqli_boolean_probe` | Medium-high | Medium | Defer to v0.6 |

The runbook said "3 stretch candidates"; we identified 7. The
top three by impact are **`dns_enum_common`**, **`tls_certinfo`**,
and **`mifare_dict_check`** — small lifts, high operator value,
no blocking design questions.

---

## 5. Tier 3 — explicit deferrals

Tools that require a runtime binary dependency. These are
non-starters for v0.5 per the user's directive (prefer in-house;
never ship runtime deps the operator must install separately).
For each: justification + v0.6+ recommendation.

| Verb | Source MCP | External binary | Defer reason | v0.6+ vendor strategy? |
|---|---|---|---|---|
| `nmap_full` (NSE / OS fingerprint) | mcp-security-hub | `nmap` | NSE is a Lua VM bound to nmap internals; OS fingerprint DB is nmap-specific. Re-implementing breaks the value prop. | **Stay deferred.** Recommend operators install nmap separately and use `flipper_raw_cli` equivalent only if they already have it. |
| `masscan_internet` | mcp-security-hub | `masscan` | Raw socket TCP-stack reimpl is large; portability across Linux / macOS / Windows is hostile. | **Stay deferred.** |
| `nuclei_full` | mcp-security-hub, pentest-mcp | `nuclei` | Template engine is portable but the **template repository** (~5000 templates, Apache-2.0) is the value. Bundling the repo is feasible (Tier 2 `http_cve_probe` is a starting point). Re-implementing the template language is medium-large work. | **v0.6 vendor candidate.** Bundle a curated subset of templates + a pure-Go template runner. Tier 2 §4.6 is the starting point. |
| `sqlmap_full` | mcp-security-hub, pentest-mcp | `sqlmap` | sqlmap is ~50K LOC of Python. Full port is multi-quarter. | **Stay deferred.** Tier 2 §4.7 covers the most-used 5%. |
| `hashcat_gpu` | hashcat-mcp, mcp-security-hub | `hashcat` + GPU drivers | GPU acceleration is the value prop; pure-Go covers ~5% of hashcat's H/s. | **Stay deferred.** Tier 1 `hash_crack_dictionary` covers CPU-only dictionary use case. |
| `john_the_ripper` | pentest-mcp | `john` | Same shape as hashcat — value is in optimized bitslice + format support. | **Stay deferred.** |
| `ghidra_analyze` | mcp-security-hub | `ghidra` + JVM | Ghidra is ~1 GB + needs JVM. Vendoring is impractical. | **Stay deferred.** Recommend operators run ghidra-mcp directly if needed. |
| `radare2_analyze` / `binwalk_extract` | mcp-security-hub | `radare2`, `binwalk` | Both are practical to install (binwalk is `pip install`); but the user's "no runtime deps" rule applies. Pure-Go binwalk reimpl is a v0.6+ project. | **v0.6 vendor candidate** for binwalk specifically (small, useful, pure-Go reimpl is feasible). r2 stays deferred. |
| `yara_scan` | mcp-security-hub | `yara` (libyara) | `hillu/go-yara` is cgo wrapper; pure-Go YARA reimpl exists (`VirusTotal/yara-x` has Rust + Go bindings, but bindings = cgo). | **v0.6 vendor candidate** if pure-Go YARA matures. Stay deferred for now. |
| `pm3_full_session` (`sniff_start`/`sniff_stop` etc.) | pm3-mcp | iceman pm3 client + Proxmark3 hw | We don't have Proxmark3 hardware in our supported transports; even if we did, the iceman client is GPLv2 and we use the hardware via Flipper instead. | **Stay deferred.** PromptZero's NFC story is Flipper-first. |
| `tcpdump_capture` | pentest-mcp | `tcpdump` + libpcap | Live capture in Go needs libpcap (cgo) or root-only raw-socket reimpl. | **Stay deferred.** Out of scope for an offline-first tool. |
| `hydra_brute` / `medusa_brute` | mcp-security-hub, pentest-mcp | `hydra`, `medusa` | Per-protocol auth surface is large; risk of half-broken implementations transmitting malformed packets to live services is high. | **Stay deferred.** Tier 2 `sqli_boolean_probe` covers the in-app-credential subset narrowly. |
| `prowler_audit` | mcp-security-hub | `prowler` (boto3 + AWS SDK + GCP SDK + Azure SDK) | Cloud-SDK matrix is a different scope from PromptZero. | **Stay deferred** unless PromptZero ever pivots to cloud-pentest. |
| `desfire_*` | pm3-mcp | iceman pm3 client | DESFire crypto + APDU surface is its own multi-engineer-month project. | **v0.6+ candidate** if a contributor wants it. |
| `nfc_hf_sniff` (NFC sniffer) | pm3-mcp | iceman pm3 + Proxmark3 | Flipper has limited HF sniff; Marauder doesn't. Hardware-gated. | **Stay deferred.** |

**Summary.** 15 verbs deferred. **2 v0.6 vendor candidates**
(nuclei templates, binwalk reimpl); the remaining 13 stay
deferred indefinitely. None of these block v0.5.

---

## 6. Patterns the architect did NOT pre-call

Three observations worth surfacing — items the runbook §B.4
didn't enumerate but that are worth raising to the architect /
team lead:

### 6.1 — Adopt MCP **resources** for built-in wordlists

(See §2.5.) None of the four reference MCPs do this cleanly, but
mcp-go supports MCP resources first-class and our `http_enum_common`
+ Tier 2 `dns_enum_common` + Tier 2 `mifare_dict_check` all benefit
from exposing their bundled wordlists as introspectable resources.
~30 LOC in `internal/mcp/server.go::NewServer` to wire up; engineer
should land alongside Tier 1.

### 6.2 — Adopt the **pentest-mcp report-generation pattern**

(See §2.1, Tier 2 §4.5.) The `audit_report` Spec is a small lift
on top of our existing audit query DSL and would close a real
operator-workflow loop. Architect's runbook noted "1-2 prompts
per new verb family" as an MCP enhancement (§B.4) but didn't call
out report generation. Recommend including `audit_report` in
v0.5 if Tier 1 finishes early.

### 6.3 — Document the `_confirmed` ↔ Risk-tier equivalence

(See §2.2.) MCP clients that read pm3-mcp's docs expect the
`_confirmed` flag convention. PromptZero's `destructiveHint`
annotation conveys equivalent semantics but the equivalence
isn't documented anywhere. Recommend a short
`docs/mcp-client-integration.md` section explaining how to gate
Critical-tier calls in MCP clients (Claude Desktop's
auto-approve setting, etc.). Outside this researcher's scope to
write but worth flagging.

---

## Appendix — Coverage check

Verified `tools.Names()` set (179 entries via `grep -E 'Name:\s*"'
internal/tools/*.go | grep -oE '"[a-z_0-9]+"' | sort -u`) against
proposed Tier 1 / Tier 2 names: **0 collisions**. All four Tier
1 Specs (`hash_identify`, `hash_crack_dictionary`, `port_scan_tcp`,
`http_enum_common`) are net-new.

Tier 2 names also collision-free: `cve_lookup`, `dns_enum_common`,
`tls_certinfo`, `mifare_dict_check`, `audit_report`,
`http_cve_probe`, `sqli_boolean_probe`.

Group constants used in Specs: `GroupSecurity` is a new group
the engineer adds to `internal/tools/spec.go`'s `Group` enum
section (existing groups: GroupFlipperSystem, GroupFlipperNFC,
GroupFlipperRF, GroupFlipperRFID, GroupFlipperIR, GroupMarauder,
GroupWorkflow, GroupAudit, GroupGenerator, GroupDocs).
**Engineer: please confirm with architect before adding** — if the
architect prefers per-family groups (GroupSecurityHash,
GroupSecurityRecon), split accordingly.

---

*End of MCP feature-extraction research deliverable.*
