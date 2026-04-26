---
name: PromptZero capability catalog (v0.8 deepening)
description: Index + executive synthesis of the Flipper / adjacent-hardware / attack-PoC catalog produced as a deepening pass on top of docs/refactor/v0.8-team-audit.md
type: reference
created: 2026-04-26T00:00
tags: [catalog, v0.8, flipper, hardware, attacks]
---

# PromptZero capability catalog

This directory is a **point-in-time reference snapshot** of the Flipper Zero ecosystem — custom firmwares, community apps, public attack PoCs, and adjacent hardware — cross-referenced against PromptZero's current Spec inventory. It was produced as a **deepening pass** on top of `docs/refactor/v0.8-team-audit.md` to surface what the breadth-first audit missed.

**When to consult this catalog**
- Designing a new capability and unsure whether it already has prior art
- Considering a new hardware backend and looking for ecosystem placement
- Triaging a feature request to an existing primitive vs a real gap

**When NOT to consult it**
- For "what does PromptZero do today" — the **code** in `internal/tools/` is authoritative; this catalog can drift between releases.
- For implementation guidance — the **audit doc** + per-package READMEs hold the design decisions.

## Index

| Document | Lines | One-line summary |
|---|---|---|
| [`firmware.md`](./firmware.md) | 748 | 11 Flipper custom firmwares (4 active, 1 archived, 5 stale, 1 adversarial) with feature diff vs PromptZero coverage |
| [`apps.md`](./apps.md) | 470 | 233 community apps deduped from 774 across Momentum / all-the-plugins / RogueMaster / Unleashed bundles, with `Stock-Spec?` cross-reference |
| [`attacks.md`](./attacks.md) | 614 | 34 public attack PoCs (2024-01 → 2026-04) grouped by protocol family, with implementability rating and Top-15 ranking |
| [`hardware.md`](./hardware.md) | 338 | 38 companion-hardware entries across 10 categories with Top-7 backends to add in v0.8 |
| [`gap-analysis.md`](./gap-analysis.md) | 482 | Coverage matrix + Top-30 prioritized gaps + PR-able patch for the audit doc |
| [`phase0-review.md`](./phase0-review.md) | 49 | Verification finding: all five v0.8 Phase 0 hotfixes are already fixed in the current tree |

Total catalog corpus: **~2,700 lines** of citation-backed reference material.

## Executive findings

Ordered by load-bearing-ness for the v0.8 plan:

1. **Phase 0 work is done locally but uncommitted.** All five hotfixes are implemented in the user's working tree; HEAD (`a911fcb`) still carries every bug. Action: review the uncommitted diff, scope a Phase 0 commit narrowly (see `phase0-review.md` §"Recommended actions"), then proceed to Phase 1. The audit is accurate against HEAD.
2. **The existing audit's Phase 2 lists are mostly correct.** Of 24 Phase-2 rows reviewed, 0 are weakened, 2 get stronger PoC citations (`ble_findmy_emulate` ⟵ nRootTag USENIX'25; `mifare_fm11rf08_backdoor` ⟵ Quarkslab Aug 2024). The strategic shape is sound.
3. **Six tactical Specs were missed by the audit's §2b** despite being widely shipped across CFW bundles: `nfc_relay_*` (two-Flipper proxy, in Momentum + RogueMaster), `magspoof_emulate`, `gpio_sentry_safe_open`, `subghz_pocsag_decode`, `nfc_apdu_script_run` (distinct from the single-frame `nfc_apdu_run` already proposed), and the AVR-ICSP / ARM-SWD chip-dump primitives.
4. **`workflow_glitch_chip_dump` (audit §2d) has no data path.** SWD/AVR chip-dump primitives don't exist as Specs — the workflow is currently undefined past "Faultier sweep + Bus Pirate listener." Add `swd_dump` + `avr_isp_read` Specs alongside the workflow.
5. **Two new hardware backends earn a v0.8 slot beyond audit §2c**: **Proxmark3 Iceman** (containerbridge to `pm3` CLI — covers LF EM4x sniff and HID-downgrade depth Chameleon doesn't) and **CatSniffer V3 / Sniffle** (sole BLE-5 connection-following backend; closes the gap behind `ble_findmy_emulate`).
6. **Four new defensive Specs** worth adding from the attacks catalog: `tpms_anomaly_detect`, `iclass_dummy_mac_emulate`, `wifi_peap_downgrade_audit`, and `ble_continuity_classify`. PromptZero's defensive surface is currently thin compared to its offensive depth; these are easy and operator-defensible.
7. **TPMS decode lifts to #1 implementable** (above all backend-dependent items) because rtl_433 has a clean native port path, and TPMS is the only Sub-GHz primitive that lands real automotive-sensing capability without new hardware.
8. **Stale researcher claim caught in flight** — `firmware.md` §4.2 #2 listed `subghz_chat` as a missing handler; gap-analyst verified it exists at `internal/tools/subghz.go:123`. Net firmware-catalog gap drops from 5 → 4.
9. **Cuyler36 confirmed not a Flipper firmware.** It's an Animal Crossing decompilation project. The reference appears only in the task #7 brief, **not** in `docs/refactor/v0.8-team-audit.md` — no audit patch needed; just don't propagate the typo.
10. **RogueMaster default-locks Sub-GHz TX** (opt-in via `extend_range.txt`). PromptZero handlers must not assume RogueMaster ≡ unlocked — capability detection should branch on the actual `extend_range.txt` presence, not the firmware fork name.

## Confirmed for v0.8 inclusion

Recommended additions to `docs/refactor/v0.8-team-audit.md`. Patch text is in [`gap-analysis.md`](./gap-analysis.md) §4.

**Phase 2a — attack Specs:** add `tpms_anomaly_detect`, `iclass_dummy_mac_emulate`, `wifi_peap_downgrade_audit`, `ble_continuity_classify`. Lift TPMS decode to top of the list.

**Phase 2b — Flipper tool Specs:** add `nfc_relay_run`, `magspoof_emulate`, `gpio_sentry_safe_open`, `subghz_pocsag_decode`, and split the existing `nfc_apdu_run` into `nfc_apdu_run` (single-frame) and `nfc_apdu_script_run` (script-driven multi-frame).

**Phase 2c — hardware backends:** add **Proxmark3 Iceman** (priority 3, containerbridge) and **CatSniffer V3 / Sniffle** (priority 6, fills BLE-5/Zigbee/Thread/LoRa gap). Keep the existing five priorities intact.

**Phase 2d — workflows:** define data path for `workflow_glitch_chip_dump` by adding `swd_dump` and `avr_isp_read` Specs. Without them the workflow has no output.

**Phase 0 — keep the section, mark each item "implemented locally; pending commit"** and link to `phase0-review.md` for per-item evidence. The audit prescription is correct; the work just needs to be committed.

## Confirmed NOT pursuing

Items the catalog surfaced but the team explicitly recommends skipping:

- **Mifare Plus EV2 SL3 / DESFire EV2 attacks** — no public PoC; AES-128 still holds. Stay current, don't speculate. (Audit §"What NOT to do" already covers this; reaffirmed by attacks catalog.)
- **Tesla UWB relay** — needs UWB radio not in scope.
- **5Ghoul / SNI5GECT / TETRA:BURST 2024-26 follow-ups** — listed in attacks catalog as research-only. Keep on the watchlist; do not implement.
- **Ubertooth One backend** — EOL Dec 2022. Use Sniffle / CatSniffer instead.
- **Original Spooks4576 GhostESP** — archived. Use GhostESP-Revival.
- **Adversarial dark-web RKE firmware ("Private-Unleashed 2.0")** — explicitly **not** linked or catalogued by URL. Defensive `subghz_rollback_detect` (capture-only) is the right counter; ship that, skip the offensive equivalent.
- **Cuyler36** — not a firmware. Don't propagate the typo into future drafts.

## Open questions for the user

These need a decision before the relevant Phase 1/2 work commences:

1. **Phase 0 commit scope?** The working tree mixes Phase 0 hotfixes with unrelated in-progress work (`recover_fast.go`, `mfkey32.go`, `internal/flipper/companion/`, `fap/`, REPL/setup changes). Want me to draft a narrow Phase 0 commit (just the five hotfix files + their tests), or leave commit-scoping to you?
2. **Stale-claim correction in `firmware.md`** — do you want me to send `researcher-firmware` back to fix §4.2 #2 (`subghz_chat` is not missing), or fold the correction into `gap-analysis.md` §0 only?
3. **Backend-#3 slot:** Proxmark3 Iceman as containerbridge (~days, leverages existing `pm3` CLI) vs deferring to federation-only via an `iceman/proxmark3-mcp` server. Preference?
4. **GhostESP unification timing** — do you still want to defer the `internal/esp32backend/` shared-core extraction until after a third ESP32 backend lands (current audit position), or pull it forward now that the attacks-catalog raises pressure on Bruce-shape parsers?
5. **CFW-aware capability gating** — do you want a Spec/handler change that branches on `extend_range.txt` presence (RogueMaster posture), or keep the current "trust the user/firmware" model and document the caveat?

## Team task ledger

All 12 tasks completed. Owners and final state:

| # | Owner | Status | Output |
|---|---|---|---|
| 1–5 | team-lead | completed | All five Phase 0 hotfixes verified pre-fixed; see `phase0-review.md` |
| 6 | team-lead | completed | `phase0-review.md` |
| 7 | researcher-firmware | completed | `firmware.md` |
| 8 | researcher-apps | completed | `apps.md` |
| 9 | researcher-attacks | completed | `attacks.md` |
| 10 | researcher-hardware | completed | `hardware.md` |
| 11 | gap-analyst | completed | `gap-analysis.md` |
| 12 | team-lead | completed | this document |
