package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/risk"
)

// firmware.go — v0.5 wave-1 firmware oracle Spec skeletons.
//
// This file is an ARCHITECT SKELETON. It declares every Spec the
// wave-1 engineer (task #6) needs to land, but it does NOT call
// Register() — that is the engineer's single-edit job once the
// Handler bodies are wired. Keeping registration in the engineer's
// commit means:
//
//   - the architect commit leaves `go test ./...` green (the
//     registry_size_test cumulative count is unaffected);
//   - the engineer only has to touch Handler bodies, init() Register
//     calls, the risk.go classification map, and the size-test count
//     — everything else (Name, Description, Schema, Group, AgentOnly)
//     is pinned here and signed off by the architect.
//
// See docs/refactor/v0.5-runbook.md §B.1 and §C for the full wave-1
// runbook including the Capabilities struct expansion it depends on.
//
// Linter note: the `unused` check in golangci-lint flags unexported
// vars that are never read. These skeleton vars are referenced by
// the `_skel` slice at the bottom of this file, which the wave-1
// engineer lifts into the init() Register() calls.

// ---------------------------------------------------------------------
// A.1 — firmware_introspect
// ---------------------------------------------------------------------
//
// Surface the parsed Capabilities bitmap to the LLM as a structured
// JSON object, so the model can gate tool calls on fork-specific
// quirks without re-parsing device_info itself. Companion to the
// expanded Capabilities struct — see §C of the runbook.
//
// Read-only; no transmit; no write. Risk: Low.

//nolint:unused // Wave-1 skeleton — engineer wires Register() and Handler body.
var firmwareIntrospectSpec = Spec{
	Name:        "firmware_introspect",
	Description: "Return the connected Flipper's firmware capability bitmap as structured JSON: fork, version, commit, build date, feature flags (HasNFCSubshell, SubGHzNeedsDev, NFCFlaggedArgs, SubGHzRxRawHasFilePath, JSEngineKind, SubGHzBruteforcerAvail, ...), and the resolved fork+version band (e.g. 'momentum/mntm-dev', 'unleashed/v1.2.x'). Use this before any fork-gated tool call so the LLM can pick the right verb variant without a trial-and-error round trip.",
	Schema:      json.RawMessage(`{"type":"object","properties":{"refresh":{"type":"boolean","description":"Re-issue device_info and recompute the bitmap instead of returning the connect-time snapshot. Default false."}}}`),
	Required:    nil,
	Risk:        risk.Low,
	Group:       GroupFlipperSystem,
	AgentOnly:   false,
	// Handler: TODO(v0.5 wave 1). The engineer's Handler body:
	//
	//   caps := d.Flipper.Capabilities()
	//   if boolOr(p, "refresh", false) {
	//       if _, err := d.Flipper.DetectCapabilities(); err != nil { return "", err }
	//       caps = d.Flipper.Capabilities()
	//   }
	//   b, err := json.Marshal(caps)
	//   if err != nil { return "", err }
	//   return string(b), nil
	//
	// The marshalled struct must be the expanded Capabilities shape
	// from §C of the runbook (with the full ~20 feature flags + the
	// resolved FirmwareBand string).
	Handler: nil,
}

// ---------------------------------------------------------------------
// A.4 — Mifare offline crackers
// ---------------------------------------------------------------------
//
// All three are offline — they chew on captured nonces and recover
// keys WITHOUT re-touching the card. No hardware is involved once the
// capture is on disk. They share the same JSON output contract:
//
//   { "keys": ["A0A1A2A3A4A5", ...], "sectors": [1, 5, 7, ...], "method": "mfoc|mfcuk|mfkey32", "duration_ms": 1234 }
//
// All three depend on internal/crypto1. The crypto1 interface lands
// in architect commit; the algorithm bodies land in wave 2 alongside
// these Handlers. Risk: High (key recovery enables cloning; no
// transmit, but offline key recovery IS the attack).
//
// Reference sources the wave-2 engineer ports from (algorithm only,
// clean-reimpl — see §E of the runbook):
//
//   - mfoc_attack:            nfc-tools/mfoc/src/mfoc.c::mf_nested_attack
//   - mfcuk_attack:           nfc-tools/mfcuk/src/mfcuk_keyrecovery_darkside.c
//   - mfkey32_recover:        equipter/mfkey32v2/mfkey32v2.c
//
// hardnested is DEFERRED to v0.5.1 per the team-lead brief; the
// skeleton here covers only nested + darkside + mfkey32.

//nolint:unused // Wave-2 skeleton.
var mfocAttackSpec = Spec{
	Name:        "mfoc_attack",
	Description: "Run the MIFARE Classic nested key-recovery attack (mfoc algorithm) offline against a captured .mfd or .nfc nonce dump. Returns recovered sector keys as a JSON array. Requires at least one known key (usually a MAD-A or default key) to bootstrap. Offline: no card contact. High risk — recovered keys enable cloning.",
	Schema:      json.RawMessage(`{"type":"object","properties":{"dump":{"type":"string","description":"Path to the .mfd or .nfc nonce dump on the host (not the Flipper SD)"},"known_keys":{"type":"array","description":"Hex-encoded 6-byte keys already known (MAD-A defaults, leaked keys)"},"key_type":{"type":"string","description":"Key type to target: A or B. Default A."},"timeout_ms":{"type":"integer","description":"Per-sector attack timeout in ms. Default 60000."}}}`),
	Required:    []string{"dump"},
	Risk:        risk.High,
	Group:       GroupFlipperNFC,
	AgentOnly:   false,
	Handler:     nil, // TODO(v0.5 wave 2): attack.NestedRecover(dump, knownKeys, keyType) → []Key
}

//nolint:unused // Wave-2 skeleton.
var mfcukAttackSpec = Spec{
	Name:        "mfcuk_attack",
	Description: "Run the MIFARE Classic darkside key-recovery attack (mfcuk algorithm) offline. Works without any known key — exploits the weak PRNG to recover the first sector key, after which mfoc_attack can recover the rest. Offline: no card contact. Slow (minutes to hours on a hard target).",
	Schema:      json.RawMessage(`{"type":"object","properties":{"dump":{"type":"string","description":"Path to a darkside-capture nonce dump"},"sector":{"type":"integer","description":"Sector to attack (default 0)"},"key_type":{"type":"string","description":"A or B (default A)"},"timeout_ms":{"type":"integer","description":"Attack timeout in ms. Default 600000 (10 min)."}}}`),
	Required:    []string{"dump"},
	Risk:        risk.High,
	Group:       GroupFlipperNFC,
	AgentOnly:   false,
	Handler:     nil, // TODO(v0.5 wave 2): attack.DarksideRecover(dump, sector, keyType)
}

//nolint:unused // Wave-2 skeleton.
var mfkey32RecoverSpec = Spec{
	Name:        "mfkey32_recover",
	Description: "Recover a MIFARE Classic sector key from a single captured reader↔tag authentication exchange (mfkey32 algorithm). Input is a 4-tuple: uid, nt (tag nonce), nr_enc (encrypted reader nonce), ar_enc (encrypted reader auth response). Output is the 6-byte key. Offline; runs in <1 second on a modern CPU.",
	Schema:      json.RawMessage(`{"type":"object","properties":{"uid":{"type":"string","description":"Card UID as hex (4 or 7 bytes)"},"nt":{"type":"string","description":"Tag nonce as hex (4 bytes)"},"nr":{"type":"string","description":"Encrypted reader nonce as hex (4 bytes)"},"ar":{"type":"string","description":"Encrypted reader auth response as hex (4 bytes)"}}}`),
	Required:    []string{"uid", "nt", "nr", "ar"},
	Risk:        risk.High,
	Group:       GroupFlipperNFC,
	AgentOnly:   false,
	Handler:     nil, // TODO(v0.5 wave 2): attack.Mfkey32(uid, nt, nr, ar) → Key
}

// mifare_hardnested_recover is DEFERRED to v0.5.1 per the team-lead
// brief. The Spec is NOT drafted here so the wave-2 engineer has one
// unambiguous scope: nested + darkside + mfkey32 only.

// ---------------------------------------------------------------------
// A.5 — iCLASS / HID Prox loclass
// ---------------------------------------------------------------------
//
// Loclass is the cryptanalytic key-recovery attack on HID iCLASS
// legacy (Standard Security) credentials. Given 8 authenticated
// read exchanges captured against any iCLASS reader keyed to the
// same HID master key (typically a door reader on the target
// building), the algorithm recovers the reader's privileged key in
// ~10 seconds on a modern CPU — which then decrypts every iCLASS
// card at that site.
//
// Reference: USENIX 2012 "Heart of Darkness" paper by Meriac; canonical
// C impl is in the proxmark3 iceman fork under `client/src/loclass/`.
//
// Risk: High (key recovery enables arbitrary cloning). Offline; no
// card contact; Flipper is NOT touched during the attack itself.
// Separate workflow (not in this skeleton) will cover the capture
// phase — loclass assumes the 8 captures are already on disk.

//nolint:unused // Wave-3 skeleton (engineer claiming task #8).
var iclassLoclassRecoverSpec = Spec{
	Name:        "iclass_loclass_recover",
	Description: "Recover an HID iCLASS reader's master key from 8 captured authenticated-read exchanges (loclass algorithm). Given the 8-capture file, returns the recovered key as hex. Offline; no card contact; <30 s on a modern CPU. Only works against iCLASS Standard Security (legacy); iCLASS SE / SR / Seos are NOT vulnerable — use a different workflow for those.",
	Schema:      json.RawMessage(`{"type":"object","properties":{"captures":{"type":"string","description":"Path to the loclass capture file (8-tuple of authenticated read exchanges, typically a .bin or .txt from proxmark3 or a field capture workflow)"},"format":{"type":"string","description":"Capture format: 'pm3' (proxmark3 default) or 'raw' (concatenated hex blocks). Default 'pm3'."},"timeout_ms":{"type":"integer","description":"Attack timeout in ms. Default 60000."}}}`),
	Required:    []string{"captures"},
	Risk:        risk.High,
	Group:       GroupFlipperNFC,
	AgentOnly:   false,
	Handler:     nil, // TODO(v0.5 wave 3): attack.LoclassRecover(capturesPath, format)
}

// ---------------------------------------------------------------------
// Skeleton handler usage guard
// ---------------------------------------------------------------------
//
// The _skel variable below references every unregistered Spec so the
// `unused` linter doesn't flag them individually. The sibling file
// `firmware_wave1_wire.go` (dropped in during wave 1) reuses the same
// slice as the source of Register() calls, so flipping the skeleton
// into live registrations is one edit.
//
// Using context import here keeps the handler signature compile-check
// honest — if the Handler type changes the engineer's wire commit
// won't silently build.

//nolint:unused
var _skel = []Spec{
	firmwareIntrospectSpec,
	mfocAttackSpec,
	mfcukAttackSpec,
	mfkey32RecoverSpec,
	iclassLoclassRecoverSpec,
}

// Ensure the `context` import stays used in this file even before the
// Handler bodies exist. context.Context is the first parameter of
// every Handler and will appear in the engineer's wave commits.
var _ = context.Background
