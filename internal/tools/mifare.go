// mifare.go — v0.5 Mifare offline-cracker Specs (stub registration).
//
// Status (v0.5): the Crypto1 cipher port (internal/crypto1/) is the v0.5
// architectural deliverable but the algorithm body did not land in the v0.5
// engineering window. The runbook (docs/refactor/v0.5-runbook.md §B.2) and the
// algorithm reference (docs/refactor/mifare-algorithms.md — 34 KB with LFSR
// taps, filter truth tables, 5 test vectors) are the deliverable for v0.5.
//
// These three Specs are registered as STUBS so the LLM sees them in the
// catalogue and can route operator intent at them, returning a clear
// "scheduled for v0.5.1" message that points at the workaround
// (loader_mfkey FAP for in-device mfkey32; nfc_dump_protocol for offline
// dump capture). v0.5.1's job is to fill in the Handler bodies once
// internal/crypto1/crypto1.go has its impl.
//
// Tracking: see v0.5.1 milestone in docs/refactor/v0.5-runbook.md §F.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
)

const mifareV05DeferralMsg = "Mifare offline cracker (Crypto1) is scheduled for v0.5.1 — see docs/refactor/mifare-algorithms.md for the algorithm reference. " +
	"For the live-capture flow today: use `nfc_dump_protocol mfc` to capture the card, then run `loader_mfkey` (in-device FAP) for sector-key recovery. " +
	"v0.5.1 will land the pure-Go cipher + offline cracker so this Spec returns the recovered key directly."

func init() { //nolint:gochecknoinits
	Register(mfocAttackSpec)
	Register(mfcukAttackSpec)
	Register(mfkey32RecoverSpec)
}

func deferred(specName string) Handler {
	return func(_ context.Context, _ *Deps, _ map[string]any) (string, error) {
		out, _ := json.Marshal(map[string]string{
			"status":  "deferred_v0.5.1",
			"spec":    specName,
			"message": mifareV05DeferralMsg,
		})
		return string(out), fmt.Errorf("%s: %s", specName, mifareV05DeferralMsg)
	}
}

var mfocAttackSpec = Spec{
	Name:        "mfoc_attack",
	Description: "Mifare Classic offline nested attack. Recover all sector keys when at least one is known. Pure-Go port of the libnfc-tools mfoc nested algorithm. (v0.5: deferred to v0.5.1; see message for workaround.)",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as hex (4 or 7 bytes)"},
			"known_key_hex":{"type":"string","description":"At least one sector key already known, 6 bytes hex"},
			"known_sector":{"type":"integer","description":"Sector number whose key is provided in known_key_hex"},
			"key_type":{"type":"string","description":"Key type for known_key (A or B)"}
		},
		"required":["uid_hex","known_key_hex","known_sector","key_type"]
	}`),
	Required:  []string{"uid_hex", "known_key_hex", "known_sector", "key_type"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   deferred("mfoc_attack"),
}

var mfcukAttackSpec = Spec{
	Name:        "mfcuk_attack",
	Description: "Mifare Classic darkside attack. Recover the first sector key without any prior key knowledge. Pure-Go port of the mfcuk darkside algorithm — note: vulnerable to legacy Classic 1K only; EV1/Plus/DESFire are immune. (v0.5: deferred to v0.5.1; see message for workaround.)",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as hex"}
		},
		"required":["uid_hex"]
	}`),
	Required:  []string{"uid_hex"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   deferred("mfcuk_attack"),
}

var mfkey32RecoverSpec = Spec{
	Name:        "mfkey32_recover",
	Description: "Recover a Mifare Classic sector key from sniffed reader-authentication exchanges. Offline / no card I/O — feed the sniffed (uid, nt, nr0, ar0, nr1, ar1) tuples and get the 48-bit key. Pure-Go port of mfkey32v2. (v0.5: deferred to v0.5.1; see message for workaround.)",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uid_hex":{"type":"string","description":"Card UID as hex (4 bytes)"},
			"nt_hex":{"type":"string","description":"Card nonce as 4-byte hex"},
			"nr0_hex":{"type":"string","description":"Reader nonce 0 as 4-byte hex"},
			"ar0_hex":{"type":"string","description":"Reader auth response 0 as 4-byte hex"},
			"nr1_hex":{"type":"string","description":"Reader nonce 1 as 4-byte hex"},
			"ar1_hex":{"type":"string","description":"Reader auth response 1 as 4-byte hex"}
		},
		"required":["uid_hex","nt_hex","nr0_hex","ar0_hex","nr1_hex","ar1_hex"]
	}`),
	Required:  []string{"uid_hex", "nt_hex", "nr0_hex", "ar0_hex", "nr1_hex", "ar1_hex"},
	Risk:      risk.High,
	Group:     GroupFlipperNFC,
	AgentOnly: false,
	Handler:   deferred("mfkey32_recover"),
}
