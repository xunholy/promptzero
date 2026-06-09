// ir_raw_decode.go — host-side raw-IR-timing protocol decoder Spec,
// delegating to internal/ir.DecodeRaw.
//
// Wrap-vs-native: native — decoding a captured IR pulse train into its NEC
// protocol + address/command is a leader-match plus a per-bit mark/space
// classifier over microsecond timings, with NEC's address/command bitwise-
// inverse pair as a built-in checksum. It is the IR analogue of subghz_decode
// and the complement to ir_decode_file (which only reads a .ir file's
// already-parsed entries). Offline transform — reads timings, transmits
// nothing, so it is Low risk.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/ir"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(irRawDecodeSpec)
}

var irRawDecodeSpec = Spec{
	Name: "ir_raw_decode",
	Description: "Decode a raw infrared timing capture (the space-separated microsecond mark/space " +
		"durations from ir_receive raw, a Flipper RAW .ir entry, or a logic-analyser trace) into its " +
		"protocol + address/command — the IR analogue of subghz_decode, and the complement to " +
		"ir_decode_file (which only reads a .ir file's already-parsed entries).\n\n" +
		"Decodes NEC, Kaseikyo (Panasonic/Denon/JVC/Sharp/Mitsubishi), Samsung32, RCA, Sony SIRC, and Philips RC5/RC5X, dispatched by the leader pulse (NEC ~9000µs, Kaseikyo ~3456/1728µs, Samsung " +
		"~4500µs, RCA ~4000/4000µs, SIRC ~2400µs). NEC: standard NEC (8-bit address + command, each followed by its " +
		"bitwise inverse), NEC-extended (16-bit address, command inversion only), and the NEC repeat " +
		"code — NEC's inverse-byte pairs are a built-in checksum, so a frame is reported as standard NEC " +
		"only when BOTH inversions hold, as NEC-extended when only the command inversion holds, and " +
		"otherwise the raw 4 bytes are surfaced with a note. Samsung32: a 32-bit address·address·command·" +
		"~command frame (NEC bit encoding, 4500/4500 leader) — the command byte's bitwise inverse is the " +
		"checksum, reported as Samsung32 only when byte3 == ~byte2 (a 16-bit-address variant when the " +
		"address bytes differ). Sony SIRC (12 / 15 / 20-bit): 7 command bits + address (+ a 20-bit " +
		"extension), LSB-first — SIRC has no checksum, so it is gated structurally instead (the " +
		"distinctive 2400µs leader, an exact 12/15/20-bit count, and a clean per-bit mark classification " +
		"reject any non-SIRC pulse train). The leader and every bit are tolerance-matched (±30%). " +
		"Philips RC5/RC5X (14-bit Manchester / bi-phase): no leader and no checksum, the 889us half-bit stream is reconstructed into exactly 28 half-bits forming 14 Manchester bit-pairs (S1, S2, toggle, 5 address, 6 command), gated by a valid S1=1 start bit so a polarity-inverted or non-RC5 train is rejected not mis-decoded; RC5X (S2=0) extends the command to 0-127. Kaseikyo (48-bit pulse-distance, 3456/1728µs header): the shared frame behind Panasonic/Denon/JVC/Sharp/Mitsubishi — decodes the 16-bit vendor ID (+ vendor name), the 12-bit address and 8-bit command, gated by BOTH the 4-bit vendor parity AND the 8-bit frame parity (a frame failing either gate is reported as Kaseikyo-like/parity-failed, never asserted); the per-vendor address/command semantics vary, so the generic frame fields are surfaced as-is. RCA (24-bit pulse-distance, distinct 4000/4000µs leader, 500µs mark + 1000µs/2000µs spaces): 4-bit address + 8-bit command, each followed by its bitwise inverse — reported as RCA only when BOTH inverse-field checksums hold, otherwise the raw fields are surfaced unverified. RC6 is deliberately not decoded yet.\n\n" +
		"Field: **timings** — space/comma-separated integer microsecond values, alternating mark, space, " +
		"mark, space… (a leading 9000 4500 NEC leader). Output is the protocol, address, command (decimal " +
		"+ hex), bit count, checksum validity, and the raw 4 bytes. Offline transform — reads timings and " +
		"transmits nothing, so it is Low risk. Wrap-vs-native: native — leader-match + per-bit classifier, " +
		"no IR hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"timings":{"type":"string","description":"Space/comma-separated microsecond mark/space durations, e.g. \"9000 4500 560 560 560 1690 ...\"."}
		},
		"required":["timings"]
	}`),
	Required:  []string{"timings"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   irRawDecodeHandler,
}

func irRawDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	res, err := ir.DecodeRaw(str(p, "timings"))
	if err != nil {
		return "", fmt.Errorf("ir_raw_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
