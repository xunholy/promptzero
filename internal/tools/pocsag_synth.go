// pocsag_synth.go — host-side POCSAG paging transmission synthesizer Spec,
// the inverse of subghz_pocsag_decode, delegating to internal/pocsag.Synth.
//
// Wrap-vs-native: native — POCSAG framing is fully public (ITU-R M.584-2):
// BCH(31,21) + even parity + fixed batch layout + numeric/alphanumeric
// tables. Unlike the decoder (parity only), the synth computes the real
// BCH, verified against the canonical idle codeword and round-trip against
// subghz_pocsag_decode.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pocsag"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pocsagSynthSpec)
}

var pocsagSynthSpec = Spec{
	Name: "subghz_pocsag_synth",
	Description: "Synthesize a complete POCSAG paging transmission (preamble + sync + one batch) for a " +
		"single page from a RIC address + function + message — the offline inverse of " +
		"subghz_pocsag_decode. Builds the address codeword in the batch frame its low 3 RIC bits " +
		"demand, the numeric/alphanumeric message codewords, and idle-fills the rest, with proper " +
		"BCH(31,21) error-correction + even parity on every codeword (per ITU-R M.584-2). The decoder " +
		"only checks parity; this computes the real BCH so the frame is valid to an actual pager — " +
		"verified against the canonical idle codeword and round-trip-verified against " +
		"subghz_pocsag_decode. The bit-generator behind a paging-spoof payload; generation only — it " +
		"transmits nothing (pair with a Sub-GHz TX stage), so it is Low risk like the decoder.\n\n" +
		"Inputs:\n" +
		" - `address`: 21-bit RIC (decimal or 0x-hex). The low 3 bits set the batch frame position.\n" +
		" - `function`: 0 = numeric, 1/2 = alphanumeric, 3 = tone-only (message must be empty).\n" +
		" - `message`: the body. Numeric allows 0-9, space, U, -, (, ); alphanumeric is 7-bit ASCII.\n\n" +
		"Bounded to one batch: a message that doesn't fit after the address frame errors (multi-batch " +
		"deferred) rather than emit a wrong layout. Numeric has no on-wire length field, so a short " +
		"numeric message is space-padded to its codeword (POCSAG convention). Output is the '0'/'1' " +
		"bit-stream plus the transmission decoded back for confirmation.\n\n" +
		"Companion to subghz_pocsag_decode (gap-analysis §3 rank 4). Wrap-vs-native: native — public " +
		"framing + BCH maths, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"address":{"type":"string","description":"21-bit RIC address: decimal or 0x-hex (e.g. 1234567 or 0x12D687)."},
			"function":{"type":"integer","description":"0=numeric, 1/2=alphanumeric, 3=tone-only."},
			"message":{"type":"string","description":"Page body. Numeric: 0-9 space U - ( ). Alphanumeric: 7-bit ASCII. Empty for tone."}
		},
		"required":["address","function"]
	}`),
	Required:  []string{"address", "function"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pocsagSynthHandler,
}

func pocsagSynthHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	addrStr := strings.TrimSpace(str(p, "address"))
	if addrStr == "" {
		return "", fmt.Errorf("subghz_pocsag_synth: 'address' is required")
	}
	addr, err := parseUint32(addrStr)
	if err != nil {
		return "", fmt.Errorf("subghz_pocsag_synth: address %q: %w", addrStr, err)
	}
	fn, ok := intArg(p["function"])
	if !ok {
		return "", fmt.Errorf("subghz_pocsag_synth: 'function' is required (0-3)")
	}

	stream, err := pocsag.Synth(pocsag.SynthInput{
		Address:  addr,
		Function: fn,
		Message:  str(p, "message"),
	})
	if err != nil {
		return "", fmt.Errorf("subghz_pocsag_synth: %w", err)
	}
	back, _ := pocsag.Decode(stream)
	out, _ := json.MarshalIndent(struct {
		Bits  string        `json:"bits"`
		Frame pocsag.Result `json:"decoded_back"`
	}{Bits: stream, Frame: back}, "", "  ")
	return string(out), nil
}

// parseUint32 parses a decimal or 0x-hex unsigned 32-bit value.
func parseUint32(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	base := 10
	if l := strings.ToLower(s); strings.HasPrefix(l, "0x") {
		s = s[2:]
		base = 16
	}
	if s == "" {
		return 0, fmt.Errorf("empty number")
	}
	var v uint64
	for _, c := range strings.ToLower(s) {
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		default:
			return 0, fmt.Errorf("invalid digit %q", string(c))
		}
		v = v*uint64(base) + uint64(d)
		if v > 0xFFFFFFFF {
			return 0, fmt.Errorf("value exceeds 32 bits")
		}
	}
	return uint32(v), nil
}
