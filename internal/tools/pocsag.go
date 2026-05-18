// pocsag.go — host-side POCSAG paging decoder Spec, delegating to
// the internal/pocsag package for the walker proper.
//
// Wrap-vs-native judgement: POCSAG is a public specification
// (ITU-R M.584-2). The decoder is a bit-level walker over
// 32-bit codewords with sync detection and per-encoding (numeric
// 4-bit BCD / alphanumeric 7-bit ASCII) content tables. Wrapping
// a FAP for this would require an SD-card install + a
// firmware-fork dependency for what is, ultimately, a recursive
// descent over a bit-stream. Native delivers offline analysis
// (operators can paste a multimon-ng / rtl_433 bit-stream or a
// codeword dump from a Flipper-side analyzer and decode pages
// without an SDR or Flipper attached), unit-testable round-trips
// against public test vectors, and an output shape that's easy to
// post-process or chain.
//
// Pairs with the loader_pocsag_pager FAP wrapper (which gets a
// live Flipper-side decode running) — this Spec covers the
// offline analyst flow.

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
	Register(pocsagDecodeSpec)
}

var pocsagDecodeSpec = Spec{
	Name: "subghz_pocsag_decode",
	Description: "Decode a POCSAG (ITU-R M.584-2) paging-protocol bit-stream or codeword dump into " +
		"structured pages — 21-bit RIC address, 2-bit function tag (numeric / alphanumeric / tone), " +
		"and the decoded message text. Two input modes:\n\n" +
		" - `bits`: a string of '0' / '1' characters captured from an FSK demodulator " +
		"(multimon-ng -a POCSAG1200, rtl_433, or a Flipper-side FSK sub-GHz capture pre-extracted " +
		"to bits). The decoder scans for the sync word (0x7CD215D8) at every bit offset so the " +
		"stream doesn't need to start at sync.\n" +
		" - `codewords`: a hex-string list of pre-aligned 32-bit codewords (8 hex chars each), " +
		"separated by whitespace / commas / colons. Useful when the operator extracted codewords " +
		"from a Flipper-side analyzer or a recorded scan.\n\n" +
		"Decodes numeric pages via the 4-bit BCD-plus-extended table (space, U, -, ), (), and " +
		"alphanumeric pages as 7-bit ASCII with LSB-first packing across codeword boundaries. " +
		"Reports parity-error count and the bit offsets where syncs were found so operators can " +
		"verify their bit-stream alignment. Pure offline parser — no Flipper / SDR required. " +
		"Accepts ':' '-' '_' / whitespace separators in `bits`.\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 rank 4 (subghz_pocsag_decode). Wrap-vs-native: " +
		"native — POCSAG is a public spec, the walker is ~300 lines of pure bit-twiddling, no " +
		"hardware needed.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"string","description":"Bit-stream of '0' / '1' characters from an FSK demodulator. Sync word (0x7CD215D8) is searched at every bit offset. ':' '-' '_' / whitespace separators tolerated."},
			"codewords":{"type":"string","description":"Hex-string list of pre-aligned 32-bit codewords (8 hex chars each), separated by whitespace / commas / colons. Mutually exclusive with 'bits' — provide one or the other."}
		},
		"oneOf":[
			{"required":["bits"]},
			{"required":["codewords"]}
		]
	}`),
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pocsagDecodeHandler,
}

func pocsagDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	bitsRaw := strings.TrimSpace(str(p, "bits"))
	codewordsRaw := strings.TrimSpace(str(p, "codewords"))
	if bitsRaw == "" && codewordsRaw == "" {
		return "", fmt.Errorf("subghz_pocsag_decode: one of 'bits' or 'codewords' is required")
	}
	if bitsRaw != "" && codewordsRaw != "" {
		return "", fmt.Errorf("subghz_pocsag_decode: provide 'bits' OR 'codewords', not both")
	}
	var (
		res pocsag.Result
		err error
	)
	if bitsRaw != "" {
		res, err = pocsag.Decode(bitsRaw)
	} else {
		res, err = pocsag.DecodeCodewordsHex(codewordsRaw)
	}
	if err != nil {
		return "", fmt.Errorf("subghz_pocsag_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
