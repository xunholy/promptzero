// emv_afl.go — host-side EMV Application File Locator decoder Spec,
// delegating to internal/emv.DecodeAFL.
//
// Wrap-vs-native: native — the AFL (tag 94) value is a list of 4-byte
// [SFI, first record, last record, ODA count] entries with no checksum.
// nfc_emv_decode's BER-TLV walker surfaces it as raw bytes; this expands it
// into the SFIs + record ranges and the implied READ RECORD command list,
// gated structurally (4-byte groups, SFI 1-30, ascending ranges). Offline
// transform over operator-supplied bytes; no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/emv"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(emvAFLDecodeSpec)
}

var emvAFLDecodeSpec = Spec{
	Name: "nfc_emv_afl_decode",
	Description: "Decode an EMV Application File Locator (tag 94) — the structure a card returns in its " +
		"GET PROCESSING OPTIONS response that tells the terminal which records to read. nfc_emv_decode's " +
		"BER-TLV walker surfaces tag 94's value as raw bytes; this expands it.\n\n" +
		"The AFL is a sequence of 4-byte entries — [SFI<<3][first record][last record][ODA record " +
		"count]. Each entry is decoded into its short file identifier (SFI), the inclusive record range, " +
		"and how many of those records take part in offline data authentication, and the whole AFL is " +
		"flattened into the implied READ RECORD command list (one SFI+record per command) the terminal " +
		"would issue. There is no checksum, so correctness is gated structurally: the length must be a " +
		"non-zero multiple of 4, every SFI must be 1-30, the record range must ascend, and the ODA count " +
		"cannot exceed the range — a blob that fails any check is rejected, never mis-decoded.\n\n" +
		"Pass the AFL value hex directly (tag 94's value_hex from nfc_emv_decode); a full EMV BER-TLV " +
		"blob is also accepted and tag 94 is extracted automatically. Accepts ':' / '-' / '_' / " +
		"whitespace separators. Offline transform — reads bytes, transmits nothing, so it is Low risk. " +
		"Wrap-vs-native: native — structural 4-byte-entry walk over a byte slice.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"AFL value hex (tag 94's value), or a full EMV BER-TLV blob containing tag 94. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvAFLDecodeHandler,
}

func emvAFLDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_afl_decode: 'hex' is required")
	}
	source := "afl"
	res, err := emv.DecodeAFLHex(raw)
	if err != nil {
		// Fall back to treating the input as a full TLV blob and pulling tag 94.
		if tlvs, perr := emv.Parse(raw); perr == nil {
			if v, ok := searchTag(tlvs, 0x94); ok {
				source = "tag94-extracted"
				res, err = emv.DecodeAFL(v)
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("nfc_emv_afl_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"source": source,
		"afl":    res,
	}, "", "  ")
	return string(out), nil
}
