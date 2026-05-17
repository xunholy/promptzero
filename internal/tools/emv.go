// emv.go — host-side EMV BER-TLV decoder Spec, delegating to the
// internal/emv package for the parser proper.
//
// Wrap-vs-native judgement: the EMV BER-TLV format is a public spec
// (EMV Book 3 §B Annex B). The walker is a recursive descent over
// bytes and a tag-name lookup table. Wrapping a FAP for this would
// require an SD-card install + a firmware-fork dependency for a
// pure parser. Native delivers offline analysis (paste an EMV
// transcript from a forum post and decode it without a Flipper
// attached), unit-testable round-trips, and a tag-name table the
// operator can extend inline without rebuilding the firmware.

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
	Register(emvDecodeSpec)
}

var emvDecodeSpec = Spec{
	Name: "nfc_emv_decode",
	Description: "Parse an EMV BER-TLV blob (typical EMV card APDU response — FCI templates, " +
		"Application Templates, GET PROCESSING OPTIONS / READ RECORD responses) into a structured " +
		"tree with tag names. Walks constructed templates recursively; recognises ~80 of the most " +
		"common EMV tags from EMV Books 1-4 with operator-facing names. Pure offline parser — no " +
		"Flipper required; useful for decoding a saved EMV trace, a forum-post hex dump, or the raw " +
		"response from any contactless payment-card READ. Accepts ':' / '-' / '_' / whitespace " +
		"separators so loosely-formatted input decodes without preprocessing.\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 rank 21 (nfc_emv_parse). Wrap-vs-native: native — " +
		"BER-TLV is a public spec, the walker is ~150 lines, no hardware needed.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded EMV BER-TLV bytes. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvDecodeHandler,
}

func emvDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_decode: 'hex' is required")
	}
	tree, err := emv.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("nfc_emv_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"tlvs":  tree,
		"count": len(tree),
	}, "", "  ")
	return string(out), nil
}
