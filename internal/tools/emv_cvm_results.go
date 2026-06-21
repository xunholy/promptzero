// emv_cvm_results.go — host-side EMV CVM Results (tag 9F34) decoder Spec,
// delegating to internal/emv.DecodeCVMResults.
//
// Wrap-vs-native: native — the CVM Results is a fixed 3-byte EMV field (CVM
// Performed + CVM Condition + CVM Result); the performed/condition bytes reuse
// the same EMV Book 3 tables as nfc_emv_cvm_decode (tag 8E), so it is the
// "what actually happened" companion to that decoder's "what the card wants".
// Offline read, no hardware.

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
	Register(emvCVMResultsDecodeSpec)
}

var emvCVMResultsDecodeSpec = Spec{
	Name: "nfc_emv_cvm_results_decode",
	Description: "Decode an EMV CVM Results (tag 9F34) — the 3-byte field recording which Cardholder " +
		"Verification Method the terminal **actually performed** during a transaction and its **outcome**. It " +
		"is the companion to nfc_emv_cvm_decode (tag 8E, the CVM List): the List is what the card asks for, the " +
		"Results are what happened — exactly what you want when reconstructing whether cardholder verification " +
		"succeeded on a captured transaction.\n\n" +
		"Layout (fixed 3 bytes): byte 1 the CVM Performed (low 6 bits = the method code, bit 0x40 = the " +
		"'apply the next rule if this CVM was unsuccessful' flag) — the same encoding as a CVM List rule's " +
		"method byte; byte 2 the CVM Condition (same EMV Book 3 condition table); byte 3 the CVM Result " +
		"(0x00 Unknown, 0x01 Failed, 0x02 Successful, EMV Book 4). The method and condition reuse the same " +
		"bounded EMV tables nfc_emv_cvm_decode uses; a code outside the standard table is flagged " +
		"RFU/payment-system-specific rather than guessed (no confidently-wrong output). Gated structurally to " +
		"exactly 3 bytes.\n\n" +
		"Pass the CVM Results value hex directly (tag 9F34's value, e.g. \"1F0002\"); a full EMV BER-TLV blob " +
		"is also accepted and tag 9F34 is extracted automatically. Offline transform — reads bytes, transmits " +
		"nothing, so it is Low risk. Wrap-vs-native: native — fixed-layout decode reusing the CVM-List tables.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"CVM Results value hex (tag 9F34's 3-byte value, e.g. \"1F0002\"), or a full EMV BER-TLV blob containing tag 9F34. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvCVMResultsDecodeHandler,
}

func emvCVMResultsDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_cvm_results_decode: 'hex' is required")
	}
	source := "cvm_results"
	res, err := emv.DecodeCVMResultsHex(raw)
	if err != nil {
		// Fall back to treating the input as a full TLV blob and pulling tag 9F34.
		if tlvs, perr := emv.Parse(raw); perr == nil {
			if v, ok := searchTag(tlvs, 0x9F34); ok {
				source = "tag9F34-extracted"
				res, err = emv.DecodeCVMResults(v)
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("nfc_emv_cvm_results_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"source":      source,
		"cvm_results": res,
	}, "", "  ")
	return string(out), nil
}
