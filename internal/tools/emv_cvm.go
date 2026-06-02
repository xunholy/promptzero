// emv_cvm.go — host-side EMV CVM List (tag 8E) decoder Spec, delegating to
// internal/emv.DecodeCVMList.
//
// Wrap-vs-native: native — the CVM List layout (4-byte Amount X + 4-byte
// Amount Y + 2-byte rules) is a fixed EMV Book 3 structure; nfc_emv_decode's
// BER-TLV walker surfaces tag 8E's value raw, and this cracks it into the
// rules describing how the card wants the cardholder verified. The method /
// condition names come from the same kind of bounded EMV table the tag-name
// lookup already uses, with raw bytes always surfaced. Offline read, no
// hardware.

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
	Register(emvCVMDecodeSpec)
}

var emvCVMDecodeSpec = Spec{
	Name: "nfc_emv_cvm_decode",
	Description: "Decode an EMV CVM List (tag 8E) — the Cardholder Verification Method rules that tell " +
		"the terminal how the card wants the cardholder verified (online PIN, offline PIN, signature, no " +
		"CVM, …) and under what conditions. nfc_emv_decode's BER-TLV walker surfaces tag 8E's value raw; " +
		"this cracks it.\n\n" +
		"The layout is fixed: a 4-byte Amount X, a 4-byte Amount Y (the thresholds the per-rule " +
		"conditions reference), then a sequence of 2-byte rules. Each rule is split into its method code " +
		"(low 6 bits) and the 'apply the next rule if this CVM is unsuccessful' bit (else fail CVM), plus " +
		"the condition byte. Both bytes are ALWAYS surfaced raw; the EMV Book 3 method/condition name is " +
		"added as a best-effort label, and a code outside the standard table is flagged as " +
		"RFU/payment-system-specific rather than guessed (no confidently-wrong output). Gated " +
		"structurally — the 8-byte amount header must be present and the rules must be whole 2-byte " +
		"pairs.\n\n" +
		"Pass the CVM List value hex directly (tag 8E's value_hex from nfc_emv_decode); a full EMV " +
		"BER-TLV blob is also accepted and tag 8E is extracted automatically. Offline transform — reads " +
		"bytes, transmits nothing, so it is Low risk. Wrap-vs-native: native — fixed-layout structural " +
		"parse + a bounded EMV name table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"CVM List value hex (tag 8E's value), or a full EMV BER-TLV blob containing tag 8E. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvCVMDecodeHandler,
}

func emvCVMDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_cvm_decode: 'hex' is required")
	}
	source := "cvm"
	res, err := emv.DecodeCVMListHex(raw)
	if err != nil {
		// Fall back to treating the input as a full TLV blob and pulling tag 8E.
		if tlvs, perr := emv.Parse(raw); perr == nil {
			if v, ok := searchTag(tlvs, 0x8E); ok {
				source = "tag8E-extracted"
				res, err = emv.DecodeCVMList(v)
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("nfc_emv_cvm_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"source": source,
		"cvm":    res,
	}, "", "  ")
	return string(out), nil
}
