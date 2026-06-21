// emv_tsi.go — host-side EMV Transaction Status Information (tag 9B) decoder
// Spec, delegating to internal/emv.DecodeTSI.
//
// Wrap-vs-native: native — the TSI is a fixed 2-byte EMV Book 3 Annex C6
// bitfield recording which functions the terminal performed during a
// transaction (offline data authentication, cardholder verification, card /
// terminal risk management, issuer authentication, script processing). It is
// the third member of the EMV transaction-outcome trio alongside the AIP
// (tag 82, card capabilities) and TVR (tag 95, terminal verdict).
// nfc_emv_decode's BER-TLV walker surfaces tag 9B's value raw; this cracks it.
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
	Register(emvTSIDecodeSpec)
}

var emvTSIDecodeSpec = Spec{
	Name: "nfc_emv_tsi_decode",
	Description: "Decode an EMV Transaction Status Information (tag 9B) — the 2-byte bitfield in which the " +
		"terminal records which functions it actually performed during a transaction. It completes the EMV " +
		"transaction-outcome trio: the AIP (tag 82, nfc_emv_aip_decode) says what the card can do, the TVR " +
		"(tag 95, nfc_emv_tvr_decode) records what the terminal flagged, and the TSI records what the " +
		"terminal carried out — together they reconstruct an EMV transaction for forensics. nfc_emv_decode's " +
		"BER-TLV walker surfaces tag 9B's value raw; this cracks it.\n\n" +
		"Byte 1's six defined bits are decoded per EMV 4.3 Book 3, Annex C6: offline data authentication " +
		"(0x80), cardholder verification (0x40), card risk management (0x20), issuer authentication (0x10), " +
		"terminal risk management (0x08) and script processing (0x04) — each surfaced as a 'function " +
		"performed'. An all-zero TSI is reported as none_performed (a transaction aborted before any function " +
		"completed). Byte 1 bits 2/1 and the whole of byte 2 are RFU and are surfaced via a note rather than " +
		"named — no confidently-wrong output. Gated structurally: exactly 2 bytes.\n\n" +
		"Pass the TSI value hex directly (tag 9B's 2-byte value, e.g. \"E800\"); a full EMV BER-TLV blob is " +
		"also accepted and tag 9B is extracted automatically. Offline transform — reads bytes, transmits " +
		"nothing, so it is Low risk. Wrap-vs-native: native — fixed-layout bit decode + a bounded EMV name " +
		"table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"TSI value hex (tag 9B's 2-byte value, e.g. \"E800\"), or a full EMV BER-TLV blob containing tag 9B. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvTSIDecodeHandler,
}

func emvTSIDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_tsi_decode: 'hex' is required")
	}
	source := "tsi"
	res, err := emv.DecodeTSIHex(raw)
	if err != nil {
		// Fall back to treating the input as a full TLV blob and pulling tag 9B.
		if tlvs, perr := emv.Parse(raw); perr == nil {
			if v, ok := searchTag(tlvs, 0x9B); ok {
				source = "tag9B-extracted"
				res, err = emv.DecodeTSI(v)
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("nfc_emv_tsi_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"source": source,
		"tsi":    res,
	}, "", "  ")
	return string(out), nil
}
