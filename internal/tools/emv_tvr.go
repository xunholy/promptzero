// emv_tvr.go — host-side EMV Terminal Verification Results (tag 95) decoder
// Spec, delegating to internal/emv.DecodeTVR.
//
// Wrap-vs-native: native — the TVR is a fixed 5-byte EMV Book 3 Annex C5
// bitfield in which the terminal records the outcome of every check it ran
// during a transaction (offline data authentication, application usage,
// cardholder verification, terminal risk management, issuer script processing).
// nfc_emv_decode's BER-TLV walker surfaces tag 95's value raw; this cracks it
// into the named flags the terminal set, grouped by EMV's own functional byte
// layout, with RFU bits surfaced raw. Offline read, no hardware.

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
	Register(emvTVRDecodeSpec)
}

var emvTVRDecodeSpec = Spec{
	Name: "nfc_emv_tvr_decode",
	Description: "Decode an EMV Terminal Verification Results (tag 95) — the 5-byte bitfield in which the " +
		"terminal records the outcome of every check it ran during a transaction. Each set bit is an " +
		"exception the terminal flagged, so it is the terminal's pass/fail verdict: which offline-" +
		"authentication, application-usage, cardholder-verification, risk-management and issuer-script " +
		"steps failed or were skipped — exactly what you reconstruct when examining a declined or fraud " +
		"transaction. nfc_emv_decode's BER-TLV walker surfaces tag 95's value raw; this cracks it.\n\n" +
		"All five bytes are decoded per EMV 4.3 Book 3, Annex C5 and grouped by EMV's own functional " +
		"byte layout: byte 1 offline data authentication (SDA/DDA/CDA failed, ICC data missing, exception " +
		"file), byte 2 application usage (expired / not-yet-effective / service-not-allowed), byte 3 " +
		"cardholder verification (CVM failed, PIN Try Limit exceeded, PIN pad missing, online PIN), " +
		"byte 4 terminal risk management (floor limit, offline limits, random/forced online), byte 5 " +
		"issuer-to-card script processing (issuer authentication failed, script failed before/after " +
		"GENERATE AC). A flat 'indications' list gives a one-glance read of everything flagged, and " +
		"'clean' reports an all-zero TVR (no exceptions). RFU bits are surfaced via a note rather than " +
		"named — no confidently-wrong output. Gated structurally: exactly 5 bytes.\n\n" +
		"Pass the TVR value hex directly (tag 95's value, e.g. \"4000808000\"); a full EMV BER-TLV blob " +
		"is also accepted and tag 95 is extracted automatically. Offline transform — reads bytes, " +
		"transmits nothing, so it is Low risk. Wrap-vs-native: native — fixed-layout bit decode + a " +
		"bounded EMV name table.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"TVR value hex (tag 95's 5-byte value, e.g. \"4000808000\"), or a full EMV BER-TLV blob containing tag 95. Accepts ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   emvTVRDecodeHandler,
}

func emvTVRDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nfc_emv_tvr_decode: 'hex' is required")
	}
	source := "tvr"
	res, err := emv.DecodeTVRHex(raw)
	if err != nil {
		// Fall back to treating the input as a full TLV blob and pulling tag 95.
		if tlvs, perr := emv.Parse(raw); perr == nil {
			if v, ok := searchTag(tlvs, 0x95); ok {
				source = "tag95-extracted"
				res, err = emv.DecodeTVR(v)
			}
		}
	}
	if err != nil {
		return "", fmt.Errorf("nfc_emv_tvr_decode: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"source": source,
		"tvr":    res,
	}, "", "  ")
	return string(out), nil
}
